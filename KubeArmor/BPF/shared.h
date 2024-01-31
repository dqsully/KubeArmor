/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright 2023 Authors of KubeArmor */

#ifndef __SHARED_H
#define __SHARED_H

// This code targets Linux 5.8+, because that's the lowest version that supports
// BPF ring buffers, which is how KubeArmor receives events from eBPF code.
//
// This means we have the following extra eBPF features available:
// * BPF-to-BPF calls (not all functions need to be __always_inline)
// * No instruction count limit
// * Support for bounded loops
//
// However, we still have the following limitations:
// * Max program complexity of 1M instructions
// * Max stack size of 512 bytes, or 256 bytes for BPF-to-BPF calls
// * Max stack depth of 8
// * Max 5 arguments for a BPF-to-BPF call
//
// See https://github.com/iovisor/bcc/blob/master/docs/kernel-versions.md for
// more info.

#include "vmlinux.h"
#include "vmlinux_macro.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "syscalls.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

#define EPERM 13

#define MASK_WRITE 0x00000002
#define MASK_READ 0x00000004
#define MASK_APPEND 0x00000008

/* relax_verifier is a dummy helper call to introduce a pruning checkpoint
 * to help relax the verifier to avoid reaching complexity limits.
 */
static inline __attribute__((always_inline)) void relax_verifier(void)
{
	/* Calling get_smp_processor_id() in asm saves an instruction as we
	 * don't have to store the result to ensure the call takes place.
	 * However, we have to specifiy the call target by number and not
	 * name, hence 'call 8'. This is unlikely to change, though, so this
	 * isn't a big issue.
	 */
	asm volatile("call 8;\n" ::
			     : "r0", "r1", "r2", "r3", "r4", "r5");
}

#undef container_of
#define container_of(ptr, type, member)                                        \
  ({                                                                           \
    const typeof(((type *)0)->member) *__mptr = (ptr);                         \
    (type *)((char *)__mptr - offsetof(type, member));                         \
  })

#define RULE_KEY_STR_LEN 256

#define RULE_TYPE_FILE 1
#define RULE_TYPE_PROCESS 2
#define RULE_TYPE_NETWORK 3
#define RULE_TYPE_DEFAULT 0xFF

// Generic rule bitwise offsets
#define RULE_OFFSET__BY_OWNER 4 // _BY_OWNER offsets should always be +4 from the more-generic offset

// Path rule bitwise offsets
#define RULE_OFFSET_FILE_READ 0
#define RULE_OFFSET_FILE_READ_BY_OWNER 4
#define RULE_OFFSET_FILE_WRITE 8
#define RULE_OFFSET_FILE_WRITE_BY_OWNER 12
#define RULE_OFFSET_PROCESS_EXECUTE 16
#define RULE_OFFSET_PROCESS_EXECUTE_BY_OWNER 20

// Network rule bitwise offsets (only one kind of network rule possible right
// now)
#define RULE_OFFSET_NETWORK 0

// Default posture rule offsets
#define RULE_OFFSET_DEFAULT_FILE 0
#define RULE_OFFSET_DEFAULT_PROCESS 4
#define RULE_OFFSET_DEFAULT_NETWORK 8

// Bit flags for a 4-bit rule
#define RULE_FLAG_ALLOW 1     // Allow event
#define RULE_FLAG_LOG 2       // Log event to KubeArmor
#define RULE_FLAG_RECURSIVE 4 // (for path rules ending in '/' only) Apply to all files under the directory
#define RULE_FLAG_HINT 8      // (for path rules only) Indicates that there are more-specific directory rules under this directory

#define RULE_MASK 0xF // A rule is 4 bits
#define RULE_MASK_ANY(flag) (flag | (flag << 4) | (flag << 8) | (flag << 12) | (flag << 16) | (flag << 20) | (flag << 24) | (flag << 28)) // For a 32-bit value containing up to 8 rules, create a number with a given 4-bit mask repeated 8 times
#define RULE_MASK_ANY_RECURSIVE (RULE_MASK_ANY(RULE_FLAG_RECURSIVE)) // 0x44444444, for checking if any of the 8 rules are recursive
#define RULE_MASK_ANY_HINT (RULE_MASK_ANY(RULE_FLAG_HINT)) // 0x88888888, for checking if any of the 8 rules have deeper dir rules

#define RULE_MASK__BY_OWNER (RULE_MASK << RULE_OFFSET_FILE_READ_BY_OWNER) // 0x000000F0, for checking a relative by-owner rule
#define RULE_MASK_FILE_WRITE_ANY ((RULE_MASK << RULE_OFFSET_FILE_WRITE) | (RULE_MASK << RULE_OFFSET_FILE_WRITE_BY_OWNER)) // 0x0000FF00, for checking any file write rule

// Helpful shortcuts for rule flags
#define RULE_NONE 0                                  // No rule defined
#define RULE_ALLOW (RULE_FLAG_ALLOW)                 // Allow event without logging
#define RULE_BLOCK (RULE_FLAG_LOG)                   // Deny event and log
#define RULE_AUDIT (RULE_FLAG_LOG | RULE_FLAG_ALLOW) // Allow event and log (aka Audit)

// struct outer_key is the key type for the root BPF map, identifying a single
// container by its pid and mount namespace IDs.
struct outer_key {
  u32 pid_ns;
  u32 mnt_ns;
};

// kubearmor_containers is an eBPF map of maps. Only 1 level of map nesting is
// allowed, so the top-level keyspace identifies each container, and the
// second-level keyspace identifies enforcement rules by path/protocol and
// source executable.
//
// Surprisingly, the inner map spec can't be defined here in C, only in the code
// which sets up this eBPF program during runtime. (see
// ../enforcer/bpflsm/enforcer.go)
struct {
  __uint(type, BPF_MAP_TYPE_HASH_OF_MAPS);
  __uint(max_entries, 256);
  __uint(key_size, sizeof(struct outer_key));
  __uint(value_size, sizeof(u32));
  __uint(pinning, LIBBPF_PIN_BY_NAME);
} kubearmor_containers SEC(".maps");

// struct network_rule_key is a pseudo-path rule key for network rules. It
// allows us to encode binary network information into the path field of the
// rule_key, so that we could use it like any other path string during rule
// matching.
struct network_rule_key {
  union {
    // Network rules apply by protocol/socket type, there's no path involved. So
    // this union lets us commandeer the first 3 bytes of the path field to
    // instead store the relevant network info. rule_type MUST be the first
    // field, and it CANNOT be 47 (0x2F or the '/' character) or 36 (0x24 or the
    // '$' character) because every path rule is going to start with one of
    // those and we can't have any possible collisions.
    struct {
      // The non-path rule type, currently only network rules are supported in
      // keys.
      char rule_type;

      // The IP protocol number (e.g. IPPROTO_TCP, IPPROTO_UDP, etc.)
      char protocol;

      // Empty struct field to make sure there's a null terminator at the end.
      //
      // Even though in normal C we could assume this byte was already zeroed,
      // eBPF won't let us read this 4th byte until we write to it first, so we
      // still need to zero it out ourselves at some point.
      char null_byte;
    };
    char raw[4];
  };
};

// rule_key is the key type for the inner maps of kubearmor_containers.
//
// 512 bytes
struct rule_key {
  // The path to the target file (being executed, read, written, etc.)
  char path[RULE_KEY_STR_LEN];

  // The path to the executable which took the action
  char source[RULE_KEY_STR_LEN];
};

#define RULE_KEY_ID_ZERO 0      // This rule key is always left zeroed-out
#define RULE_KEY_ID_GP 1        // General-purpose rule key, used for exact matches or as a match template for recursive rules
#define NUM_RULE_KEYS 2         // Number of rule key slots

// rule_keys is a per-CPU array of rule_key structs for use during rule
// enforcement.
//
// eBPF programs have a max stack frame size of 512 bytes, and a single struct
// rule_key would consume all of that, so we have to store them in off-stack
// memory instead.
struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __type(key, u32);
  __type(value, struct rule_key);
  __uint(max_entries, NUM_RULE_KEYS);
} rule_keys SEC(".maps");

#define BUFFER_LEN 32760        // 2^15 - 8 or just under 32KiB, leaving space for 2 32-bit offsets
#define BUFFER_MASK 32767       // 2^15 - 1, used for bounds checking
#define BUFFER_HALF_POINT 16384 // 2^14, used for bounds checking
#define BUFFER_HALF_MASK 16383  // 2^14 - 1, used for bounds checking

#define BUFFER_ID_PATH 0 // Path buffer
#define NUM_BUFFERS 1    // Number of buffers

// buffer is exactly 32KiB, with strings written from the center towards either
// end of the buffer (useful for constructing paths from the filename to the
// root, and for proving eBPF validity with fewer required states).
//
// In eBPF, map values must be powers of 2 in size. There's no reason we need to
// store our offsets in a separate map, so we just shrink the buffer by 8 bytes
// and store 2 32-bit offsets at the end of the buffer instead.
struct buffer {
  char data[BUFFER_LEN];
  u32 prepend_offset;
  u32 append_offset;
};

// buffers is a per-CPU array of general-purpose buffers, especially useful for
// concatenating strings.
struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __type(key, u32);
  __type(value, struct buffer);
  __uint(max_entries, NUM_BUFFERS);
} buffers SEC(".maps");

// Bit flags for reporting events
#define EVENT_FLAG_OWNER 1
#define EVENT_FLAG_WRITE 2

// event contains all audit info for an audited or blocked event
//
// Note: eBPF ring buffer values can be any length, so this struct doesn't need
// to be a power of 2.
struct event {
  // Timestamp in nanoseconds
  u64 ts;

  // PID and mount namespace IDs, for identifying the container
  u32 pid_id;
  u32 mnt_id;

  // Host parent PID and PID
  u32 host_ppid;
  u32 host_pid;

  // In-container parent PID, PID, and user ID
  //
  // If the parent process is not inside the same container, its PID will match
  // whatever PID it has in its namespace. For example, if the parent process is
  // in the host PID namespace, then ppid will match host_ppid.
  u32 ppid;
  u32 pid;
  u32 uid;

  // The eBPF event matched, and its return value
  u32 event_id;
  s64 retval;

  // Linux's recorded commandline
  u8 comm[TASK_COMM_LEN];

  // Rule key and flags used to match the rule for this event
  //
  // KubeArmor understands that opening a file at /foo/bar/baz would match a
  // recursive rule at /foo/, so we don't need to tell it exactly what key
  // matched. However, we do need to tell it all the original data we used to
  // make a match.
  struct rule_key data;
  u32 flags;
};

// Ring buffer for reporting events back to KubeArmor
struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 1 << 24);
  __uint(pinning, LIBBPF_PIN_BY_NAME);
} kubearmor_events SEC(".maps");

// clear_buffer() resets the offset of a buffer to the midpoint, as if nothing
// was ever written to it. This does not clear any data already inside the
// buffer however except for writing a null byte at the midpoint.
static __always_inline void clear_buffer(int buf_idx) {
  struct buffer *buf = bpf_map_lookup_elem(&buffers, &buf_idx);

  if (buf != NULL) {
    buf->data[BUFFER_HALF_POINT - 1] = '\0';
    buf->prepend_offset = BUFFER_HALF_POINT - 1;
    buf->append_offset = BUFFER_HALF_POINT;
  }
}

// get_task_pid_ns_id() returns the Linux PID namespace for a given task.
static __always_inline u32 get_task_pid_ns_id(struct task_struct *task) {
  return BPF_CORE_READ(task, nsproxy, pid_ns_for_children, ns).inum;
}

// get_task_mnt_ns_id() returns the Linux mount namespace for a given task.
static __always_inline u32 get_task_mnt_ns_id(struct task_struct *task) {
  return BPF_CORE_READ(task, nsproxy, mnt_ns, ns).inum;
}

// get_task_pid_vnr() returns the in-namespace PID for a given task.
static __always_inline u32 get_task_pid_vnr(struct task_struct *task) {
  struct pid *pid = BPF_CORE_READ(task, thread_pid);
  unsigned int level = BPF_CORE_READ(pid, level);
  return BPF_CORE_READ(pid, numbers[level].nr);
}

// get_task_ns_ppid() returns the in-namespace parent PID for a given task.
static __always_inline u32 get_task_ns_ppid(struct task_struct *task) {
  struct task_struct *real_parent = BPF_CORE_READ(task, real_parent);
  return get_task_pid_vnr(real_parent);
}

// get_task_ns_tgid() returns the in-namespace PID for a given task's main
// thread.
//
// In Linux, threads are given their own PIDs, and a task may be a thread, but
// the threads are all grouped under the main thread of the process.
// task->group_leader is that main thread of the process, so we can use it to
// get the in-namespace PID for the process.
static __always_inline u32 get_task_ns_tgid(struct task_struct *task) {
  struct task_struct *group_leader = BPF_CORE_READ(task, group_leader);
  return get_task_pid_vnr(group_leader);
}

// get_task_ppid() returns the task's parent PID.
static __always_inline u32 get_task_ppid(struct task_struct *task) {
  return BPF_CORE_READ(task, parent, pid);
}

// get_task_file() returns the task's executable file.
static __always_inline struct file *get_task_file(struct task_struct *task) {
  return BPF_CORE_READ(task, mm, exe_file);
}

// real_mount() returns the `struct mount` that contains the given `struct
// vfsmount`.
static __always_inline struct mount *real_mount(struct vfsmount *mnt) {
  return container_of(mnt, struct mount, mnt);
}

static __always_inline u32 get_vfsmount_ns_id(struct vfsmount *mnt) {
  return BPF_CORE_READ(real_mount(mnt), mnt_ns, ns).inum;
}

static __always_inline struct mount *get_vfsmount_ns_root(struct vfsmount *mnt) {
  return BPF_CORE_READ(real_mount(mnt), mnt_ns, root);
}

static __always_inline u32 get_task_exe_mnt_ns_id(struct task_struct *task) {
  struct file *file_p = get_task_file(task);
  if (file_p == NULL) {
    return 0xFFFFFFFF;
  }

  struct path f_path = BPF_CORE_READ(file_p, f_path);
  return get_vfsmount_ns_id(f_path.mnt);
}

static __always_inline u32 is_task_exe_external(struct task_struct *task) {
  return get_task_exe_mnt_ns_id(task) != get_task_mnt_ns_id(task);
}

static __always_inline u32 is_path_external(struct path *path, struct task_struct *task) {
  return get_vfsmount_ns_id(path->mnt) != get_task_mnt_ns_id(task);
}

// prepend_path() writes out the string representation of a path to the given
// buffer.
static char *prepend_path(struct path *path, int buf_idx) {
  if (path == NULL) {
    return NULL;
  }

  // Load the buffer to write into (per CPU)
  struct buffer *buf = bpf_map_lookup_elem(&buffers, &buf_idx);
  if (buf == NULL) {
    return NULL;
  }

  // This needs to be a variable so that the eBPF verifier can track its state
  u32 offset = buf->prepend_offset & BUFFER_HALF_MASK;

  char path_start = '/';

  u32 d_len;

  struct dentry *dentry = path->dentry;

  struct mount *mnt = real_mount(path->mnt);
  struct dentry *mnt_root = BPF_CORE_READ(&mnt->mnt, mnt_root);

  struct dentry *parent;
  struct mount *m;
  struct qstr d_name;

  for (int i = 0; i < 30; i++) {
    if (dentry == mnt_root) {
      // We're at the top of the mount

      m = BPF_CORE_READ(mnt, mnt_parent);

      // If we're at the top of the entire mount tree, we're done
      if (mnt == m) {
        if (get_vfsmount_ns_root(path->mnt) != mnt) {
          // We didn't make it to the root mount of the path's namespace's
          // filesystem, so we don't really know what the full path is...
          offset = buf->prepend_offset - 1;
          path_start = '?';
        } else if (offset == buf->prepend_offset) {
          // No path segments up to the root of the filesystem, must mean we're
          // looking at '/' itself
          offset = buf->prepend_offset - 1;
        }

        goto save_path;
      }

      // Otherwise, grab the dentry where this mount was mounted to its parent,
      // grab the parent mount, get the root dentry of that mount, and continue
      dentry = BPF_CORE_READ(mnt, mnt_mountpoint);
      mnt = m;
      mnt_root = BPF_CORE_READ(&mnt->mnt, mnt_root);

      // This continue is very important, because it allows us to properly trace
      // filesystems mounted at the roots of other filesystems.
      continue;
    }

    // Grab the current dentry's parent
    parent = BPF_CORE_READ(dentry, d_parent);

    // Orphaned entry, doesn't exist in an accessible filesystem, replace the
    // entire path with a placeholder and break out of the loop
    if (dentry == parent) {
      offset = buf->prepend_offset - 1;
      path_start = '?';
      goto save_path;
    }

    // Get the dentry's static name (string with length and hash)
    d_name = BPF_CORE_READ(dentry, d_name);

    // This is really only required for the eBPF verifier, since d_name.len
    // won't ever be >255 for a dentry.
    d_len = d_name.len & BUFFER_HALF_MASK;

    // If the dentry doesn't have a static name, replace the entire path with a
    // placeholder and break out of the loop
    if (d_len == 0) {
      offset = buf->prepend_offset - 1;
      path_start = '?';
      goto save_path;
    }

    // Rewind in the buffer to where the start of the name can go
    offset -= (d_len + 1);

    // If we rewound to the buffer's start, that's a fatal error (since we need
    // to prepend a slash at the start of the path still)
    if (offset > BUFFER_HALF_POINT) {
      return NULL;
    }

    // Copy the d_name into the buffer at offset
    //
    // There is a HUGE hack here to please the eBPF verifier. Even though d_len
    // will only be between 0 and 255, if we let the verifier know that, it will
    // track every possible maximum offset written to the buffer and returned.
    // Instead, we tell the verifier that d_len is up to 50% of the buffer's
    // size, which in the following function call, means (to the verifier) that:
    //
    // * offset may be anywhere from 0 to 16383
    // * d_len may be anywhere from 0 to 16383
    //
    // -- therefore --
    //
    // * bpf_probe_read_str could access anywhere from 0 to 32767 within the
    //   buffer (the verifier can't track the relationship between offset
    //   and d_len, just their individual bounds)
    // * the returned pointer could be anywhere from 0 to 16383 within the
    //   buffer or NULL, *regardless of how many times this loop was executed*
    //
    // When tested with the loop running only 5 times, this hack reduced the
    // instruction complexity by 75%.
    int sz = bpf_probe_read_str(
      &(buf->data[offset]),
      (d_len + 1),
      d_name.name
    );

    // Error reading, return NULL
    if (sz < 0) {
      return NULL;
    }

    // Write a slash after the path segment (instead of the null terminator)
    buf->data[offset + d_len] = '/';

    // Check the parent on the next iteration
    dentry = parent;
  }

  // If we get here, it means the path was more than 30 segments deep, just
  // return NULL since we don't know the full path
  return NULL;

save_path:
  // offset got saved to the stack before the bounds check in the loop, and then
  // loaded from the stack here, so we have to check its bounds again.
  offset--;

  if (offset >= BUFFER_HALF_POINT) {
    return NULL;
  }

  // Add a slash to the beginning of the path
  buf->data[offset] = path_start;

  // Write a null terminator at the end of the path so we have a null-terminated
  // string again. (We already confirmed at the start of this function that
  // buf->prepend_offset is >= 1, but the verifier forgot that by now.)
  buf->data[(buf->prepend_offset - 1) & BUFFER_HALF_MASK] = '\0';

  // Save the new buffer offset back into the map
  buf->prepend_offset = offset;

  // Return a pointer to the start of our new null-terminated path string
  return &buf->data[offset];
};

static __always_inline char *prepend_ext(int buf_idx) {
  // Load the buffer to write into (per CPU)
  struct buffer *buf = bpf_map_lookup_elem(&buffers, &buf_idx);
  if (buf == NULL) {
    return NULL;
  }

  u32 offset = buf->prepend_offset - 1;

  if (offset > BUFFER_HALF_POINT) {
    return NULL;
  }

  buf->data[offset] = '$';
  buf->prepend_offset = offset;

  return &buf->data[offset];
}

static __always_inline u32 init_event(
  struct event *event,
  struct task_struct *task
) {
  event->ts = bpf_ktime_get_ns();

  event->host_ppid = get_task_ppid(task);
  event->host_pid = bpf_get_current_pid_tgid() >> 32;

  u32 pid = get_task_ns_tgid(task);
  if (event->host_pid == pid) {
    // host
    event->pid_id = 0;
    event->mnt_id = 0;

    event->ppid = get_task_ppid(task);
    event->pid = bpf_get_current_pid_tgid() >> 32;
  } else {
    // container
    event->pid_id = get_task_pid_ns_id(task);
    event->mnt_id = get_task_mnt_ns_id(task);

    event->ppid = get_task_ns_ppid(task);
    event->pid = pid;
  }

  event->uid = bpf_get_current_uid_gid();

  bpf_get_current_comm(&event->comm, sizeof(event->comm));

  return 0;
}

// match_dir() returns the best-matching directory rule (not pre-masked) for the
// given path and mask, or RULE_NONE if no rule matched.
//
// The passed key must have a completely empty path field, since this will write
// into the path field as needed.
static u32 match_dir(
  void *inner,
  char *path,
  struct rule_key *key,
  u32 mask
) {
  u32 *dir_rule = NULL;
  u32 recursive_rule_masked = RULE_NONE;

  // Check for recursive and non-recursive directory matches
  //
  // Every directory rule ends with a '/' character. And then for any deeper
  // directory rule like /foo/bar/baz/ (recursive or not), there will be 'hint'
  // policies created at /foo/bar/, /foo/, and / so that we know there's more to
  // look for.
  //
  // If we pass a recursive directory rule at /foo/, we want to save it until we
  // find a more-specific rule, if any. And if we get all the way to
  // /foo/bar/baz/ (for some file /foo/bar/baz/file.txt) and find a rule there,
  // recursive or not, it will always take priority. The most-recent rule read
  // gets stored into dir_rule, so by the end of the loop if dir_rule isn't
  // NULL, it's the most-specific rule and will take priority. If /foo/bar/ is
  // as far as the policies go, then /foo/bar/baz/ will be NULL and any
  // previously-saved recursive rule will apply instead.
  //
  // >50% of all program complexity is caused by this loop, so any small state
  // or instruction optimizations can go a really long way.
  for (int i = 0; i < RULE_KEY_STR_LEN - 1; i++) {
    // If we've reached the end of the string, break
    if (path[i] == '\0') {
      break;
    }

    // We only care about '/' characters, matching entire directories, so skip
    // until we find one
    if (path[i] != '/') {
      continue;
    }

    // Write out the now-deeper path we're checking.
    //
    // Yes, this 'needlessly' overwrites bytes in key that were already written,
    // but this way is much simpler for eBPF to verify.
    bpf_probe_read_str(key->path, i + 2, path);

    // Check the inner map for a matching rule, and stop looking if we couldn't
    // find one
    dir_rule = bpf_map_lookup_elem(inner, key);
    if (dir_rule == NULL) {
      // If we get here, it means there's no non-recursive directory rule that
      // applies, because there was still more path to parse but the policies
      // didn't go quite as deep.
      break;
    }

    // Check if the rule is a process rule with a recursive directory match
    if (*dir_rule & mask & RULE_MASK_ANY_RECURSIVE) {
      if (*dir_rule & mask & RULE_MASK_ANY_HINT) {
        // There are more-specific policies within this directory, so save the
        // current directory rule as the most-specific recursive rule so far.
        recursive_rule_masked = *dir_rule & mask;
      } else {
        // There are no more-specific policies within this directory, so return
        // the current directory rule
        return *dir_rule & mask;
      }
    }
  }

  // If last directory in the path matched a rule, return that since it's the
  // most specific rule possible. This is for both recursive and non-recursive
  // policies.
  if (dir_rule != NULL && (*dir_rule & mask)) {
    return *dir_rule & mask;
  }

  // Otherwise, return the most-recent recursive rule we found along the way, if
  // any
  return recursive_rule_masked;
}

// get_outer_key() returns the outer_key for the given task.
static __always_inline struct outer_key get_outer_key(struct task_struct *t) {
  struct outer_key key = {
    .pid_ns = get_task_pid_ns_id(t),
    .mnt_ns = get_task_mnt_ns_id(t),
  };

  if (key.pid_ns == PROC_PID_INIT_INO) {
    key.pid_ns = 0;
    key.mnt_ns = 0;
  }

  return key;
}

// get_task_source() returns a pointer to a null-terminated string containing
// the full path of the source binary of the given task, or NULL if no
// executable was found.
static __always_inline char *get_task_source(
  struct task_struct *task,
  int buffer_id
) {
  struct file *file_p = get_task_file(task);
  if (file_p == NULL) {
    return NULL;
  }

  struct path f_src = BPF_CORE_READ(file_p, f_path);

  char *path = prepend_path(&f_src, buffer_id);
  if (path != NULL && is_path_external(&f_src, task)) {
    path = prepend_ext(buffer_id);
  }

  return path;
}

// is_owner_path() returns true if the given dentry is owned by the current
// process's Linux user.
static __always_inline bool is_owner_path(struct dentry *dent) {
  kuid_t owner = BPF_CORE_READ(dent, d_inode, i_uid);
  unsigned int z = bpf_get_current_uid_gid();
  return owner.val == z;
}

// apply_rule() determines the return value for a given event, and submits it to
// the KubeArmor ring buffer if necessary. If the provided rule is RULE_NONE, it
// will also check the default rule for the given rule type.
static __always_inline int apply_rule(
  u32 *inner,
  struct task_struct *task,
  char *path,
  char *source,
  u32 event_id,
  u32 flags,
  u32 rule,
  u32 rule_type
) {
  // We only care about the lowest 2 bits of the rule
  rule = rule & 3;

  // If there wasn't a matched rule, look up the default rule
  if (rule == RULE_NONE) {
    u32 zero_idx = RULE_KEY_ID_ZERO;
    struct rule_key *zero_key = bpf_map_lookup_elem(&rule_keys, &zero_idx);

    u32 gp_idx = RULE_KEY_ID_GP;
    struct rule_key *gp_key = bpf_map_lookup_elem(&rule_keys, &gp_idx);

    if (zero_key != NULL && gp_key != NULL) {
      // Zero out gp_key and set it up for a default rule lookup
      bpf_map_update_elem(&rule_keys, &gp_idx, zero_key, BPF_ANY); // Copy from zero_key to gp_key
      gp_key->path[0] = RULE_TYPE_DEFAULT;

      u32 *default_rule = bpf_map_lookup_elem(inner, gp_key);
      if (default_rule != NULL) {
        // If there is a default rule set, get the lowest 2 bits for the rule
        // type
        rule = (*default_rule >> ((rule_type - 1) * 4)) & 3;
      }
    }
  }

  // If there is no default rule or the rule is an allow rule, return ok and
  // don't log the event to KubeArmor
  if (rule < RULE_BLOCK) {
    return 0;
  }

  // This needs to be a variable, since we can't access alert->retval after
  // submitting it to the ring buffer.
  int retval;

  // Figure out what the return value should be
  if (rule == RULE_BLOCK) {
    retval = -EPERM;
  } else {
    retval = 0;
  }

  // Reserve space on the output ring buffer for whatever event we're logging
  struct event *alert = bpf_ringbuf_reserve(
    &kubearmor_events,
    sizeof(struct event),
    0
  );
  if (alert == NULL) {
    // We couldn't reserve space on the ring buffer, so we can't log this event.
    // That doesn't mean we shouldn't still enforce the rule though.
    return retval;
  }

  // Fill in the event info
  init_event(alert, task);
  alert->event_id = event_id;
  alert->retval = retval;
  alert->flags = flags;

  // Fill in path and/or source if they were provided
  if (path != NULL) {
    bpf_probe_read_str(&alert->data.path, sizeof(alert->data.path), path);
  }
  if (source != NULL) {
    bpf_probe_read_str(&alert->data.source, sizeof(alert->data.source), source);
  }

  // Submit the event to KubeArmor
  bpf_ringbuf_submit(alert, BPF_RB_FORCE_WAKEUP);

  return retval;
}

// match_with_info() returns the best-matching rule (already masked) for the
// given path, source, and rule mask, or RULE_NONE if no rule matched.
static __always_inline u32 match_with_info(
  u32 *inner,
  struct task_struct *task,
  char *path,
  char *source,
  u32 mask
) {
  // Get a pointer to the 'zero' rule key (always zeroed-out)
  u32 zero_idx = RULE_KEY_ID_ZERO;
  struct rule_key *zero_key = bpf_map_lookup_elem(&rule_keys, &zero_idx);
  if (zero_key == NULL) {
    return RULE_NONE;
  }

  // Get a pointer to the general-purpose rule key
  u32 gp_idx = RULE_KEY_ID_GP;
  struct rule_key *gp_key = bpf_map_lookup_elem(&rule_keys, &gp_idx);
  if (gp_key == NULL) {
    return RULE_NONE;
  }

  u32 *rule_ptr = NULL; // Used for direct map accesses
  u32 rule = RULE_NONE; // Used for non-inlined function calls, since they can't return pointers

  if (source != NULL) {
    // Set up gp_key for an exact path+source match
    bpf_map_update_elem(&rule_keys, &gp_idx, zero_key, BPF_ANY); // Copy from zero_key to gp_key
    bpf_probe_read_str(gp_key->path, sizeof(gp_key->path), path);
    bpf_probe_read_str(gp_key->source, sizeof(gp_key->source), source);

    // Check the inner map for an exact match, returning if found
    rule_ptr = bpf_map_lookup_elem(inner, gp_key);
    if (rule_ptr != NULL && (*rule_ptr & mask)) {
      return *rule_ptr & mask;
    }

    if (path != NULL) {
      // Set up gp_key with only source, using it as a template for a directory
      // match
      bpf_map_update_elem(&rule_keys, &gp_idx, zero_key, BPF_ANY); // Copy from zero_key to gp_key
      bpf_probe_read_str(gp_key->source, sizeof(gp_key->source), source);

      // Do a check for any parent directory matches using gp_key (pre-filled
      // with source). The returned rule is already masked.
      rule = match_dir(inner, path, gp_key, mask);
      if (rule) {
        return rule;
      }
    }
  }

  // Set up gp_key for an exact path match (no source)
  bpf_map_update_elem(&rule_keys, &gp_idx, zero_key, BPF_ANY); // Copy from zero_key to gp_key
  bpf_probe_read_str(gp_key->path, sizeof(gp_key->path), path);

  // Check the inner map for an exact match, returning if found
  rule_ptr = bpf_map_lookup_elem(inner, gp_key);
  if (rule_ptr != NULL && (*rule_ptr & mask)) {
    return *rule_ptr & mask;
  }

  if (path != NULL) {
    // Zero out gp_key for a directory match
    bpf_map_update_elem(&rule_keys, &gp_idx, zero_key, BPF_ANY); // Copy from zero_key to gp_key

    // Do a check for any parent directory matches using gp_key (now zeroed
    // out). The returned rule is already masked.
    rule = match_dir(inner, path, gp_key, mask);
    if (rule) {
      return rule;
    }
  }

  return RULE_NONE;
}

// match_net() returns the best-matching rule (already masked) for the given
// network rule key
static __always_inline u32 match_net(
  u32 *inner,
  struct task_struct *task,
  char *path,
  char *source,
  u32 mask
) {
  // Get a pointer to the 'zero' rule key (always zeroed-out)
  u32 zero_idx = RULE_KEY_ID_ZERO;
  struct rule_key *zero_key = bpf_map_lookup_elem(&rule_keys, &zero_idx);
  if (zero_key == NULL) {
    return RULE_NONE;
  }

  // Get a pointer to the general-purpose rule key
  u32 gp_idx = RULE_KEY_ID_GP;
  struct rule_key *gp_key = bpf_map_lookup_elem(&rule_keys, &gp_idx);
  if (gp_key == NULL) {
    return RULE_NONE;
  }

  u32 *rule_ptr = NULL; // Used for direct map accesses
  u32 rule = RULE_NONE; // Used for non-inlined function calls, since they can't return pointers

  if (source != NULL) {
    // Set up gp_key for an exact path+source match
    bpf_map_update_elem(&rule_keys, &gp_idx, zero_key, BPF_ANY); // Copy from zero_key to gp_key
    bpf_probe_read_str(gp_key->path, sizeof(gp_key->path), path);
    bpf_probe_read_str(gp_key->source, sizeof(gp_key->source), source);

    // Check the inner map for an exact match, returning if found
    rule_ptr = bpf_map_lookup_elem(inner, gp_key);
    if (rule_ptr != NULL && (*rule_ptr & mask)) {
      return *rule_ptr & mask;
    }

    if (gp_key->path[1] != 0) {
      // Set up gp_key for an 'any' protocol match, since an 'any' rule on a
      // source is more specific than a protocol on all processes
      gp_key->path[1] = 0;

      // Check the inner map for an exact match, returning if found
      rule_ptr = bpf_map_lookup_elem(inner, gp_key);
      if (rule_ptr != NULL && (*rule_ptr & mask)) {
        return *rule_ptr & mask;
      }
    }
  }

  // Set up gp_key for an exact path match (no source)
  bpf_map_update_elem(&rule_keys, &gp_idx, zero_key, BPF_ANY); // Copy from zero_key to gp_key
  bpf_probe_read_str(gp_key->path, sizeof(gp_key->path), path);

  // Check the inner map for an exact match, returning if found
  rule_ptr = bpf_map_lookup_elem(inner, gp_key);
  if (rule_ptr != NULL && (*rule_ptr & mask)) {
    return *rule_ptr & mask;
  }

  if (gp_key->path[1] != 0) {
    // Set up gp_key for an 'any' protocol match, because it's possible that
    // someone wants a 'most-general' network rule for a container that isn't the
    // default posture. File/process rules have an equivalent already anyways: a
    // recursive directory rule at /.
    gp_key->path[1] = 0;

    // Check the inner map for an exact match, returning if found
    rule_ptr = bpf_map_lookup_elem(inner, gp_key);
    if (rule_ptr != NULL && (*rule_ptr & mask)) {
      return *rule_ptr & mask;
    }
  }

  return RULE_NONE;
}

// match_and_enforce_path_hooks() matches the given path, event ID, and event
// write status with the enforcement rules for the current container, and
// enforces the best-matching rule, returning the appropriate LSM hook return
// value.
//
// Because eBPF is weird, there's a couple things callers of this function need
// to do in order for it to work properly:
//
// DO NOT pass a struct f_path * received from an LSM hook directly to this
// function. Instead, construct a new struct path on the stack and read at
// least the `mnt` property using BPF_CORE_READ (or bpf_probe_read), and then
// pass the pointer to that struct. This erases certain information about the
// pointer types, and keeps pointer types consistent further within the eBPF
// program.
static __always_inline int match_and_enforce_path_hooks_write(
  struct path *f_path,
  u32 event_id
) {
  // Get the current task
  struct task_struct *task = (struct task_struct *)bpf_get_current_task();

  // Get the inner map for the current container.
  //
  // Leave this at the start of this function so we can return early if this
  // container isn't being enforced.
  struct outer_key okey = get_outer_key(task);
  u32 *inner = bpf_map_lookup_elem(&kubearmor_containers, &okey);
  if (inner == NULL) {
    return 0;
  }

  // Clear the path buffer
  clear_buffer(BUFFER_ID_PATH);

  // Get the path that's being accessed, and the executable accessing it
  char *path = prepend_path(f_path, BUFFER_ID_PATH);
  if (path != NULL && is_path_external(f_path, task)) {
    // For now, don't enforce file access on any paths outside of the
    // container's namespace. Theoretically this means we can't protect any file
    // accesses from escaping the container's namespace if that's possible, but
    // so far I've noticed a lot of expected cross-namespace file accesses that
    // we want to allow, but it's hard to figure out how to:
    //
    // * "sockfs" - can't determine a filename, shows up as external mount ns
    // * "pipefs" - similar to sockfs
    // * container image files - anytime the container accesses a file included
    //   in the container's image that hasn't yet been modified, it shows up
    //   first as a file access in the container's mount namespace (on the
    //   overlay filesystem), and then as a second file access in another mount
    //   namespace (on the host's filesystem)
    return 0;
  }

  char *source = get_task_source(task, BUFFER_ID_PATH);

  u32 alert_flags = EVENT_FLAG_WRITE;
  u32 mask = RULE_MASK | (RULE_MASK << RULE_OFFSET_FILE_WRITE);

  // If the current PID owns the file, set the owner flag and duplicate the mask
  // to cover FILE_READ_BY_OWNER
  if (is_owner_path(f_path->dentry)) {
    alert_flags |= EVENT_FLAG_OWNER;
    mask |= mask << RULE_OFFSET__BY_OWNER;
  }

  // For some reason, trying to trick eBPF into thinking alert_flags can be any
  // u32 here doesn't provide any benefit.

  // Trick the eBPF verifier into thinking mask can be any u32, reducing
  // instruction complexity by about 2x.
  bpf_probe_read(&mask, sizeof(mask), &mask);

  // Get the best matching rule for this event
  u32 rule = match_with_info(inner, task, path, source, mask);

  // If there's matched write rules, we care about those more than read rules,
  // so shift them into place
  if (rule & RULE_MASK_FILE_WRITE_ANY) {
    rule >>= RULE_OFFSET_FILE_WRITE;
  }

  // If there's a matched ownerOnly rule, we care about it more, so shift it
  // into place
  if (rule & RULE_MASK__BY_OWNER) {
    rule >>= RULE_OFFSET__BY_OWNER;
  }

  // Apply the rule
  return apply_rule(
    inner,
    task,
    path,
    source,
    event_id,
    alert_flags,
    rule,
    RULE_TYPE_FILE
  );
}

// match_and_enforce_path_hooks_read() is a near-duplicate of the write variant,
// but by explicitly separating them, for some reason clang can do much better
// optimizations for the enforce_file and enforce_file_perm hooks.
//
// See match_and_enforce_path_hooks_write() for more details.
static __always_inline int match_and_enforce_path_hooks_read(
  struct path *f_path,
  u32 event_id
) {
  // Get the current task
  struct task_struct *task = (struct task_struct *)bpf_get_current_task();

  // Get the inner map for the current container.
  //
  // Leave this at the start of this function so we can return early if this
  // container isn't being enforced.
  struct outer_key okey = get_outer_key(task);
  u32 *inner = bpf_map_lookup_elem(&kubearmor_containers, &okey);
  if (inner == NULL) {
    return 0;
  }

  // Clear the path buffer
  clear_buffer(BUFFER_ID_PATH);

  // Get the path that's being accessed, and the executable accessing it
  char *path = prepend_path(f_path, BUFFER_ID_PATH);
  if (path != NULL && is_path_external(f_path, task)) {
    // For now, don't enforce file access on any paths outside of the container's namespace.
    // Theoretically this means we can't protect any file accesses from escaping
    // the container's namespace if that's possible, but so far I've noticed a
    // lot of expected cross-namespace file accesses that we want to allow, but
    // it's hard to figure out how to:
    //
    // * "sockfs" - can't determine a filename, shows up as external mount ns
    // * "pipefs" - similar to sockfs
    // * container image files - anytime the container accesses a file included
    //   in the container's image that hasn't yet been modified, it shows up
    //   first as a file access in the container's mount namespace (on the
    //   overlay filesystem), and then as a second file access in another mount
    //   namespace (on the host's filesystem)
    return 0;
  }

  char *source = get_task_source(task, BUFFER_ID_PATH);

  u32 alert_flags = 0;
  u32 mask = RULE_MASK;

  // If the current PID owns the file, set the owner flag and duplicate the mask
  // to cover FILE_READ_BY_OWNER
  if (is_owner_path(f_path->dentry)) {
    alert_flags |= EVENT_FLAG_OWNER;
    mask |= mask << RULE_OFFSET__BY_OWNER;
  }

  // Trick the eBPF verifier into thinking flags can be any u32
  bpf_probe_read(&alert_flags, sizeof(alert_flags), &alert_flags);

  // Trick the eBPF verifier into thinking mask can be any u32, reducing
  // instruction complexity by about 2x.
  bpf_probe_read(&mask, sizeof(mask), &mask);

  // Get the best matching rule for this event
  u32 rule = match_with_info(inner, task, path, source, mask);

  // If there's a matched ownerOnly rule, we care about it more, so shift it
  // into place
  if (rule & RULE_MASK__BY_OWNER) {
    rule >>= RULE_OFFSET__BY_OWNER;
  }

  // Apply the rule
  return apply_rule(
    inner,
    task,
    path,
    source,
    event_id,
    alert_flags,
    rule,
    RULE_TYPE_FILE
  );
}

#endif /* __SHARED_H */
