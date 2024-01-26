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
    // field, and it CANNOT be 47 (0x2F or the '/' character) because every path
    // rule is going to start with that and we can't have any possible collisions.
    struct {
      // The non-path rule type, currently only network rules are supported in
      // keys.
      char rule_type;

      // The socket type number (e.g. SOCK_STREAM, SOCK_DGRAM, etc.)
      char socket_type;

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
#define RULE_KEY_ID_SCRATCH_1 2 // Scratch rule key, can be used by functions for temporary storage
#define NUM_RULE_KEYS 3         // Number of rule key slots

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
    buf->prepend_offset = BUFFER_HALF_POINT;
    buf->append_offset = BUFFER_HALF_POINT;
    buf->data[BUFFER_HALF_POINT] = '\0';
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
  s32 old_offset = buf->prepend_offset;

  // If the buffer is full, we can't write anything to it.
  if (old_offset < 1) {
    return NULL;
  }

  // To please the eBPF verifier, cap old_offset at BUFFER_HALF_POINT as a
  // bounds check.
  if (old_offset > BUFFER_HALF_POINT) {
    old_offset = BUFFER_HALF_POINT;
  }

  s32 new_offset = old_offset;
  u32 d_len;

  struct dentry *dentry = path->dentry;

  struct mount *mnt = real_mount(path->mnt);
  struct dentry *mnt_root = BPF_CORE_READ(&mnt->mnt, mnt_root);

  struct dentry *parent;
  struct mount *m;
  struct qstr d_name;

  for (int i = 0; i < 30; i++) {
    // Grab the current dentry's parent
    parent = BPF_CORE_READ(dentry, d_parent);

    if (dentry == mnt_root) {
      // We're at the top of the mount
      m = BPF_CORE_READ(mnt, mnt_parent);

      // If we're at the top of the mount tree, we're done
      if (mnt == m) {
        break;
      }

      // Otherwise, grab the dentry where this mount was mounted to its parent,
      // grab the parent mount, get the root dentry of that mount, and continue
      dentry = BPF_CORE_READ(mnt, mnt_mountpoint);
      mnt = m;
      mnt_root = BPF_CORE_READ(&mnt->mnt, mnt_root);
      parent = BPF_CORE_READ(dentry, d_parent);

      // This continue is kinda funky being here, but it makes the complexity of
      // this loop go from O(n^>2) to O(n^<1) in testing. I couldn't tell you
      // why... but it makes a huge difference.
      continue;
    }

    // Root directory, we're done
    if (dentry == parent) {
      break;
    }

    // Get the dentry's static name (string with length and hash)
    d_name = BPF_CORE_READ(dentry, d_name);

    // This is really only required for the eBPF verifier, since d_name.len
    // won't ever be >255 for a dentry.
    d_len = d_name.len & BUFFER_HALF_MASK;

    // Rewind in the buffer to where the start of the name can go
    new_offset -= (d_len + 1);

    // If we rewound to the buffer's start, that's a fatal error (since we need
    // to prepend a slash at the start of the path still)
    if (new_offset < 1) {
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
    // * new_offset may be anywhere from 1 to 16383
    // * d_len may be anywhere from 0 to 16383
    //
    // -- therefore --
    //
    // * bpf_probe_read_str could access anywhere from 1 to 32767 within the
    //   buffer (the verifier can't track the relationship between new_offset
    //   and d_len, just their individual bounds)
    // * the returned pointer could be anywhere from 0 to 16383 within the
    //   buffer or NULL, *regardless of how many times this loop was executed*
    //
    // When tested with the loop running only 5 times, this hack reduced the
    // instruction complexity by 75%.
    int sz = bpf_probe_read_str(
      &(buf->data[new_offset]),
      (d_len + 1),
      d_name.name
    );

    if (sz > 1) {
      // If we wrote more than one character, write a slash after the path
      // segment (instead of the null terminator)
      buf->data[new_offset + d_len] = '/';
    } else {
      // Otherwise, if the dentry had no name, pretend it didn't exist
      new_offset += (d_len + 1);
    }

    // Check the parent on the next iteration
    dentry = parent;
  }

  // Return NULL if we didn't write any paths into the buffer
  if (new_offset == old_offset) {
    return NULL;
  }

  // Write a null terminator at the end of the path so we have a null-terminated
  // string again
  buf->data[old_offset - 1] = '\0';

  // Add a slash to the beginning of the path
  new_offset--;
  buf->data[new_offset] = '/';

  // Save the new buffer offset back into the map
  buf->prepend_offset = new_offset;

  // Return a pointer to the start of our new null-terminated path string
  return &buf->data[new_offset];
};

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

// TODO: optimize for instruction complexity?
static u32 match_dir(
  void *inner,
  char *path,
  struct rule_key *in_key,
  int working_key_idx,
  u32 mask
) {
  // Inner key used for checking against inner map
  struct rule_key *key = bpf_map_lookup_elem(&rule_keys, &working_key_idx);
  if (key == NULL) {
    return RULE_NONE;
  }

  u32 *recursive_rule = NULL;
  u32 *dir_rule = NULL;

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
  // TODO: fix the cyclic complexity in this loop
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

    // Copy from input key into working key, and set its path to the
    // directory we're about to check for
    bpf_map_update_elem(&rule_keys, &working_key_idx, in_key, BPF_ANY);
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
        // current directory rule as the most-specific recursive rule so far
        recursive_rule = dir_rule;
      } else {
        // There are no more-specific policies within this directory, so return
        // the current directory rule
        return *dir_rule;
      }
    }
  }

  // If last directory in the path matched a rule, return that since it's the
  // most specific rule possible. This is for both recursive and non-recursive
  // policies.
  if (dir_rule != NULL && (*dir_rule & mask)) {
    return *dir_rule;
  }

  // Otherwise, return the most-recent recursive rule we found along the way, if
  // any
  if (recursive_rule != NULL) {
    return *recursive_rule;
  }

  return RULE_NONE;
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
  struct task_struct *t,
  int buffer_id
) {
  struct file *file_p = get_task_file(t);
  if (file_p == NULL) {
    return NULL;
  }

  // TODO: fix process path detection when exe_file is NULL (dynamic filesystem)
  struct path f_src = BPF_CORE_READ(file_p, f_path);

  return prepend_path(&f_src, buffer_id);
}

// is_owner_path() returns true if the given dentry is owned by the current
// process's Linux user.
static __always_inline bool is_owner_path(struct dentry *dent) {
  kuid_t owner = BPF_CORE_READ(dent, d_inode, i_uid);
  unsigned int z = bpf_get_current_uid_gid();
  if (owner.val != z)
    return false;
  return true;
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
  // If there wasn't a matched rule, look up the default rule
  if (rule == RULE_NONE) {
    u32 zero_idx = RULE_KEY_ID_ZERO;
    struct rule_key *zero_key = bpf_map_lookup_elem(&rule_keys, &zero_idx);
    if (zero_key != NULL) {
      u32 *default_rule = bpf_map_lookup_elem(inner, zero_key);
      if (default_rule != NULL) {
        // If there is a default rule set, get the lowest 2 bits for the rule type
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
  u32 mask,
  bool can_dir_match
) {
  if (path == NULL) {
    can_dir_match = false;
  }

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

    if (can_dir_match) {
      // Set up gp_key with only source, using it as a template for a directory
      // match
      bpf_map_update_elem(&rule_keys, &gp_idx, zero_key, BPF_ANY); // Copy from zero_key to gp_key
      bpf_probe_read_str(gp_key->source, sizeof(gp_key->source), source);

      // Do a check for any parent directory matches, using gp_key as a template,
      // and RULE_KEY_ID_SCRATCH_1 as a working key
      rule = match_dir(inner, path, gp_key, RULE_KEY_ID_SCRATCH_1, mask);
      if (rule & mask) {
        return rule & mask;
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

  if (can_dir_match) {
    // Do a check for any parent directory matches, using gp_key as a template,
    // and RULE_KEY_ID_SCRATCH_1 as a working key
    rule = match_dir(inner, path, gp_key, RULE_KEY_ID_SCRATCH_1, mask);
    if (rule & mask) {
      return rule & mask;
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
static __always_inline int match_and_enforce_path_hooks(
  struct path *f_path,
  u32 event_id,
  bool is_write_event
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
  char *source = get_task_source(task, BUFFER_ID_PATH);

  u32 alert_flags = 0;
  u32 mask = RULE_MASK;

  // If the current PID owns the file, set the owner flag and duplicate the mask
  // to cover FILE_READ_BY_OWNER
  if (is_owner_path(f_path->dentry)) {
    alert_flags |= EVENT_FLAG_OWNER;
    mask |= mask << RULE_OFFSET__BY_OWNER;
  }

  // If the current event is a write event, set the write flag and duplicate the
  // mask to cover FILE_WRITE and possibly FILE_WRITE_BY_OWNER if
  // FILE_READ_BY_OWNER was already covered by the mask.
  if (is_write_event) {
    alert_flags |= EVENT_FLAG_WRITE;
    mask |= mask << RULE_OFFSET_FILE_WRITE;
  }

  // Get the best matching rule for this event
  u32 rule = match_with_info(inner, task, path, source, mask, true);

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

#endif /* __SHARED_H */
