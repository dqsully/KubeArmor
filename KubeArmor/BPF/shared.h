/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright 2023 Authors of KubeArmor */

#ifndef __SHARED_H
#define __SHARED_H

#include "vmlinux.h"
#include "vmlinux_macro.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";
#define EPERM 13

#define MAX_BUFFER_SIZE 32768 // 2 ** 15

#define MAX_STRING_SIZE 256 // 2 ** 8

#define PATH_BUFFER 0
#define MAX_BUFFERS 1

#define TASK_COMM_LEN 80

#define AUDIT_POSTURE 140
#define BLOCK_POSTURE 141

enum file_hook_type { dpath = 0, dfileread, dfilewrite };

enum deny_by_default {
  dproc = 101,
  dfile,
  dnet
}; // check if the list is whitelist/blacklist

#define NET_MATCH 2

typedef struct buffers {
  char buf[MAX_BUFFER_SIZE];
} bufs_t;

typedef struct bufkey {
  char path[MAX_STRING_SIZE];
  char source[MAX_STRING_SIZE];
} bufs_k;

struct sockinfo {
  char type;
  char proto;
};

#undef container_of
#define container_of(ptr, type, member)                                        \
  ({                                                                           \
    const typeof(((type *)0)->member) *__mptr = (ptr);                         \
    (type *)((char *)__mptr - offsetof(type, member));                         \
  })
struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __type(key, u32);
  __type(value, bufs_t);
  __uint(max_entries, MAX_BUFFERS);
} bufs SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __type(key, u32);
  __type(value, u32);
  __uint(max_entries, MAX_BUFFERS);
} bufs_off SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __type(key, u32);
  __type(value, bufs_k);
  __uint(max_entries, 4);
} bufk SEC(".maps");

struct outer_key {
  u32 pid_ns;
  u32 mnt_ns;
};

struct event {
  u64 ts;

  u32 pid_id;
  u32 mnt_id;

  u32 host_ppid;
  u32 host_pid;

  u32 ppid;
  u32 pid;
  u32 uid;

  u32 event_id;
  s64 retval;

  u8 comm[TASK_COMM_LEN];

  bufs_k data;
};

struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 1 << 24);
  __uint(pinning, LIBBPF_PIN_BY_NAME);
} kubearmor_events SEC(".maps");

#define RULE_EXEC 1 << 0
#define RULE_WRITE 1 << 1
#define RULE_READ 1 << 2
#define RULE_OWNER 1 << 3
#define RULE_DIR 1 << 4
#define RULE_RECURSIVE 1 << 5
#define RULE_HINT 1 << 6
#define RULE_DENY 1 << 7

#define MASK_WRITE 0x00000002
#define MASK_READ 0x00000004
#define MASK_APPEND 0x00000008

struct data_t {
  union {
    struct {
      u8 processmask;
      u8 filemask;
    };
    u8 mask[2];
  };
};

struct outer_hash {
  __uint(type, BPF_MAP_TYPE_HASH_OF_MAPS);
  __uint(max_entries, 256);
  __uint(key_size, sizeof(struct outer_key));
  __uint(value_size, sizeof(u32));
  __uint(pinning, LIBBPF_PIN_BY_NAME);
};

struct outer_hash kubearmor_containers SEC(".maps");

static __always_inline bufs_t *get_buf(int idx) {
  return bpf_map_lookup_elem(&bufs, &idx);
}

// real_mount() returns the `struct mount` that contains the given `struct
// vfsmount`.
static __always_inline struct mount *real_mount(struct vfsmount *mnt) {
  return container_of(mnt, struct mount, mnt);
}

// init_buffer() resets the offset of the buffer to the end, as if nothing was
// ever written to it. This does not clear any data already inside the buffer
// however.
static __always_inline void init_buffer(int buf_idx) {
  int new_offset = MAX_BUFFER_SIZE;
  bpf_map_update_elem(&bufs_off, &buf_idx, &new_offset, BPF_ANY);
}

// prepend_path() writes out the string representation of a path to the given
// buffer, starting from the end and working backwards.
//
// TODO: add max_len parameter?
static __always_inline char *prepend_path(struct path *path, int buf_idx) {
  if (path == NULL) {
    return NULL;
  }

  char slash = '/';
  char null = '\0';

  // Load the buffer to write into (per CPU)
  int *buf_offset = bpf_map_lookup_elem(&bufs_off, &buf_idx);
  bufs_t *string_p = get_buf(buf_idx);

  if (buf_offset == NULL || string_p == NULL) {
    return NULL;
  }

  int offset = *buf_offset;

  struct dentry *dentry = path->dentry;
  struct vfsmount *vfsmnt = path->mnt;

  struct mount *mnt = real_mount(vfsmnt);
  struct dentry *mnt_root = BPF_CORE_READ(vfsmnt, mnt_root);

  struct dentry *parent;
  struct mount *m;
  struct qstr d_name;

  // This loop doesn't need to be unrolled since Linux 5.3, and it reduces the
  // program size dramatically by not unrolling it (until Linux 5.8, programs
  // were limited to 4096 instructions)
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
      mnt = BPF_CORE_READ(mnt, mnt_parent);
      vfsmnt = &mnt->mnt;
      mnt_root = BPF_CORE_READ(vfsmnt, mnt_root);
      continue;
    }

    // Root directory, we're done
    if (dentry == parent) {
      break;
    }

    // Get the dentry's static name (string with length and hash)
    d_name = BPF_CORE_READ(dentry, d_name);

    // Rewind in the buffer to where the start of the name can go
    offset -= (d_name.len + 1);

    // If we rewound to before the buffer's start, that's a fatal error
    if (offset < 0)
      return NULL;

    // Copy the d_name into the buffer at offset
    int sz = bpf_probe_read_str(
      &(string_p->buf[(offset)]),
      (d_name.len + 1),
      d_name.name
    );

    if (sz > 1) {
      // If we wrote more than one character, write a slash after the path
      // segment (instead of the null terminator)
      bpf_probe_read(
        &(string_p->buf[(offset + d_name.len)]),
        1,
        &slash
      );
    } else {
      // Otherwise, if the dentry had no name, pretend it didn't exist
      offset += (d_name.len + 1);
    }

    // Check the parent on the next iteration
    dentry = parent;
  }

  // Return NULL if we didn't write any paths into the buffer
  if (offset == *buf_offset) {
    return NULL;
  }

  // Write a null terminator at the end of the path so we have a null-terminated
  // string again
  bpf_probe_read(&(string_p->buf[*buf_offset - 1]), 1, &null);

  // Add a slash to the beginning of the path
  offset--;
  bpf_probe_read(&(string_p->buf[offset]), 1, &slash);

  // Save the new buffer offset back into the map
  *buf_offset = offset;

  // Return a pointer to the start of our new null-terminated path string
  return &string_p->buf[offset];
}

static __always_inline u32 get_task_pid_ns_id(struct task_struct *task) {
  return BPF_CORE_READ(task, nsproxy, pid_ns_for_children, ns).inum;
}

static __always_inline u32 get_task_mnt_ns_id(struct task_struct *task) {
  return BPF_CORE_READ(task, nsproxy, mnt_ns, ns).inum;
}

static __always_inline u32 get_task_pid_vnr(struct task_struct *task) {
  struct pid *pid = BPF_CORE_READ(task, thread_pid);
  unsigned int level = BPF_CORE_READ(pid, level);
  return BPF_CORE_READ(pid, numbers[level].nr);
}

static __always_inline u32 get_task_ns_ppid(struct task_struct *task) {
  struct task_struct *real_parent = BPF_CORE_READ(task, real_parent);
  return get_task_pid_vnr(real_parent);
}

static __always_inline u32 get_task_ns_tgid(struct task_struct *task) {
  struct task_struct *group_leader = BPF_CORE_READ(task, group_leader);
  return get_task_pid_vnr(group_leader);
}

static __always_inline u32 get_task_ppid(struct task_struct *task) {
  return BPF_CORE_READ(task, parent, pid);
}

static __always_inline struct file *get_task_file(struct task_struct *task) {
  return BPF_CORE_READ(task, mm, exe_file);
}

static __always_inline void get_outer_key(
  struct outer_key *key,
  struct task_struct *t
) {
  key->pid_ns = get_task_pid_ns_id(t);
  key->mnt_ns = get_task_mnt_ns_id(t);

  if (key->pid_ns == PROC_PID_INIT_INO) {
    key->pid_ns = 0;
    key->mnt_ns = 0;
  }
}

// get_task_source() returns a pointer to a null-terminated string containing
// the full path of the source binary of the given task, or NULL if no
// executable was found.
//
// This string is constructed and stored in the PATH_BUFFER buffer, which will
// not be overwritten until a call to init_buffer(PATH_BUFFER) is made.
static __always_inline char *get_task_source(struct task_struct *t) {
  struct file *file_p = get_task_file(t);
  if (file_p == NULL)
    return NULL;

  struct path f_src = BPF_CORE_READ(file_p, f_path);

  return prepend_path(&f_src, PATH_BUFFER);
}

static __always_inline struct data_t *match_dir(
  void *inner,
  char path[256],
  int in_buf_idx,
  int working_buf_idx,
  u8 mask,
  bool match_type
) {
    // Inner key used for checking against inner map
    bufs_k *key = bpf_map_lookup_elem(&bufk, &working_buf_idx);
    if (key == NULL) {
      return NULL;
    }

    struct data_t *recursive_policy = NULL;
    struct data_t *dir_policy = NULL;

    u8 dir_mask;

    // Check for recursive and non-recursive directory matches
    //
    // Every directory policy ends with a '/' character. And then for any deeper
    // directory policy like /foo/bar/baz/ (recursive or not), there will be
    // 'hint' policies created at /foo/bar/, /foo/, and / so that we know
    // there's more to look for.
    //
    // If we pass a recursive directory policy at /foo/, we want to save it
    // until we find a more-specific policy, if any. And if we get all the way
    // to /foo/bar/baz/ (for some file /foo/bar/baz/file.txt) and find a policy
    // there, recursive or not, it will always take priority. The most-recent
    // policy read gets stored into dir_policy, so by the end of the loop if
    // dir_policy isn't NULL, it's the most-specific policy and will take
    // priority. If /foo/bar/ is as far as the policies go, then /foo/bar/baz/
    // will be NULL and any previously-saved recursive policy will apply
    // instead.
    for (int i = 0; i < MAX_STRING_SIZE - 1; i++) {
      // If we've reached the end of the string, break
      if (path[i] == '\0') {
        break;
      }

      // We only care about '/' characters, matching entire directories, so skip
      // until we find one
      if (path[i] != '/') {
        continue;
      }

      // Copy from input buffer into working buffer, and set its path to the
      // directory we're about to check for
      bpf_map_update_elem(&bufk, &working_buf_idx, &in_buf_idx, BPF_ANY);
      bpf_probe_read_str(key->path, i + 2, path);

      // Check the inner map for a matching policy, and stop looking if we
      // couldn't find one
      dir_policy = bpf_map_lookup_elem(inner, key);
      if (dir_policy == NULL) {
        // If we get here, it means there's no non-recursive directory policy
        // that applies, because there was still more path to parse but the
        // policies didn't go quite as deep.
        break;
      }

      // Check if the policy is a process policy with a recursive directory
      // match
      dir_mask = mask | RULE_DIR | RULE_RECURSIVE;
      if ((dir_policy->mask[match_type] & dir_mask) == dir_mask) {
        if (dir_policy->mask[match_type] & RULE_HINT) {
          // There are more-specific policies within this directory, so save the
          // current directory policy as the most-specific recursive policy so
          // far
          recursive_policy = dir_policy;
        } else {
          // There are no more-specific policies within this directory, so
          // return the current directory policy
          return dir_policy;
        }
      }
    }

    // If last directory in the path matched a non-recursive policy, return that
    // since it's the most specific policy possible. This is for both recursive
    // and non-recursive policies.
    dir_mask = mask | RULE_DIR;
    if (dir_policy != NULL &&
        (dir_policy->mask[match_type] & dir_mask) == dir_mask) {
      return dir_policy;
    }

    // Otherwise, return the most-recent recursive policy we found along the
    // way, if any
    return recursive_policy;
}

// == Context Management == //

static __always_inline u32 init_context(
  struct event *event_data,
  struct task_struct *task
) {
  event_data->ts = bpf_ktime_get_ns();

  event_data->host_ppid = get_task_ppid(task);
  event_data->host_pid = bpf_get_current_pid_tgid() >> 32;

  u32 pid = get_task_ns_tgid(task);
  if (event_data->host_pid == pid) { // host
    event_data->pid_id = 0;
    event_data->mnt_id = 0;

    event_data->ppid = get_task_ppid(task);
    event_data->pid = bpf_get_current_pid_tgid() >> 32;
  } else { // container
    event_data->pid_id = get_task_pid_ns_id(task);
    event_data->mnt_id = get_task_mnt_ns_id(task);

    event_data->ppid = get_task_ns_ppid(task);
    event_data->pid = pid;
  }

  event_data->uid = bpf_get_current_uid_gid();

  bpf_get_current_comm(&event_data->comm, sizeof(event_data->comm));

  return 0;
}

static __always_inline bool is_owner(struct file *file_p) {
  kuid_t owner = BPF_CORE_READ(file_p, f_inode, i_uid);
  unsigned int z = bpf_get_current_uid_gid();
  if (owner.val != z)
    return false;
  return true;
}

static __always_inline bool is_owner_path(struct dentry *dent) {
  kuid_t owner = BPF_CORE_READ(dent, d_inode, i_uid);
  unsigned int z = bpf_get_current_uid_gid();
  if (owner.val != z)
    return false;
  return true;
}

static __always_inline int match_and_enforce_path_hooks(
  struct path *f_path,
  u32 id,
  u32 eventID
) {
  // Alert info sent to KubeArmor
  struct event *alert;

  // Get the current task
  struct task_struct *task = (struct task_struct *)bpf_get_current_task();

  // Get the 'outer' map key (PID and mount namespace IDs) that identifies the
  // current container
  struct outer_key okey;
  get_outer_key(&okey, task);

  // Get the 'inner' map that contains the policies for the current container
  void *inner = bpf_map_lookup_elem(&kubearmor_containers, &okey);
  if (!inner) {
    return 0;
  }

  // Attempt to get 'inner' key buffer #0 as 'z' (always filled with 0's)
  u32 z_idx = 0;
  bufs_k *z = bpf_map_lookup_elem(&bufk, &z_idx);
  if (z == NULL) {
    return 0;
  }

  // Attempt to get 'inner' key buffer #1 as 'tk' (zeroed out as needed)
  u32 tk_idx = 1;
  bufs_k *tk = bpf_map_lookup_elem(&bufk, &tk_idx);
  if (tk == NULL) {
    return 0;
  }

  // Attempt to get 'inner' key buffer #2 as 'pk' (zeroed out as needed)
  u32 pk_idx = 2;
  bufs_k *pk = bpf_map_lookup_elem(&bufk, &pk_idx);
  if (pk == NULL) {
    return 0;
  }

  // Get the path that's being accessed
  char *path_ptr = prepend_path(f_path, PATH_BUFFER);

  struct data_t *matched_policy = NULL;

  // Get the current process's executable, if possible
  void *source_str = get_task_source(task);

  if (source_str != NULL) {
    // Set up pk to check for an exact path+source match
    bpf_map_update_elem(&bufk, &pk_idx, z, BPF_ANY);
    bpf_probe_read_str(pk->path, MAX_STRING_SIZE, path_ptr);
    bpf_probe_read_str(pk->source, MAX_STRING_SIZE, source_str);

    // Check the inner map for an exact match
    matched_policy = bpf_map_lookup_elem(inner, pk);
    if (matched_policy != NULL && (matched_policy->filemask & RULE_EXEC)) {
      goto decision;
    }

    // Zero out and store the parent process's executable in tk->source to
    // prepare for a directory match
    bpf_map_update_elem(&bufk, &tk_idx, z, BPF_ANY);
    bpf_probe_read_str(tk->source, MAX_STRING_SIZE, source_str);

    // Do a check for any parent directory matches, using tk as a template, and
    // buffer #3 (otherwise unused) as a working buffer
    matched_policy = match_dir(inner, pk->path, tk_idx, 3, RULE_EXEC, true);
    if (matched_policy != NULL) {
      goto decision;
    }
  }

  // Zero out pk, set pk->path, and check for an exact match (no source set)
  bpf_map_update_elem(&bufk, &pk_idx, z, BPF_ANY);
  bpf_probe_read_str(pk->path, MAX_STRING_SIZE, path_ptr);

  matched_policy = bpf_map_lookup_elem(inner, pk);
  if (matched_policy && (matched_policy->filemask & RULE_READ)) {
    goto decision;
  }

  matched_policy = NULL;

  // Do a check for any parent directory matches, using z as a template (no
  // source set), and buffer #3 (otherwise unused) as a working buffer
  matched_policy = match_dir(inner, pk->path, z_idx, 3, RULE_EXEC, false);

decision:

  // Reserve space in the output ring buffer for this event
  alert = bpf_ringbuf_reserve(&kubearmor_events, sizeof(struct event), 0);
  if (alert == NULL) {
    return 0;
  }

  // Fill out common alert fields
  init_context(alert, task);

  // Read path and source strings into the alert
  bpf_probe_read_str(&alert->data.path, MAX_STRING_SIZE, path_ptr);
  bpf_probe_read_str(&alert->data.source, MAX_STRING_SIZE, source_str);

  // Add other alert fields
  alert->event_id = eventID;
  alert->retval = -EPERM;

  // If we found a matching policy and it's a deny policy, return permission
  // denied and send alert to KubeArmor
  if (matched_policy != NULL) {
    // We found a matching policy

    // TODO: fix this whole mess
    if (id == dfileread && (~matched_policy->filemask & RULE_WRITE)) {
      // The event is lsm/file_open and the matching policy allows read-only. We
      // can't tell if the file is being opened for read-only or read-write, so
      // we have to allow it and let lsm/file_permission decide if it's allowed.
      bpf_ringbuf_discard(alert, BPF_RB_NO_WAKEUP);
      return 0;
    }

    if (matched_policy->filemask & RULE_DENY) {
      // The matching policy is a deny policy, return permission denied and
      // send alert to KubeArmor
      bpf_ringbuf_submit(alert, BPF_RB_FORCE_WAKEUP);
      return -EPERM;
    }

    if ((matched_policy->filemask & RULE_OWNER) && !is_owner_path(f_path->dentry)) {
      // The matching policy is an allow policy with ownerOnly: true set, so
      // enforce that only the owner of the executable file is accessing it
      bpf_ringbuf_submit(alert, BPF_RB_FORCE_WAKEUP);
      return -EPERM;
    }
  }

  // Clear out pk and set pk->path to the special value to check the default
  // file posture
  bpf_map_update_elem(&bufk, &pk_idx, z, BPF_ANY);
  pk->path[0] = dfile;

  struct data_t *default_posture = bpf_map_lookup_elem(inner, pk);

  if (default_posture != NULL) {
    if (default_posture->filemask == BLOCK_POSTURE) {
      // Default posture is Block, return permission denied and send alert to
      // KubeArmor
      bpf_ringbuf_submit(alert, BPF_RB_FORCE_WAKEUP);
      return -EPERM;
    } else {
      // Default posture is Audit, return ok and send (updated) alert to
      // KubeArmor
      alert->retval = 0;
      bpf_ringbuf_submit(alert, BPF_RB_FORCE_WAKEUP);
      return 0;
    }
  }

  // No matching policy, no default policy, return ok and discard the alert
  bpf_ringbuf_discard(alert, BPF_RB_NO_WAKEUP);
  return 0;
}

/*
  How do we check what to deny or not?

  We match in the the following order:
  - entity + source
  -? directory matching + source
  - entity
  -? directory

  Once matched
  -? Owner Check
  - Deny Check
  - Check if WhiteList i.e. DefaultPosture for entity is block
  - if not match deny

  ? => Indicates optional check, like network hooks don't have owner or
       directory checks
*/

#endif /* __SHARED_H */
