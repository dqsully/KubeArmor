// +build ignore
/* SPDX-License-Identifier: GPL-2.0    */
/* Copyright 2023 Authors of KubeArmor */

#include "shared.h"
#include "syscalls.h"

SEC("lsm/bprm_check_security")
int BPF_PROG(enforce_proc, struct linux_binprm *bprm, int ret) {
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

  // Get the current process's executable
  char *path_ptr = get_task_source(task);

  // TODO: what to do if path_ptr is NULL?

  // Get the parent process's executable, if possible
  struct task_struct *parent_task = BPF_CORE_READ(task, parent);
  char *source_str = get_task_source(parent_task);

  // Matched enforcement policy
  struct data_t *matched_policy = NULL;

  if (source_str != NULL) {
    // Set up pk to check for an exact path+source match
    bpf_map_update_elem(&bufk, &pk_idx, z, BPF_ANY);
    bpf_probe_read_str(pk->path, MAX_STRING_SIZE, path_ptr);
    bpf_probe_read_str(pk->source, MAX_STRING_SIZE, source_str);

    // Check the inner map for an exact match
    matched_policy = bpf_map_lookup_elem(inner, pk);
    if (matched_policy != NULL && (matched_policy->processmask & RULE_EXEC)) {
      goto decision;
    }

    // Zero out and store the parent process's executable in tk->source to
    // prepare for a directory match
    bpf_map_update_elem(&bufk, &tk_idx, z, BPF_ANY);
    bpf_probe_read_str(tk->source, MAX_STRING_SIZE, source_str);

    // Do a check for any parent directory matches, using tk as a template, and
    // buffer #3 (otherwise unused) as a working buffer
    matched_policy = match_dir(inner, pk->path, tk_idx, 3, RULE_EXEC, false);
    if (matched_policy != NULL) {
      goto decision;
    }
  }

  // Zero out pk, set pk->path, and check for an exact match (no source set)
  bpf_map_update_elem(&bufk, &pk_idx, z, BPF_ANY);
  bpf_probe_read_str(pk->path, MAX_STRING_SIZE, path_ptr);

  matched_policy = bpf_map_lookup_elem(inner, pk);
  if (matched_policy && (matched_policy->processmask & RULE_EXEC)) {
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
  alert->event_id = _SECURITY_BPRM_CHECK;
  alert->retval = -EPERM;

  // If we found a matching policy and it's a deny policy, return permission
  // denied and send alert to KubeArmor
  if (matched_policy != NULL) {
    // We found a matching policy

    if (matched_policy->processmask & RULE_DENY) {
      // The matching policy is a deny policy, return permission denied and send
      // alert to KubeArmor
      bpf_ringbuf_submit(alert, BPF_RB_FORCE_WAKEUP);
      return -EPERM;
    }

    if ((matched_policy->processmask & RULE_OWNER) && !is_owner(bprm->file)) {
      // The matching policy is an allow policy with ownerOnly: true set, so
      // enforce that only the owner of the executable file is calling it
      bpf_ringbuf_submit(alert, BPF_RB_FORCE_WAKEUP);
      return -EPERM;
    }

    // Otherwise, the matching policy is an allow policy, return ok and discard
    // the alert
    bpf_ringbuf_discard(alert, BPF_RB_NO_WAKEUP);
    return 0;
  }

  // Clear out pk and set pk->path to the special value to check the default
  // process posture
  bpf_map_update_elem(&bufk, &pk_idx, z, BPF_ANY);
  pk->path[0] = dproc;

  struct data_t *default_posture = bpf_map_lookup_elem(inner, pk);

  if (default_posture != NULL) {
    if (default_posture->processmask == BLOCK_POSTURE) {
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

static __always_inline int match_net_policies(int type, int protocol, u32 eventID) {
  // Alert info sent to KubeArmor
  struct event *alert;

  // Current process/thread
  struct task_struct *task = (struct task_struct *)bpf_get_current_task();

  // Get the 'outer' map key (PID and mount namespace IDs) that identifies the
  // current container
  struct outer_key okey;
  get_outer_key(&okey, task);

  // Get the 'inner' map that contains the policies for the current container
  u32 *inner = bpf_map_lookup_elem(&kubearmor_containers, &okey);
  if (inner == NULL) {
    return 0;
  }

  // Attempt to get 'inner' key buffer #0 as 'z' (always filled with 0's)
  u32 zero = 0;
  bufs_k *z = bpf_map_lookup_elem(&bufk, &zero);
  if (z == NULL)
    return 0;

  // Attempt to get 'inner' key buffer #1 as 'p' (used to find a matching policy)
  u32 one = 1;
  bufs_k *p = bpf_map_lookup_elem(&bufk, &one);
  if (p == NULL)
    return 0;

  // Zero out p (buffer #1) in a single instruction
  bpf_map_update_elem(&bufk, &one, z, BPF_ANY);

  // Network protocol info
  struct sockinfo sock = {.type = type, .proto = protocol};
  // Matched enforcement policy
  struct data_t *matched_policy = NULL;

  if (protocol == 0) {
    if (type == SOCK_STREAM) {
      sock.proto = IPPROTO_TCP;
    } else if (type == SOCK_DGRAM) {
      sock.proto = IPPROTO_UDP;
    }
  }

  // Set p->path to a binary representation of the socket info
  p->path[0] = NET_MATCH;
  p->path[1] = sock.type;
  p->path[2] = sock.proto;

  // Get the process's executable, if possible (NULL-terminated string)
  char *source_str = get_task_source(task);

  if (source_str != NULL) {
    bpf_probe_read_str(p->source, MAX_STRING_SIZE, source_str);

    // Check the inner map for a matching policy
    matched_policy = bpf_map_lookup_elem(inner, p);

    if (matched_policy) {
      goto decision;
    }

    // Clear out p and reset p->path since we didn't find a match
    bpf_map_update_elem(&bufk, &one, z, BPF_ANY);

    p->path[0] = NET_MATCH;
    p->path[1] = sock.type;
    p->path[2] = sock.proto;
  }

  // Check the inner map for a matching policy (no source binary path)
  matched_policy = bpf_map_lookup_elem(inner, p);

decision:

  // Reserve space in the output ring buffer for this event
  alert = bpf_ringbuf_reserve(&kubearmor_events, sizeof(struct event), 0);
  if (alert == NULL) {
    return 0;
  }

  // Fill out common alert fields
  init_context(alert, task);

  // Read path and source strings into the alert
  bpf_probe_read_kernel_str(&alert->data.path, MAX_STRING_SIZE, p->path);
  bpf_probe_read_kernel_str(&alert->data.source, MAX_STRING_SIZE, p->source);

  // Add other alert fields
  alert->event_id = eventID;
  alert->retval = -EPERM;

  if (matched_policy != NULL) {
    // We found a matching policy

    if (matched_policy->processmask & RULE_DENY) {
      // The matching policy is a deny policy, return permission denied and send
      // alert to KubeArmor
      bpf_ringbuf_submit(alert, BPF_RB_FORCE_WAKEUP);
      return -EPERM;
    }

    // Otherwise, the matching policy is an allow policy, return ok and discard the
    // alert
    bpf_ringbuf_discard(alert, BPF_RB_NO_WAKEUP);
    return 0;
  }

  // Clear out p and set p->path to the a special value to check the default
  // network posture
  bpf_map_update_elem(&bufk, &one, z, BPF_ANY);
  p->path[0] = dnet;

  struct data_t *default_posture = bpf_map_lookup_elem(inner, p);

  if (default_posture != NULL) {
    if (default_posture->processmask == BLOCK_POSTURE) {
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

SEC("lsm/socket_create")
int BPF_PROG(enforce_net_create, int family, int type, int protocol) {
  return match_net_policies(type, protocol, _SOCKET_CREATE);
}

#define LSM_NET(name, ID)                                                      \
  int BPF_PROG(name, struct socket *sock) {                                    \
    int type = sock->type;                                                     \
    int protocol = sock->sk->sk_protocol;                                      \
    return match_net_policies(type, protocol, ID);                                \
  }

SEC("lsm/socket_connect")
LSM_NET(enforce_net_connect, _SOCKET_CONNECT);

SEC("lsm/socket_accept")
LSM_NET(enforce_net_accept, _SOCKET_ACCEPT);

SEC("lsm/file_open")
int BPF_PROG(enforce_file, struct file *file) { // check if ret code available
  struct path f_path = BPF_CORE_READ(file, f_path);
  return match_and_enforce_path_hooks(&f_path, dfileread, _FILE_OPEN);
}

SEC("lsm/file_permission")
int BPF_PROG(enforce_file_perm, struct file *file, int mask) {
  if (!(mask & (MASK_WRITE | MASK_APPEND))) {
    // only relevant when write events triggered, since rest is blocked by
    // file_open
    return 0;
  }

  struct path f_path = BPF_CORE_READ(file, f_path);
  return match_and_enforce_path_hooks(&f_path, dfilewrite, _FILE_PERMISSION);
}
