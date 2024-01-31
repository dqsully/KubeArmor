// +build ignore
/* SPDX-License-Identifier: GPL-2.0    */
/* Copyright 2023 Authors of KubeArmor */

#include "shared.h"

SEC("lsm/bprm_check_security")
int BPF_PROG(enforce_proc, struct linux_binprm *bprm, int ret) {
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
  //
  // security_bprm_check() in the Linux kernel is called before the current task
  // is updated for the new executable (while handling the `execve` syscall).
  // This means that the 'parent' executable is actually still the current
  // task's executable.
  struct path f_path = BPF_CORE_READ(bprm->file, f_path);
  char *path = prepend_path(&f_path, BUFFER_ID_PATH);
  if (path != NULL && is_path_external(&f_path, task)) {
    path = prepend_ext(BUFFER_ID_PATH);
  }

  char *source = get_task_source(task, BUFFER_ID_PATH);

  u32 alert_flags = 0;
  u32 mask = RULE_MASK << RULE_OFFSET_PROCESS_EXECUTE;

  // If the current PID owns the file, set the owner flag and duplicate the mask
  // to cover PROCESS_EXECUTE_BY_OWNER
  if (is_owner_path(f_path.dentry)) {
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

  // Shift the process parts of the rule into place
  rule >>= RULE_OFFSET_PROCESS_EXECUTE;

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
    _SECURITY_BPRM_CHECK,
    alert_flags,
    rule,
    RULE_TYPE_FILE
  );
}

static __always_inline int match_net_policies(
  int socket_type,
  int protocol,
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

  // If the protocol is 0, try to guess it from the socket type
  if (protocol == 0) {
    if (socket_type == SOCK_STREAM) {
      protocol = IPPROTO_TCP;
    } else if (socket_type == SOCK_DGRAM) {
      protocol = IPPROTO_UDP;
    } else if (socket_type == SOCK_RAW) {
      protocol = 0xFF;
    }
  }

  // Construct a 'path string' out of the socket type
  struct network_rule_key path;
  path.rule_type = RULE_TYPE_NETWORK;
  path.protocol = protocol;
  path.null_byte = '\0';

  // Get the executable accessing the socket
  char *source = get_task_source(task, BUFFER_ID_PATH);

  u32 alert_flags = 0;

  // Get the best matching rule for this event
  u32 rule = match_net(inner, task, path.raw, source, RULE_MASK);

  // Apply the rule
  return apply_rule(
    inner,
    task,
    path.raw,
    source,
    event_id,
    alert_flags,
    rule,
    RULE_TYPE_FILE
  );
}

SEC("lsm/socket_create")
int BPF_PROG(enforce_net_create, int family, int type, int protocol) {
  return match_net_policies(type, protocol, _SOCKET_CREATE);
}

#define LSM_NET(name, ID)                                                      \
  int BPF_PROG(name, struct socket *sock) {                                    \
    int type = sock->type;                                                     \
    int protocol = sock->sk->sk_protocol;                                      \
    return match_net_policies(type, protocol, ID);                             \
  }

SEC("lsm/socket_connect")
LSM_NET(enforce_net_connect, _SOCKET_CONNECT);

SEC("lsm/socket_accept")
LSM_NET(enforce_net_accept, _SOCKET_ACCEPT);

SEC("lsm/file_open")
int BPF_PROG(enforce_file, struct file *file) {
  struct path f_path = BPF_CORE_READ(file, f_path);
  return match_and_enforce_path_hooks_read(&f_path, _FILE_OPEN);
}

SEC("lsm/file_permission")
int BPF_PROG(enforce_file_perm, struct file *file, int mask) {
  if (!(mask & (MASK_WRITE | MASK_APPEND))) {
    // only relevant when write events triggered, since rest is blocked by
    // file_open
    return 0;
  }

  struct path f_path = BPF_CORE_READ(file, f_path);
  return match_and_enforce_path_hooks_write(&f_path, _FILE_PERMISSION);
}
