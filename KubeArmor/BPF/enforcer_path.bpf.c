// +build ignore
/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright 2023 Authors of KubeArmor */

#include "shared.h"

#define PATH_SEC_CALL(NAME , ID)                                               \
  SEC("lsm/path_" #NAME)                                                       \
  int BPF_PROG(enforce_##NAME, struct path *dir, struct dentry *dentry) {      \
    struct path f_path;                                                        \
    f_path.dentry = dentry;                                                    \
    f_path.mnt = BPF_CORE_READ(dir, mnt);                                      \
    return match_and_enforce_path_hooks_write(&f_path, ID);                    \
  }

PATH_SEC_CALL(mknod, _FILE_MKNOD)
PATH_SEC_CALL(rmdir, _FILE_RMDIR)
PATH_SEC_CALL(unlink, _FILE_UNLINK)
PATH_SEC_CALL(symlink, _FILE_SYMLINK)
PATH_SEC_CALL(mkdir, _FILE_MKDIR)

SEC("lsm/path_link")
int BPF_PROG(enforce_link_src, struct dentry *old_dentry, struct path *dir,
             struct dentry *new_dentry) {
  struct path f_path;
  f_path.dentry = old_dentry;
  f_path.mnt = BPF_CORE_READ(dir, mnt);
  return match_and_enforce_path_hooks_write(&f_path, _FILE_LINK);
}

SEC("lsm/path_link")
int BPF_PROG(enforce_link_dst, struct dentry *old_dentry, struct path *dir,
             struct dentry *new_dentry) {
  struct path f_path;
  f_path.dentry = new_dentry;
  f_path.mnt = BPF_CORE_READ(dir, mnt);
  return match_and_enforce_path_hooks_write(&f_path, _FILE_LINK);
}

SEC("lsm/path_rename")
int BPF_PROG(enforce_rename_old, struct path *old_dir,
             struct dentry *old_dentry) {
  struct path f_path;
  f_path.dentry = old_dentry;
  f_path.mnt = BPF_CORE_READ(old_dir, mnt);
  return match_and_enforce_path_hooks_write(&f_path, _FILE_RENAME);
}

SEC("lsm/path_rename")
int BPF_PROG(enforce_rename_new, struct path *old_dir,
             struct dentry *old_dentry, struct path *new_dir,
             struct dentry *new_dentry) {
  struct path f_path;
  f_path.dentry = new_dentry;
  f_path.mnt = BPF_CORE_READ(new_dir, mnt);
  return match_and_enforce_path_hooks_write(&f_path, _FILE_RENAME);
}

SEC("lsm/path_chmod")
int BPF_PROG(enforce_chmod, struct path *p) {
  // Copy path into stack frame so that we're passing a stack pointer. If we
  // used the trusted kernel pointer instead, prepend_path() internally would
  // fail to verify because it's not inlined and the verifier won't let a single
  // instruction operate on 2 different kinds of pointers.
  //
  // Also, use BPF_CORE_READ for no good reason except to erase pointer type
  // information within f_path so that the eBPF verifier isn't worrying about
  // quite so much, reducing total complexity.
  struct path f_path;
  f_path.dentry = BPF_CORE_READ(p, dentry);
  f_path.mnt = BPF_CORE_READ(p, mnt);
  return match_and_enforce_path_hooks_write(&f_path, _FILE_CHMOD);
}

// SEC("lsm/path_chown")
// int BPF_PROG(enforce_chown, struct path *p) {
//   return match_and_enforce_path_hooks_write(p, _FILE_CHOWN);
// }

SEC("lsm/path_truncate")
int BPF_PROG(enforce_truncate, struct path *p) {
  // Copy path into stack frame so that we're passing a stack pointer. If we
  // used the trusted kernel pointer instead, prepend_path() internally would
  // fail to verify because it's not inlined and the verifier won't let a single
  // instruction operate on 2 different kinds of pointers.
  //
  // Also, use BPF_CORE_READ for no good reason except to erase pointer type
  // information within f_path so that the eBPF verifier isn't worrying about
  // quite so much, reducing total complexity.
  struct path f_path;
  f_path.dentry = BPF_CORE_READ(p, dentry);
  f_path.mnt = BPF_CORE_READ(p, mnt);
  return match_and_enforce_path_hooks_write(&f_path, _FILE_TRUNCATE);
}
