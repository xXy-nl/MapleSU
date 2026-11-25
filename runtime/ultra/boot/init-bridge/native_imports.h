/* SPDX-License-Identifier: GPL-3.0-only */
#ifndef MAPLESU_INIT_BRIDGE_NATIVE_IMPORTS_H
#define MAPLESU_INIT_BRIDGE_NATIVE_IMPORTS_H
#include "msu_resolver_build_config.h"
#include "native_cfi.h"
#include "native_direct.h"
#include <linux/fs.h>
#include <linux/rwsem.h>
#include <linux/fsnotify_backend.h>
#include <linux/init_task.h>
#include <linux/mm.h>
#include <linux/mount.h>
#include <linux/nsproxy.h>
#include <linux/mutex.h>
#include <linux/cred.h>
#include <linux/user_namespace.h>
#include <linux/kernel.h>
#include <linux/pid_namespace.h>
#include <linux/sched/user.h>
#include <linux/uaccess.h>
#include <linux/vmalloc.h>
#include <linux/tracepoint.h>
#include <linux/task_work.h>
#include <linux/version.h>
#include <linux/module.h>
#if !__has_include(<linux/execmem.h>)
#include <linux/moduleloader.h>
#endif
#include <linux/rcupdate.h>
#include <linux/seccomp.h>
#include <linux/security.h>
#include <linux/workqueue.h>
#include <linux/xattr.h>
#if __has_include(<crypto/sha2.h>)
#include <crypto/sha2.h>
#else
#include <crypto/sha.h>
#endif
#include <asm/cacheflush.h>
#if __has_include(<linux/execmem.h>)
#include <linux/execmem.h>
#endif
#include <asm/set_memory.h>
#if __has_include(<asm/text-patching.h>)
#include <asm/text-patching.h>
#elif __has_include(<asm/patching.h>)
#include <asm/patching.h>
#else
#include <asm/insn.h>
#endif

extern typeof(set_memory_ro) msu_native_set_memory_ro;
extern typeof(set_memory_rw) msu_native_set_memory_rw;
extern typeof(set_memory_x) msu_native_set_memory_x;
extern typeof(set_memory_nx) msu_native_set_memory_nx;
extern typeof(aarch64_insn_patch_text) msu_native_patch_text;
extern struct mutex *msu_native_text_mutex;
extern ssize_t (*msu_native_procattr_marker)(struct file *, const char __user *, size_t, loff_t *);
/* Native functions used by the selected HOST/SDK TUs which are outside this
 * target's module-export contract. Keep their actual declarations and typed
 * CFI-qualified pointers; no synthetic export or CRC is introduced. */
#if defined(MSU_MANAGEMENT_RESIDENT_TEXT_OWNER) && MSU_MANAGEMENT_RESIDENT_TEXT_OWNER
extern typeof(&__module_address) msu_native___module_address;
#endif
extern typeof(&__module_text_address) msu_native___module_text_address;
extern typeof(&__vfs_getxattr) msu_native___vfs_getxattr;
extern typeof(&abort_creds) msu_native_abort_creds;
extern typeof(&commit_creds) msu_native_commit_creds;
extern typeof(&getname_kernel) msu_native_getname_kernel;
extern typeof(&groups_alloc) msu_native_groups_alloc;
extern typeof(&groups_sort) msu_native_groups_sort;
extern typeof(&is_subdir) msu_native_is_subdir;
extern typeof(&putname) msu_native_putname;
extern typeof(&schedule_on_each_cpu) msu_native_schedule_on_each_cpu;
extern typeof(&security_cred_getsecid) msu_native_security_cred_getsecid;
extern typeof(&security_secctx_to_secid) msu_native_security_secctx_to_secid;
extern typeof(&set_groups) msu_native_set_groups;
extern typeof(&sha256) msu_native_sha256;
extern typeof(&vfs_getxattr) msu_native_vfs_getxattr;
extern typeof(&vfs_setxattr) msu_native_vfs_setxattr;
extern typeof(&kernel_read) msu_native_kernel_read;
#ifdef CONFIG_TASKS_RCU
extern typeof(&synchronize_rcu_tasks) msu_native_synchronize_rcu_tasks;
#endif
#if !__has_include(<linux/execmem.h>)
extern typeof(&module_alloc) msu_native_module_alloc;
extern typeof(&module_memfree) msu_native_module_memfree;
#endif
extern typeof(&copy_from_user_nofault) msu_native_copy_from_user_nofault;
extern typeof(&copy_to_user_nofault) msu_native_copy_to_user_nofault;
extern typeof(&copy_to_kernel_nofault) msu_native_copy_to_kernel_nofault;
extern typeof(&filp_open) msu_native_filp_open;
extern typeof(&file_open_root) msu_native_file_open_root;
extern typeof(&find_task_by_pid_ns) msu_native_find_task_by_pid_ns;
extern typeof(&get_task_exe_file) msu_native_get_task_exe_file;
#ifdef MSU_SU_EXEC_SESSION_NATIVE
extern typeof(&get_mm_exe_file) msu_native_get_mm_exe_file;
#endif
#if defined(MSU_SU_EXEC_SESSION_NATIVE) || defined(MSU_SU_NONROOT_NATIVE)
extern typeof(&free_nsproxy) msu_native_free_nsproxy;
extern typeof(&task_work_add) msu_native_task_work_add;
#endif
#ifdef MSU_SU_NONROOT_NATIVE
extern int path_mount(const char *dev_name, struct path *path,
    const char *type_page, unsigned long flags, void *data_page);
extern int path_umount(struct path *path, int flags);
extern typeof(&path_mount) msu_native_path_mount;
extern typeof(&path_umount) msu_native_path_umount;
extern typeof(&our_mnt) msu_native_our_mnt;
extern typeof(&init_nsproxy) msu_native_init_nsproxy;
extern typeof(&fsnotify_get_mark) msu_native_fsnotify_get_mark;
extern typeof(&__d_path) msu_native___d_path;
extern struct rw_semaphore *msu_native_namespace_sem;
#endif
extern typeof(&fsnotify_get_group) msu_native_fsnotify_get_group;
extern typeof(&fsnotify_destroy_group) msu_native_fsnotify_destroy_group;
extern typeof(&fsnotify_wait_marks_destroyed) msu_native_fsnotify_wait_marks_destroyed;
extern typeof(&init_cred) msu_native_init_cred;
extern typeof(&init_user_ns) msu_native_init_user_ns;
extern typeof(&vfs_write) msu_native_vfs_write;
extern typeof(&alloc_uid) msu_native_alloc_uid;
#if MSU_MANAGEMENT_CRED_UCOUNTS
extern typeof(&set_cred_ucounts) msu_native_set_cred_ucounts;
#endif
extern typeof(&core_kernel_text) msu_native_core_kernel_text;
extern typeof(&sync_icache_aliases) msu_native_sync_icache_aliases;
extern struct tracepoint *msu_native_trace_exec, *msu_native_trace_exit;
#ifdef CONFIG_SECCOMP_FILTER
extern typeof(&seccomp_filter_release) msu_native_seccomp_filter_release;
#endif
#if __has_include(<linux/execmem.h>)
#if MSU_MANAGEMENT_EXECMEM_ALLOC_RW
extern typeof(&execmem_alloc_rw) msu_native_execmem_alloc_rw;
#else
extern typeof(&execmem_alloc) msu_native_execmem_alloc;
#endif
extern typeof(&execmem_free) msu_native_execmem_free;
#endif

int msu_init_bridge_imports_init(void);

/* Applied only to the selected host TUs. Marker/data retain the actual native
 * pointer, including the host's f_op comparison and native text mutex identity. */
#ifdef MSU_INIT_BRIDGE_HOST_IMPORTS
#if defined(MSU_SU_EXEC_SESSION_NATIVE) || defined(MSU_SU_NONROOT_NATIVE)
/* Preserve the native put_nsproxy inline's atomic last-reference semantics;
 * its non-exported destructor is resolved through the same typed binder.
 * The actual target member type selects the native count operation. */
static inline void msu_init_bridge_put_nsproxy(struct nsproxy *ns)
{
    if (_Generic(&ns->count, refcount_t *: refcount_dec_and_test,
                 atomic_t *: atomic_dec_and_test)(&ns->count))
        msu_native_free_nsproxy(ns);
}
#define put_nsproxy msu_init_bridge_put_nsproxy
#endif
#define set_memory_ro msu_native_set_memory_ro
#define set_memory_rw msu_native_set_memory_rw
#define set_memory_x msu_native_set_memory_x
#define set_memory_nx msu_native_set_memory_nx
#define aarch64_insn_patch_text msu_native_patch_text
#define text_mutex (*msu_native_text_mutex)
#define proc_pid_attr_write (*msu_native_procattr_marker)
#if defined(MSU_MANAGEMENT_RESIDENT_TEXT_OWNER) && MSU_MANAGEMENT_RESIDENT_TEXT_OWNER
#define __module_address (*msu_native___module_address)
#endif
#define __module_text_address (*msu_native___module_text_address)
#define __vfs_getxattr (*msu_native___vfs_getxattr)
#define abort_creds (*msu_native_abort_creds)
#define commit_creds (*msu_native_commit_creds)
#define getname_kernel (*msu_native_getname_kernel)
#define groups_alloc (*msu_native_groups_alloc)
#define groups_sort (*msu_native_groups_sort)
#define is_subdir (*msu_native_is_subdir)
#define putname (*msu_native_putname)
#define schedule_on_each_cpu (*msu_native_schedule_on_each_cpu)
#define security_cred_getsecid (*msu_native_security_cred_getsecid)
#define security_secctx_to_secid (*msu_native_security_secctx_to_secid)
#define set_groups (*msu_native_set_groups)
#define vfs_getxattr (*msu_native_vfs_getxattr)
#define vfs_setxattr (*msu_native_vfs_setxattr)
#define kernel_read (*msu_native_kernel_read)
#ifdef CONFIG_TASKS_RCU
#define synchronize_rcu_tasks (*msu_native_synchronize_rcu_tasks)
#endif
#if !__has_include(<linux/execmem.h>)
#define module_alloc (*msu_native_module_alloc)
#define module_memfree (*msu_native_module_memfree)
#endif
#define copy_from_user_nofault (*msu_native_copy_from_user_nofault)
#define copy_to_user_nofault (*msu_native_copy_to_user_nofault)
#define copy_to_kernel_nofault (*msu_native_copy_to_kernel_nofault)
#define filp_open (*msu_native_filp_open)
#define file_open_root (*msu_native_file_open_root)
#define find_task_by_pid_ns (*msu_native_find_task_by_pid_ns)
#define get_task_exe_file (*msu_native_get_task_exe_file)
#ifdef MSU_SU_EXEC_SESSION_NATIVE
#define get_mm_exe_file (*msu_native_get_mm_exe_file)
#endif
#if defined(MSU_SU_EXEC_SESSION_NATIVE) || defined(MSU_SU_NONROOT_NATIVE)
#define free_nsproxy (*msu_native_free_nsproxy)
#define task_work_add (*msu_native_task_work_add)
#endif
#ifdef MSU_SU_NONROOT_NATIVE
#define path_mount (*msu_native_path_mount)
#define path_umount (*msu_native_path_umount)
#define __d_path (*msu_native___d_path)
#define namespace_sem (*msu_native_namespace_sem)
#define our_mnt (*msu_native_our_mnt)
#define init_nsproxy (*msu_native_init_nsproxy)
#define fsnotify_get_mark (*msu_native_fsnotify_get_mark)
#endif
#define fsnotify_get_group (*msu_native_fsnotify_get_group)
#define fsnotify_destroy_group (*msu_native_fsnotify_destroy_group)
#define fsnotify_wait_marks_destroyed (*msu_native_fsnotify_wait_marks_destroyed)
#define init_cred (*msu_native_init_cred)
#define init_user_ns (*msu_native_init_user_ns)
#define vfs_write (*msu_native_vfs_write)
#define alloc_uid (*msu_native_alloc_uid)
#if MSU_MANAGEMENT_CRED_UCOUNTS
#define set_cred_ucounts (*msu_native_set_cred_ucounts)
#endif
#define core_kernel_text (*msu_native_core_kernel_text)
#define sync_icache_aliases (*msu_native_sync_icache_aliases)
#define __tracepoint_sched_process_exec (*msu_native_trace_exec)
#define __tracepoint_sched_process_exit (*msu_native_trace_exit)
#ifdef CONFIG_SECCOMP_FILTER
#define seccomp_filter_release (*msu_native_seccomp_filter_release)
#endif
#if __has_include(<linux/execmem.h>)
#if MSU_MANAGEMENT_EXECMEM_ALLOC_RW
#define execmem_alloc_rw (*msu_native_execmem_alloc_rw)
#else
#define execmem_alloc (*msu_native_execmem_alloc)
#endif
#define execmem_free (*msu_native_execmem_free)
#endif
#endif
#endif
