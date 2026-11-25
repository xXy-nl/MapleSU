// SPDX-License-Identifier: GPL-3.0-only
#include <linux/errno.h>
#include "native_imports.h"
#include "native_lookup.h"
#include "native_cfi.h"
#if MSU_INIT_BRIDGE_CFI_LEGACY && defined(MODULE)
/* Only these typed module-owned entries are used for indirect calls. Their
 * bodies make real external CALL26/JUMP26 calls bound by PID1. */
#define IMPORT_RETURN(result, name, declaration, arguments) \
    extern typeof(name) msu_direct_target_##name; \
    static noinline __used result ref_##name declaration { return msu_direct_target_##name arguments; } \
    typeof(&name) msu_native_##name = ref_##name; \
    _Static_assert(__builtin_types_compatible_p(typeof(&ref_##name), typeof(&name)), "native host prototype: " #name);
#define IMPORT_VOID(name, declaration, arguments) \
    extern typeof(name) msu_direct_target_##name; \
    static noinline __used void ref_##name declaration { msu_direct_target_##name arguments; } \
    typeof(&name) msu_native_##name = ref_##name; \
    _Static_assert(__builtin_types_compatible_p(typeof(&ref_##name), typeof(&name)), "native host prototype: " #name);
#else
#define IMPORT_RETURN(result, name, declaration, arguments) \
    typeof(&name) msu_native_##name; \
    static noinline result ref_##name declaration { return msu_native_##name arguments; } \
    _Static_assert(__builtin_types_compatible_p(typeof(&ref_##name), typeof(&name)), "native host prototype: " #name);
#define IMPORT_VOID(name, declaration, arguments) \
    typeof(&name) msu_native_##name; \
    static noinline void ref_##name declaration { msu_native_##name arguments; } \
    _Static_assert(__builtin_types_compatible_p(typeof(&ref_##name), typeof(&name)), "native host prototype: " #name);
#endif
#if defined(MSU_MANAGEMENT_RESIDENT_TEXT_OWNER) && MSU_MANAGEMENT_RESIDENT_TEXT_OWNER
IMPORT_RETURN(struct module *, __module_address, (unsigned long address), (address))
#endif
IMPORT_RETURN(struct module *, __module_text_address, (unsigned long address), (address))
#ifdef XATTR_NOSECURITY
IMPORT_RETURN(ssize_t, __vfs_getxattr, (struct dentry *dentry, struct inode *inode,
    const char *name, void *value, size_t bytes, int flags),
    (dentry, inode, name, value, bytes, flags))
#else
IMPORT_RETURN(ssize_t, __vfs_getxattr, (struct dentry *dentry, struct inode *inode,
    const char *name, void *value, size_t bytes), (dentry, inode, name, value, bytes))
#endif
IMPORT_VOID(abort_creds, (struct cred *cred), (cred))
IMPORT_RETURN(int, commit_creds, (struct cred *cred), (cred))
IMPORT_RETURN(struct filename *, getname_kernel, (const char *name), (name))
IMPORT_RETURN(struct group_info *, groups_alloc, (int count), (count))
IMPORT_VOID(groups_sort, (struct group_info *groups), (groups))
IMPORT_RETURN(bool, is_subdir, (struct dentry *child, struct dentry *parent), (child, parent))
IMPORT_VOID(putname, (struct filename *name), (name))
IMPORT_RETURN(int, schedule_on_each_cpu, (work_func_t function), (function))
IMPORT_VOID(security_cred_getsecid, (const struct cred *cred, u32 *secid), (cred, secid))
IMPORT_RETURN(int, security_secctx_to_secid, (const char *context, u32 length, u32 *secid),
    (context, length, secid))
IMPORT_VOID(set_groups, (struct cred *cred, struct group_info *groups), (cred, groups))
IMPORT_VOID(sha256, (const u8 *bytes, unsigned int length, u8 *digest), (bytes, length, digest))
/* Module-local forwarding leaves policy/source member names untouched.
 * Native lookup searches vmlinux before modules; init also rejects this entry
 * if no native SHA256 exists, so a module fallback never recurses here. */
void sha256(const u8 *bytes, unsigned int length, u8 *digest)
{
    msu_native_sha256(bytes, length, digest);
}
_Static_assert(__builtin_types_compatible_p(typeof(&sha256), typeof(msu_native_sha256)),
    "native SHA256 forwarding prototype");
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)
IMPORT_RETURN(ssize_t, vfs_getxattr, (struct mnt_idmap *idmap, struct dentry *dentry,
    const char *name, void *value, size_t bytes), (idmap, dentry, name, value, bytes))
IMPORT_RETURN(int, vfs_setxattr, (struct mnt_idmap *idmap, struct dentry *dentry,
    const char *name, const void *value, size_t bytes, int flags),
    (idmap, dentry, name, value, bytes, flags))
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(5, 12, 0)
IMPORT_RETURN(ssize_t, vfs_getxattr, (struct user_namespace *ns, struct dentry *dentry,
    const char *name, void *value, size_t bytes), (ns, dentry, name, value, bytes))
IMPORT_RETURN(int, vfs_setxattr, (struct user_namespace *ns, struct dentry *dentry,
    const char *name, const void *value, size_t bytes, int flags),
    (ns, dentry, name, value, bytes, flags))
#else
IMPORT_RETURN(ssize_t, vfs_getxattr, (struct dentry *dentry, const char *name,
    void *value, size_t bytes), (dentry, name, value, bytes))
IMPORT_RETURN(int, vfs_setxattr, (struct dentry *dentry, const char *name,
    const void *value, size_t bytes, int flags), (dentry, name, value, bytes, flags))
#endif
IMPORT_RETURN(ssize_t, kernel_read, (struct file *file, void *bytes, size_t count,
    loff_t *position), (file, bytes, count, position))
#ifdef CONFIG_TASKS_RCU
IMPORT_VOID(synchronize_rcu_tasks, (void), ())
#endif
#if !__has_include(<linux/execmem.h>)
IMPORT_RETURN(void *, module_alloc, (unsigned long bytes), (bytes))
IMPORT_VOID(module_memfree, (void *address), (address))
#endif
IMPORT_RETURN(long, copy_from_user_nofault, (void *to, const void __user *from, size_t size), (to, from, size))
IMPORT_RETURN(long, copy_to_user_nofault, (void __user *to, const void *from, size_t size), (to, from, size))
IMPORT_RETURN(long, copy_to_kernel_nofault, (void *to, const void *from, size_t size), (to, from, size))
IMPORT_RETURN(struct file *, filp_open, (const char *name, int flags, umode_t mode), (name, flags, mode))
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 15, 0)
IMPORT_RETURN(struct file *, file_open_root, (struct dentry *dentry, struct vfsmount *mount,
    const char *name, int flags, umode_t mode), (dentry, mount, name, flags, mode))
#else
IMPORT_RETURN(struct file *, file_open_root, (const struct path *root,
    const char *name, int flags, umode_t mode), (root, name, flags, mode))
#endif
IMPORT_RETURN(struct task_struct *, find_task_by_pid_ns, (pid_t pid, struct pid_namespace *ns), (pid, ns))
IMPORT_RETURN(struct file *, get_task_exe_file, (struct task_struct *task), (task))
#ifdef MSU_SU_EXEC_SESSION_NATIVE
IMPORT_RETURN(struct file *, get_mm_exe_file, (struct mm_struct *mm), (mm))
#endif
#if defined(MSU_SU_EXEC_SESSION_NATIVE) || defined(MSU_SU_NONROOT_NATIVE)
IMPORT_VOID(free_nsproxy, (struct nsproxy *ns), (ns))
IMPORT_RETURN(int, task_work_add, (struct task_struct *task,
    struct callback_head *work, enum task_work_notify_mode mode), (task, work, mode))
#endif
#ifdef MSU_SU_NONROOT_NATIVE
IMPORT_RETURN(int, path_mount, (const char *dev_name, struct path *path,
    const char *type_page, unsigned long flags, void *data_page),
    (dev_name, path, type_page, flags, data_page))
IMPORT_RETURN(int, path_umount, (struct path *path, int flags), (path, flags))
IMPORT_RETURN(bool, our_mnt, (struct vfsmount *mnt), (mnt))
IMPORT_VOID(fsnotify_get_mark, (struct fsnotify_mark *mark), (mark))
#if MSU_INIT_BRIDGE_CFI_LEGACY && defined(MODULE)
typeof(&__d_path) msu_native___d_path;
static noinline char *ref___d_path(const struct path *path, const struct path *root,
    char *buffer, int length) { return msu_native___d_path(path, root, buffer, length); }
#else
IMPORT_RETURN(char *, __d_path, (const struct path *path, const struct path *root,
    char *buffer, int length), (path, root, buffer, length))
#endif
struct rw_semaphore *msu_native_namespace_sem;
typeof(&init_nsproxy) msu_native_init_nsproxy;
#endif
IMPORT_VOID(fsnotify_get_group, (struct fsnotify_group *group), (group))
IMPORT_VOID(fsnotify_destroy_group, (struct fsnotify_group *group), (group))
IMPORT_VOID(fsnotify_wait_marks_destroyed, (void), ())
IMPORT_RETURN(ssize_t, vfs_write, (struct file *file, const char __user *buffer, size_t bytes, loff_t *position), (file, buffer, bytes, position))
IMPORT_RETURN(struct user_struct *, alloc_uid, (kuid_t uid), (uid))
#if MSU_MANAGEMENT_CRED_UCOUNTS
IMPORT_RETURN(int, set_cred_ucounts, (struct cred *cred), (cred))
#endif
IMPORT_RETURN(int, core_kernel_text, (unsigned long address), (address))
/* Preserve the native address/length or start/end ABI used by the caller. */
IMPORT_VOID(sync_icache_aliases,
    (typeof(__builtin_choose_expr(
        __builtin_types_compatible_p(typeof(&sync_icache_aliases),
            void (*)(void *, unsigned long)), (void *)0, 0UL)) address,
        unsigned long length_or_end), (address, length_or_end))
#ifdef CONFIG_SECCOMP_FILTER
IMPORT_VOID(seccomp_filter_release, (struct task_struct *task), (task))
#endif
#if __has_include(<linux/execmem.h>)
#if MSU_MANAGEMENT_EXECMEM_ALLOC_RW
IMPORT_RETURN(void *, execmem_alloc_rw, (enum execmem_type type, size_t bytes), (type, bytes))
#else
IMPORT_RETURN(void *, execmem_alloc, (enum execmem_type type, size_t bytes), (type, bytes))
#endif
IMPORT_VOID(execmem_free, (void *address), (address))
#endif
#if MSU_INIT_BRIDGE_CFI_LEGACY && defined(MODULE)
IMPORT_VOID(__put_cred, (struct cred *cred), (cred))
IMPORT_RETURN(bool, cancel_work, (struct work_struct *work), (work))
IMPORT_RETURN(struct cred *, prepare_creds, (void), ())
IMPORT_RETURN(const struct cred *, override_creds, (const struct cred *cred), (cred))
IMPORT_VOID(revert_creds, (const struct cred *cred), (cred))
IMPORT_VOID(path_get, (const struct path *path), (path))
IMPORT_RETURN(int, iterate_dir, (struct file *file, struct dir_context *context), (file, context))
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 0, 0)
IMPORT_RETURN(struct fsnotify_group *, fsnotify_alloc_group, (const struct fsnotify_ops *ops, int flags), (ops, flags))
#else
IMPORT_RETURN(struct fsnotify_group *, fsnotify_alloc_group, (const struct fsnotify_ops *ops), (ops))
#endif
IMPORT_VOID(fsnotify_init_mark, (struct fsnotify_mark *mark, struct fsnotify_group *group), (mark, group))
IMPORT_RETURN(int, fsnotify_add_mark, (struct fsnotify_mark *mark, fsnotify_connp_t *connector,
    unsigned int type, int allow_dups, __kernel_fsid_t *fsid), (mark, connector, type, allow_dups, fsid))
IMPORT_VOID(fsnotify_destroy_mark, (struct fsnotify_mark *mark, struct fsnotify_group *group), (mark, group))
IMPORT_VOID(fsnotify_put_group, (struct fsnotify_group *group), (group))
IMPORT_VOID(fsnotify_put_mark, (struct fsnotify_mark *mark), (mark))
#ifdef CONFIG_FORTIFY_SOURCE
static noinline __used __noreturn void ref_fortify_panic(const char *name)
{
    msu_direct_target_fortify_panic(name);
}
_Static_assert(__builtin_types_compatible_p(typeof(&ref_fortify_panic),
    typeof(&fortify_panic)), "native fortify prototype");
#endif
#endif
#undef IMPORT_RETURN
#undef IMPORT_VOID
struct tracepoint *msu_native_trace_exec, *msu_native_trace_exit;
typeof(&init_cred) msu_native_init_cred;
typeof(&init_user_ns) msu_native_init_user_ns;
struct mutex *msu_native_text_mutex;
ssize_t (*msu_native_procattr_marker)(struct file *, const char __user *, size_t, loff_t *);
#if MSU_INIT_BRIDGE_CFI_LEGACY && defined(MODULE)
#define MEMORY_DIRECT(name)     extern typeof(name) msu_direct_target_##name;     noinline __used int msu_native_##name(unsigned long address, int pages) {         return msu_direct_target_##name(address, pages);     }
MEMORY_DIRECT(set_memory_ro)
MEMORY_DIRECT(set_memory_rw)
MEMORY_DIRECT(set_memory_x)
MEMORY_DIRECT(set_memory_nx)
#undef MEMORY_DIRECT
extern typeof(aarch64_insn_patch_text) msu_direct_target_aarch64_insn_patch_text;
noinline __used int msu_native_patch_text(void **addresses, u32 *instructions, int count)
{
    return msu_direct_target_aarch64_insn_patch_text(addresses, instructions, count);
}
#else
static typeof(&set_memory_ro) native_ro;
static typeof(&set_memory_rw) native_rw;
static typeof(&set_memory_x) native_x;
static typeof(&set_memory_nx) native_nx;
static typeof(&aarch64_insn_patch_text) native_patch;

int msu_native_set_memory_ro(unsigned long address, int pages) { return native_ro(address, pages); }
int msu_native_set_memory_rw(unsigned long address, int pages) { return native_rw(address, pages); }
int msu_native_set_memory_x(unsigned long address, int pages) { return native_x(address, pages); }
int msu_native_set_memory_nx(unsigned long address, int pages) { return native_nx(address, pages); }
int msu_native_patch_text(void **addresses, u32 *instructions, int count)
{
    return native_patch(addresses, instructions, count);
}

#endif

static noinline ssize_t msu_native_procattr_type(struct file *file,
    const char __user *buffer, size_t bytes, loff_t *position)
{
    return msu_native_procattr_marker(file, buffer, bytes, position);
}

int msu_init_bridge_imports_init(void)
{
    unsigned long address;
    int error;

#define RESOLVE_TYPED(pointer, name, prototype) do { \
    error = msu_init_bridge_resolve_cfi(name, (void *)prototype, &address); \
    if (error) return error; \
    pointer = (typeof(pointer))address; \
} while (0)
#if !MSU_INIT_BRIDGE_CFI_LEGACY || !defined(MODULE)
    RESOLVE_TYPED(native_ro, "set_memory_ro", msu_native_set_memory_ro);
    RESOLVE_TYPED(native_rw, "set_memory_rw", msu_native_set_memory_rw);
    RESOLVE_TYPED(native_x, "set_memory_x", msu_native_set_memory_x);
    RESOLVE_TYPED(native_nx, "set_memory_nx", msu_native_set_memory_nx);
    RESOLVE_TYPED(native_patch, "aarch64_insn_patch_text", msu_native_patch_text);
#define IMPORT(name) RESOLVE_TYPED(msu_native_##name, #name, ref_##name)
#else
#define IMPORT(name) do { msu_native_##name = ref_##name; } while (0)
#endif
#if defined(MSU_MANAGEMENT_RESIDENT_TEXT_OWNER) && MSU_MANAGEMENT_RESIDENT_TEXT_OWNER
    IMPORT(__module_address);
#endif
    IMPORT(__module_text_address);
    IMPORT(__vfs_getxattr);
    IMPORT(abort_creds);
    IMPORT(commit_creds);
    IMPORT(getname_kernel);
    IMPORT(groups_alloc);
    IMPORT(groups_sort);
    IMPORT(is_subdir);
    IMPORT(putname);
    IMPORT(schedule_on_each_cpu);
    IMPORT(security_cred_getsecid);
    IMPORT(security_secctx_to_secid);
    IMPORT(set_groups);
    IMPORT(sha256);
    if (msu_native_sha256 == sha256) {
        msu_native_sha256 = NULL;
        return -ESTALE;
    }
    IMPORT(vfs_getxattr);
    IMPORT(vfs_setxattr);
    IMPORT(kernel_read);
#ifdef CONFIG_TASKS_RCU
    IMPORT(synchronize_rcu_tasks);
#endif
#if !__has_include(<linux/execmem.h>)
    IMPORT(module_alloc);
    IMPORT(module_memfree);
#endif
    IMPORT(copy_from_user_nofault);
    IMPORT(copy_to_user_nofault);
    IMPORT(copy_to_kernel_nofault);
    IMPORT(filp_open);
    IMPORT(file_open_root);
    IMPORT(find_task_by_pid_ns);
    IMPORT(get_task_exe_file);
#ifdef MSU_SU_EXEC_SESSION_NATIVE
    IMPORT(get_mm_exe_file);
#endif
#if defined(MSU_SU_EXEC_SESSION_NATIVE) || defined(MSU_SU_NONROOT_NATIVE)
    IMPORT(free_nsproxy);
    IMPORT(task_work_add);
#endif
#ifdef MSU_SU_NONROOT_NATIVE
    IMPORT(path_mount);
    IMPORT(path_umount);
    IMPORT(our_mnt);
    IMPORT(fsnotify_get_mark);
    /* MODULE-only capability: missing imports disable its source, preserving SU. */
    msu_native___d_path = NULL;
    if (!msu_init_bridge_resolve_cfi("__d_path", (void *)ref___d_path, &address))
        msu_native___d_path = (typeof(msu_native___d_path))address;
    address = msu_init_bridge_lookup("namespace_sem");
    msu_native_namespace_sem = address && !(address % __alignof__(struct rw_semaphore)) ?
        (struct rw_semaphore *)address : NULL;
#endif
    IMPORT(fsnotify_get_group);
    IMPORT(fsnotify_destroy_group);
    IMPORT(fsnotify_wait_marks_destroyed);
    IMPORT(vfs_write);
    IMPORT(alloc_uid);
#if MSU_MANAGEMENT_CRED_UCOUNTS
    IMPORT(set_cred_ucounts);
#endif
    IMPORT(core_kernel_text);
    IMPORT(sync_icache_aliases);
#if defined(CONFIG_SECCOMP_FILTER)
    IMPORT(seccomp_filter_release);
#endif
#if __has_include(<linux/execmem.h>)
#if MSU_MANAGEMENT_EXECMEM_ALLOC_RW
    IMPORT(execmem_alloc_rw);
#else
    IMPORT(execmem_alloc);
#endif
    IMPORT(execmem_free);
#endif
#undef IMPORT
#if defined(CONFIG_PROC_FS) && defined(CONFIG_SECURITY)
    RESOLVE_TYPED(msu_native_procattr_marker, "proc_pid_attr_write", msu_native_procattr_type);
#endif
#undef RESOLVE_TYPED
#ifdef MSU_SU_NONROOT_NATIVE
    address = msu_init_bridge_lookup("init_nsproxy");
    if (!address || address % __alignof__(struct nsproxy)) return -EOPNOTSUPP;
    msu_native_init_nsproxy = (typeof(msu_native_init_nsproxy))address;
#endif
    address = msu_init_bridge_lookup("init_user_ns");
    if (!address || address % __alignof__(struct user_namespace)) return -EOPNOTSUPP;
    msu_native_init_user_ns = (typeof(msu_native_init_user_ns))address;
    address = msu_init_bridge_lookup("init_cred");
    if (!address || address % __alignof__(struct cred)) return -EOPNOTSUPP;
    msu_native_init_cred = (typeof(msu_native_init_cred))address;
    address = msu_init_bridge_lookup("text_mutex");
    if (!address || address % __alignof__(struct mutex)) return -EOPNOTSUPP;
    msu_native_text_mutex = (struct mutex *)address;
    address = msu_init_bridge_lookup("__tracepoint_sched_process_exec");
    if (!address || address % __alignof__(struct tracepoint)) return -EOPNOTSUPP;
    msu_native_trace_exec = (struct tracepoint *)address;
    address = msu_init_bridge_lookup("__tracepoint_sched_process_exit");
    if (!address || address % __alignof__(struct tracepoint)) return -EOPNOTSUPP;
    msu_native_trace_exit = (struct tracepoint *)address;
    return 0;
}

#if MSU_INIT_BRIDGE_CFI_LEGACY && defined(MODULE)
static const char msu_direct_calls[] __used __section(".msu_direct_calls") =
    "MAPLESU_DIRECT_V2\0"
#if defined(MSU_BOOT_SDK_NATIVE)
    "msu_direct_target___arm64_sys_execve\0__arm64_sys_execve\0"
#endif
#if defined(MSU_BOOT_SDK_NATIVE) && LINUX_VERSION_CODE < KERNEL_VERSION(5, 11, 0)
    "msu_direct_target___flush_icache_range\0__flush_icache_range\0"
#endif
#if defined(MSU_MANAGEMENT_RESIDENT_TEXT_OWNER) && MSU_MANAGEMENT_RESIDENT_TEXT_OWNER
    "msu_direct_target___module_address\0__module_address\0"
#endif
    "msu_direct_target___module_text_address\0__module_text_address\0"
    "msu_direct_target___put_cred\0__put_cred\0"
    "msu_direct_target___vfs_getxattr\0__vfs_getxattr\0"
#if defined(MSU_BOOT_SDK_NATIVE) && !defined(vmalloc)
    "msu_direct_target___vmalloc_node_range\0__vmalloc_node_range\0"
#endif
#if defined(MSU_BOOT_SDK_NATIVE) && defined(vmalloc)
    "msu_direct_target___vmalloc_node_range_noprof\0__vmalloc_node_range_noprof\0"
#endif
    "msu_direct_target_aarch64_insn_patch_text\0aarch64_insn_patch_text\0"
    "msu_direct_target_abort_creds\0abort_creds\0"
    "msu_direct_target_alloc_uid\0alloc_uid\0"
#if defined(MSU_BOOT_SDK_NATIVE) && LINUX_VERSION_CODE >= KERNEL_VERSION(5, 11, 0)
    "msu_direct_target_caches_clean_inval_pou\0caches_clean_inval_pou\0"
#endif
    "msu_direct_target_cancel_work\0cancel_work\0"
    "msu_direct_target_commit_creds\0commit_creds\0"
#if defined(MSU_BOOT_SDK_NATIVE)
    "msu_direct_target_copy_from_kernel_nofault\0copy_from_kernel_nofault\0"
#endif
    "msu_direct_target_copy_from_user_nofault\0copy_from_user_nofault\0"
    "msu_direct_target_copy_to_kernel_nofault\0copy_to_kernel_nofault\0"
    "msu_direct_target_copy_to_user_nofault\0copy_to_user_nofault\0"
    "msu_direct_target_core_kernel_text\0core_kernel_text\0"
#if __has_include(<linux/execmem.h>) && !MSU_MANAGEMENT_EXECMEM_ALLOC_RW
    "msu_direct_target_execmem_alloc\0execmem_alloc\0"
#endif
#if __has_include(<linux/execmem.h>) && MSU_MANAGEMENT_EXECMEM_ALLOC_RW
    "msu_direct_target_execmem_alloc_rw\0execmem_alloc_rw\0"
#endif
#if __has_include(<linux/execmem.h>)
    "msu_direct_target_execmem_free\0execmem_free\0"
#endif
    "msu_direct_target_file_open_root\0file_open_root\0"
    "msu_direct_target_filp_open\0filp_open\0"
    "msu_direct_target_find_task_by_pid_ns\0find_task_by_pid_ns\0"
#if defined(CONFIG_FORTIFY_SOURCE)
    "msu_direct_target_fortify_panic\0fortify_panic\0"
#endif
#if defined(MSU_SU_EXEC_SESSION_NATIVE) || defined(MSU_SU_NONROOT_NATIVE)
    "msu_direct_target_free_nsproxy\0free_nsproxy\0"
#endif
    "msu_direct_target_fsnotify_add_mark\0fsnotify_add_mark\0"
    "msu_direct_target_fsnotify_alloc_group\0fsnotify_alloc_group\0"
    "msu_direct_target_fsnotify_destroy_group\0fsnotify_destroy_group\0"
    "msu_direct_target_fsnotify_destroy_mark\0fsnotify_destroy_mark\0"
    "msu_direct_target_fsnotify_get_group\0fsnotify_get_group\0"
#if defined(MSU_SU_NONROOT_NATIVE)
    "msu_direct_target_fsnotify_get_mark\0fsnotify_get_mark\0"
#endif
    "msu_direct_target_fsnotify_init_mark\0fsnotify_init_mark\0"
    "msu_direct_target_fsnotify_put_group\0fsnotify_put_group\0"
    "msu_direct_target_fsnotify_put_mark\0fsnotify_put_mark\0"
    "msu_direct_target_fsnotify_wait_marks_destroyed\0fsnotify_wait_marks_destroyed\0"
#if defined(MSU_SU_EXEC_SESSION_NATIVE)
    "msu_direct_target_get_mm_exe_file\0get_mm_exe_file\0"
#endif
#if defined(MSU_BOOT_SDK_NATIVE)
    "msu_direct_target_get_task_cred\0get_task_cred\0"
#endif
    "msu_direct_target_get_task_exe_file\0get_task_exe_file\0"
    "msu_direct_target_getname_kernel\0getname_kernel\0"
    "msu_direct_target_groups_alloc\0groups_alloc\0"
    "msu_direct_target_groups_sort\0groups_sort\0"
    "msu_direct_target_is_subdir\0is_subdir\0"
    "msu_direct_target_iterate_dir\0iterate_dir\0"
    "msu_direct_target_kernel_read\0kernel_read\0"
#if !__has_include(<linux/execmem.h>)
    "msu_direct_target_module_alloc\0module_alloc\0"
#endif
#if !__has_include(<linux/execmem.h>)
    "msu_direct_target_module_memfree\0module_memfree\0"
#endif
#if defined(MSU_SU_NONROOT_NATIVE)
    "msu_direct_target_our_mnt\0our_mnt\0"
#endif
    "msu_direct_target_override_creds\0override_creds\0"
    "msu_direct_target_path_get\0path_get\0"
#if defined(MSU_SU_NONROOT_NATIVE)
    "msu_direct_target_path_mount\0path_mount\0"
#endif
#if defined(MSU_SU_NONROOT_NATIVE)
    "msu_direct_target_path_umount\0path_umount\0"
#endif
    "msu_direct_target_prepare_creds\0prepare_creds\0"
    "msu_direct_target_putname\0putname\0"
    "msu_direct_target_revert_creds\0revert_creds\0"
    "msu_direct_target_schedule_on_each_cpu\0schedule_on_each_cpu\0"
#if defined(CONFIG_SECCOMP_FILTER)
    "msu_direct_target_seccomp_filter_release\0seccomp_filter_release\0"
#endif
    "msu_direct_target_security_cred_getsecid\0security_cred_getsecid\0"
    "msu_direct_target_security_secctx_to_secid\0security_secctx_to_secid\0"
#if MSU_MANAGEMENT_CRED_UCOUNTS
    "msu_direct_target_set_cred_ucounts\0set_cred_ucounts\0"
#endif
    "msu_direct_target_set_groups\0set_groups\0"
    "msu_direct_target_set_memory_nx\0set_memory_nx\0"
    "msu_direct_target_set_memory_ro\0set_memory_ro\0"
    "msu_direct_target_set_memory_rw\0set_memory_rw\0"
    "msu_direct_target_set_memory_x\0set_memory_x\0"
    "msu_direct_target_sha256\0sha256\0"
    "msu_direct_target_sync_icache_aliases\0sync_icache_aliases\0"
#if defined(CONFIG_TASKS_RCU)
    "msu_direct_target_synchronize_rcu_tasks\0synchronize_rcu_tasks\0"
#endif
#if defined(MSU_SU_EXEC_SESSION_NATIVE) || defined(MSU_SU_NONROOT_NATIVE)
    "msu_direct_target_task_work_add\0task_work_add\0"
#endif
#if defined(MSU_BOOT_SDK_NATIVE)
    "msu_direct_target_vfree\0vfree\0"
#endif
    "msu_direct_target_vfs_getxattr\0vfs_getxattr\0"
    "msu_direct_target_vfs_setxattr\0vfs_setxattr\0"
    "msu_direct_target_vfs_write\0vfs_write\0"
#if defined(MSU_BOOT_SDK_NATIVE) && !defined(vmalloc)
    "msu_direct_target_vmalloc\0vmalloc\0"
#endif
#if defined(MSU_BOOT_SDK_NATIVE) && defined(vmalloc)
    "msu_direct_target_vmalloc_noprof\0vmalloc_noprof\0"
#endif
#if defined(MSU_BOOT_SDK_NATIVE) && !defined(vmalloc_user)
    "msu_direct_target_vmalloc_user\0vmalloc_user\0"
#endif
#if defined(MSU_BOOT_SDK_NATIVE) && defined(vmalloc_user)
    "msu_direct_target_vmalloc_user_noprof\0vmalloc_user_noprof\0"
#endif
    "";
#endif
