// SPDX-License-Identifier: GPL-3.0-only
#include <linux/errno.h>
#include <linux/string.h>
#include <linux/stddef.h>
#include <asm/cacheflush.h>
#include "native_sdk.h"
#include "native_lookup.h"
#include "native_imports.h"
#include "legacy_hook_private.h"
#if defined(MSU_INIT_BRIDGE_RUNTIME_FACTS) && MSU_INIT_BRIDGE_RUNTIME_FACTS
#include "manager_runtime_accessor.h"
#endif

int msu_init_bridge_environment_filename(unsigned int *offset)
{
    unsigned int value;

    if (!offset) return -EINVAL;
#if defined(MSU_INIT_BRIDGE_RUNTIME_FACTS) && MSU_INIT_BRIDGE_RUNTIME_FACTS
    {
        struct msu_runtime_btf_field field;
        int error = msu_runtime_facts_field("filename", "name", &field);
        if (error) return error;
        if (field.kind != 2 || field.bytes != sizeof(void *) ||
            field.offset % __alignof__(void *) || !field.owner_bytes ||
            field.offset > field.owner_bytes || field.bytes > field.owner_bytes - field.offset)
            return -EPROTO;
        value = field.offset;
    }
#else
    value = offsetof(struct filename, name);
#endif
    /* The existing append protocol reserves one byte for this actual field. */
    if (value > 255) return -EOVERFLOW;
    *offset = value;
    return 0;
}

static noinline void reference_environment_release(const void *address)
{
#if __has_include(<linux/execmem.h>)
    msu_native_execmem_free((void *)address);
#else
    msu_native_module_memfree((void *)address);
#endif
}

#ifdef vmalloc
#define reference_vmalloc reference_vmalloc_noprof
#define reference_vmalloc_range reference___vmalloc_node_range_noprof
#else
#define reference_vmalloc_range reference___vmalloc_node_range
#endif
#ifdef vmalloc_user
#define reference_vmalloc_user reference_vmalloc_user_noprof
#endif
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 11, 0)
#define reference_cache reference___flush_icache_range
#else
#define reference_cache reference_caches_clean_inval_pou
#endif
#define reference_execve reference___arm64_sys_execve

/* These real typed forwarding functions supply this compiler's reference CFI
 * IDs; only runtime-resolved matching native addresses enter the producer. */
#if MSU_INIT_BRIDGE_CFI_LEGACY && defined(MODULE)
#define SDK_RETURN(result, label, target, declaration, arguments) \
    extern result target declaration; \
    static noinline __used result reference_##label declaration { return target arguments; }
#define SDK_VOID(label, target, declaration, arguments) \
    extern void target declaration; \
    static noinline __used void reference_##label declaration { target arguments; }
SDK_RETURN(long, copy_from_user_nofault, msu_direct_target_copy_from_user_nofault,
    (void *to, const void __user *from, size_t size), (to, from, size))
SDK_RETURN(long, copy_to_user_nofault, msu_direct_target_copy_to_user_nofault,
    (void __user *to, const void *from, size_t size), (to, from, size))
SDK_RETURN(long, copy_from_kernel_nofault, msu_direct_target_copy_from_kernel_nofault,
    (void *to, const void *from, size_t size), (to, from, size))
SDK_RETURN(long, copy_to_kernel_nofault, msu_direct_target_copy_to_kernel_nofault,
    (void *to, const void *from, size_t size), (to, from, size))
#ifdef vmalloc
SDK_RETURN(void *, vmalloc, msu_direct_target_vmalloc_noprof, (unsigned long bytes), (bytes))
SDK_RETURN(void *, vmalloc_range, msu_direct_target___vmalloc_node_range_noprof,
    (unsigned long size, unsigned long align, unsigned long start, unsigned long end,
    gfp_t gfp, pgprot_t prot, unsigned long flags, int node, const void *caller),
    (size, align, start, end, gfp, prot, flags, node, caller))
#else
SDK_RETURN(void *, vmalloc, msu_direct_target_vmalloc, (unsigned long bytes), (bytes))
SDK_RETURN(void *, vmalloc_range, msu_direct_target___vmalloc_node_range,
    (unsigned long size, unsigned long align, unsigned long start, unsigned long end,
    gfp_t gfp, pgprot_t prot, unsigned long flags, int node, const void *caller),
    (size, align, start, end, gfp, prot, flags, node, caller))
#endif
#ifdef vmalloc_user
SDK_RETURN(void *, vmalloc_user, msu_direct_target_vmalloc_user_noprof, (unsigned long bytes), (bytes))
#else
SDK_RETURN(void *, vmalloc_user, msu_direct_target_vmalloc_user, (unsigned long bytes), (bytes))
#endif
SDK_VOID(vfree, msu_direct_target_vfree, (const void *address), (address))
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 11, 0)
SDK_VOID(cache, msu_direct_target___flush_icache_range, (unsigned long start, unsigned long end), (start, end))
#else
SDK_VOID(cache, msu_direct_target_caches_clean_inval_pou, (unsigned long start, unsigned long end), (start, end))
#endif
SDK_RETURN(struct cred *, prepare_creds, msu_direct_target_prepare_creds, (void), ())
SDK_RETURN(int, commit_creds, msu_direct_target_commit_creds, (struct cred *cred), (cred))
SDK_RETURN(const struct cred *, get_task_cred, msu_direct_target_get_task_cred, (struct task_struct *task), (task))
SDK_VOID(__put_cred, msu_direct_target___put_cred, (struct cred *cred), (cred))
SDK_RETURN(long, execve, msu_direct_target___arm64_sys_execve, (const struct pt_regs *regs), (regs))
#if defined(MSU_MANAGEMENT_RESIDENT_TEXT_OWNER) && MSU_MANAGEMENT_RESIDENT_TEXT_OWNER
/* These are the selected module's own resident registry, never kernel aliases. */
static noinline int reference_maplesu_legacy_hook_provider_get(
    const struct maplesu_legacy_hook_provider **provider, void **lease)
{
    return maplesu_legacy_hook_provider_get(provider, lease);
}
static noinline void reference_maplesu_legacy_hook_provider_put(void *lease)
{
    maplesu_legacy_hook_provider_put(lease);
}
#else
static int (*target_maplesu_legacy_hook_provider_get)(const struct maplesu_legacy_hook_provider **, void **);
static void (*target_maplesu_legacy_hook_provider_put)(void *);
static noinline int reference_maplesu_legacy_hook_provider_get(
    const struct maplesu_legacy_hook_provider **provider, void **lease)
{
    return target_maplesu_legacy_hook_provider_get(provider, lease);
}
static noinline void reference_maplesu_legacy_hook_provider_put(void *lease)
{
    target_maplesu_legacy_hook_provider_put(lease);
}
#endif
#undef SDK_RETURN
#undef SDK_VOID
#else
#define REF_RETURN(result, name, declaration, arguments) \
    static result (*target_##name) declaration; \
    static noinline result reference_##name declaration { return target_##name arguments; }
#define REF_VOID(name, declaration, arguments) \
    static void (*target_##name) declaration; \
    static noinline void reference_##name declaration { target_##name arguments; }
REF_RETURN(long, copy_from_user_nofault, (void *to, const void __user *from, size_t size), (to, from, size))
REF_RETURN(long, copy_to_user_nofault, (void __user *to, const void *from, size_t size), (to, from, size))
REF_RETURN(long, copy_from_kernel_nofault, (void *to, const void *from, size_t size), (to, from, size))
REF_RETURN(long, copy_to_kernel_nofault, (void *to, const void *from, size_t size), (to, from, size))
REF_RETURN(void *, vmalloc, (unsigned long bytes), (bytes))
REF_RETURN(void *, vmalloc_user, (unsigned long bytes), (bytes))
REF_RETURN(void *, vmalloc_range, (unsigned long size, unsigned long align,
    unsigned long start, unsigned long end, gfp_t gfp, pgprot_t prot,
    unsigned long flags, int node, const void *caller), (size, align, start, end, gfp, prot, flags, node, caller))
REF_VOID(vfree, (const void *address), (address))
REF_VOID(cache, (unsigned long start, unsigned long end), (start, end))
REF_RETURN(struct cred *, prepare_creds, (void), ())
REF_RETURN(int, commit_creds, (struct cred *cred), (cred))
REF_RETURN(const struct cred *, get_task_cred, (struct task_struct *task), (task))
REF_VOID(__put_cred, (struct cred *cred), (cred))
REF_RETURN(long, execve, (const struct pt_regs *regs), (regs))
REF_RETURN(int, maplesu_legacy_hook_provider_get,
    (const struct maplesu_legacy_hook_provider **provider, void **lease), (provider, lease))
REF_VOID(maplesu_legacy_hook_provider_put, (void *lease), (lease))
#undef REF_RETURN
#undef REF_VOID

#endif

/* Inner segmented allocators place four unsigned page indices before the
 * virtual range. Its own typed reference keeps the native CFI call contract. */
static void *(*target_vmalloc_segmented_range)(unsigned long, unsigned long,
    unsigned int, unsigned int, unsigned int, unsigned int, unsigned long,
    unsigned long, gfp_t, pgprot_t, unsigned long, int, const void *);
static noinline void *reference_vmalloc_segmented_range(unsigned long size, unsigned long align,
    unsigned int begin, unsigned int pages, unsigned int init_begin, unsigned int init_end,
    unsigned long start, unsigned long end, gfp_t gfp, pgprot_t prot,
    unsigned long flags, int node, const void *caller)
{
    return target_vmalloc_segmented_range(size, align, begin, pages, init_begin, init_end,
        start, end, gfp, prot, flags, node, caller);
}

#define MATCH_NATIVE(name) _Static_assert(__builtin_types_compatible_p( \
    typeof(&reference_##name), typeof(&name)), "native SDK prototype: " #name)
MATCH_NATIVE(copy_from_user_nofault);
MATCH_NATIVE(copy_to_user_nofault);
MATCH_NATIVE(copy_from_kernel_nofault);
MATCH_NATIVE(copy_to_kernel_nofault);
MATCH_NATIVE(vfree);
MATCH_NATIVE(prepare_creds);
MATCH_NATIVE(commit_creds);
MATCH_NATIVE(get_task_cred);
MATCH_NATIVE(__put_cred);
MATCH_NATIVE(maplesu_legacy_hook_provider_get);
MATCH_NATIVE(maplesu_legacy_hook_provider_put);
#undef MATCH_NATIVE
#ifdef vmalloc
_Static_assert(__builtin_types_compatible_p(typeof(&reference_vmalloc), typeof(&vmalloc_noprof)), "native vmalloc prototype");
_Static_assert(__builtin_types_compatible_p(typeof(&reference_vmalloc_range), typeof(&__vmalloc_node_range_noprof)), "native range allocator prototype");
#else
_Static_assert(__builtin_types_compatible_p(typeof(&reference_vmalloc), typeof(&vmalloc)), "native vmalloc prototype");
_Static_assert(__builtin_types_compatible_p(typeof(&reference_vmalloc_range), typeof(&__vmalloc_node_range)), "native range allocator prototype");
#endif
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 11, 0)
_Static_assert(__builtin_types_compatible_p(typeof(&reference_cache),
    typeof(&__flush_icache_range)), "native instruction cache prototype");
#else
_Static_assert(__builtin_types_compatible_p(typeof(&reference_cache),
    typeof(&caches_clean_inval_pou)), "native instruction cache prototype");
#endif

struct msu_native_sdk_symbol {
    const char *name;
    const void *reference;
    unsigned long address;
};

static struct msu_native_sdk_symbol sdk_symbols[] = {
    { "copy_from_user_nofault", reference_copy_from_user_nofault },
    { "copy_to_user_nofault", reference_copy_to_user_nofault },
    { "copy_from_kernel_nofault", reference_copy_from_kernel_nofault },
    { "copy_to_kernel_nofault", reference_copy_to_kernel_nofault },
    { "vfree", reference_vfree },
    { "prepare_creds", reference_prepare_creds },
    { "commit_creds", reference_commit_creds },
    { "get_task_cred", reference_get_task_cred },
    { "__put_cred", reference___put_cred },
    { "__arm64_sys_execve", reference_execve },
    { "maplesu_legacy_hook_provider_get", reference_maplesu_legacy_hook_provider_get },
    { "maplesu_legacy_hook_provider_put", reference_maplesu_legacy_hook_provider_put },
};

unsigned long msu_init_bridge_checked_lookup(const char *name)
{
#if !MSU_INIT_BRIDGE_CFI_LEGACY || !defined(MODULE)
    const void *reference = NULL;
#endif
    unsigned long address = 0;
    unsigned int i;

    if (!name) return 0;
#if __has_include(<linux/execmem.h>)
    if (!strcmp(name, "execmem_free")) return (unsigned long)reference_environment_release;
#else
    if (!strcmp(name, "module_memfree")) return (unsigned long)reference_environment_release;
#endif
    if (!strcmp(name, "___vmalloc_node_range") || !strcmp(name, "___vmalloc_node_range_noprof")) {
        if (!msu_init_bridge_resolve_cfi(name, reference_vmalloc_segmented_range, &address))
            return address;
        return msu_init_bridge_resolve_cfi(name, reference_vmalloc_range, &address) ? 0 : address;
    }
#if MSU_INIT_BRIDGE_CFI_LEGACY && defined(MODULE)
    for (i = 0; i < ARRAY_SIZE(sdk_symbols); ++i)
        if (!strcmp(name, sdk_symbols[i].name)) {
            if (i < ARRAY_SIZE(sdk_symbols) - 2)
                return (unsigned long)sdk_symbols[i].reference;
#if defined(MSU_MANAGEMENT_RESIDENT_TEXT_OWNER) && MSU_MANAGEMENT_RESIDENT_TEXT_OWNER
            return (unsigned long)sdk_symbols[i].reference;
#else
            if (!sdk_symbols[i].address && msu_init_bridge_resolve_cfi(name,
                    sdk_symbols[i].reference, &sdk_symbols[i].address)) return 0;
            return sdk_symbols[i].address;
#endif
        }
#ifdef vmalloc
    if (!strcmp(name, "vmalloc_noprof")) return (unsigned long)reference_vmalloc;
    if (!strcmp(name, "__vmalloc_node_range_noprof")) return (unsigned long)reference_vmalloc_range;
#else
    if (!strcmp(name, "vmalloc")) return (unsigned long)reference_vmalloc;
    if (!strcmp(name, "__vmalloc_node_range")) return (unsigned long)reference_vmalloc_range;
#endif
#ifdef vmalloc_user
    if (!strcmp(name, "vmalloc_user_noprof")) return (unsigned long)reference_vmalloc_user;
#else
    if (!strcmp(name, "vmalloc_user")) return (unsigned long)reference_vmalloc_user;
#endif
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 11, 0)
    if (!strcmp(name, "__flush_icache_range")) return (unsigned long)reference_cache;
#else
    if (!strcmp(name, "caches_clean_inval_pou")) return (unsigned long)reference_cache;
#endif
    if (!strcmp(name, "set_memory_ro")) return (unsigned long)msu_native_set_memory_ro;
    if (!strcmp(name, "set_memory_rw")) return (unsigned long)msu_native_set_memory_rw;
    if (!strcmp(name, "set_memory_x")) return (unsigned long)msu_native_set_memory_x;
    if (!strcmp(name, "set_memory_nx")) return (unsigned long)msu_native_set_memory_nx;
#else
    for (i = 0; i < ARRAY_SIZE(sdk_symbols); ++i)
        if (!strcmp(name, sdk_symbols[i].name)) {
            if (!sdk_symbols[i].address && msu_init_bridge_resolve_cfi(name,
                    sdk_symbols[i].reference, &sdk_symbols[i].address)) return 0;
            return sdk_symbols[i].address;
        }
    if (!strcmp(name, "vmalloc") || !strcmp(name, "vmalloc_noprof")) reference = reference_vmalloc;
    if (!strcmp(name, "vmalloc_user") || !strcmp(name, "vmalloc_user_noprof")) reference = reference_vmalloc_user;
    if (!strcmp(name, "__vmalloc_node_range") || !strcmp(name, "__vmalloc_node_range_noprof")) reference = reference_vmalloc_range;
    if (!strcmp(name, "caches_clean_inval_pou") || !strcmp(name, "__flush_icache_range")) reference = reference_cache;
    if (reference)
        return msu_init_bridge_resolve_cfi(name, reference, &address) ? 0 : address;
    if (!strcmp(name, "set_memory_ro")) reference = msu_native_set_memory_ro;
    if (!strcmp(name, "set_memory_rw")) reference = msu_native_set_memory_rw;
    if (!strcmp(name, "set_memory_x")) reference = msu_native_set_memory_x;
    if (!strcmp(name, "set_memory_nx")) reference = msu_native_set_memory_nx;
    if (reference)
        return msu_init_bridge_resolve_cfi(name, reference, &address) ? 0 : address;
#endif
#if MSU_INIT_BRIDGE_CFI_LEGACY && defined(MODULE)
    if (!strcmp(name, "kallsyms_lookup_name"))
        return msu_init_bridge_resolve_cfi(name, (void *)msu_init_bridge_lookup,
            &address) ? 0 : address;
#endif
    /* These are address-only inputs. No unchecked native indirect call is
     * made through them here; environment ABI qualification stays separate. */
    if (!strcmp(name, "_text") || !strcmp(name, "kallsyms_lookup_name") ||
        !strcmp(name, "do_execveat_common") || !strcmp(name, "filldir64") ||
        !strcmp(name, "slow_avc_audit") || !strcmp(name, "avc_denied"))
        return msu_init_bridge_lookup(name);
    return 0;
}

unsigned long msu_init_bridge_observation_entry(const char *name)
{
    unsigned long address;
    if (!name || (strcmp(name, "__arm64_sys_execve") &&
        strcmp(name, "__vmalloc_node_range") && strcmp(name, "__vmalloc_node_range_noprof") &&
        strcmp(name, "___vmalloc_node_range") && strcmp(name, "___vmalloc_node_range_noprof"))) return 0;
    /* Only kprobe/identity observations consume this raw kernel entry. Callable
     * SDK imports always use the typed module-owned forwarding table above. */
    address = msu_init_bridge_lookup(name);
    return address && !(address & 3) ? address : 0;
}
