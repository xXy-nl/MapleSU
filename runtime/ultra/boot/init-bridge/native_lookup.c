// SPDX-License-Identifier: GPL-3.0-only
#include <linux/compiler.h>
#include <linux/errno.h>
#include <linux/irqflags.h>
#include <linux/kallsyms.h>
#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/preempt.h>
#include <linux/uaccess.h>
#include "native_cfi.h"
#include "native_lookup.h"
#if MSU_INIT_BRIDGE_CFI_LEGACY && defined(MODULE)
#include "native_legacy_cfi.h"
#endif

#ifndef CONFIG_ARM64
#error "Ultra init bridge native lookup requires ARM64"
#endif

#if MSU_INIT_BRIDGE_CFI_KCFI
/* ARM64 KCFI places the compiler's type word immediately before its entry.
 * Read the actual word without depending on newer cfi.h helper declarations;
 * indirect calls below retain the compiler's normal KCFI checks. */
static u32 msu_native_cfi_hash(const void *function)
{
    unsigned long entry = (unsigned long)function;
    u32 hash;

    if (entry < sizeof(hash) || (entry & 3) ||
        copy_from_kernel_nofault(&hash, (const void *)(entry - sizeof(hash)), sizeof(hash)))
        return 0;
    return hash;
}
#endif

static typeof(&kallsyms_lookup_name) native_lookup;
_Static_assert(__builtin_types_compatible_p(typeof(&msu_init_bridge_lookup),
    typeof(&kallsyms_lookup_name)), "target kallsyms lookup prototype");

/* This real forwarding function also supplies the compiler's own CFI hash for
 * exactly the native lookup prototype. No separately computed type ID is used. */
noinline unsigned long msu_init_bridge_lookup(const char *name)
{
    typeof(native_lookup) lookup = READ_ONCE(native_lookup);

    return lookup && name ? lookup(name) : 0;
}

int msu_init_bridge_resolve_cfi(const char *name, const void *prototype,
    unsigned long *address)
{
#if !MSU_INIT_BRIDGE_CFI_LEGACY
    unsigned long found;
#if MSU_INIT_BRIDGE_CFI_KCFI
    unsigned int expected;
#endif
#endif

    if (!name || !prototype || !address) return -EINVAL;
#if MSU_INIT_BRIDGE_CFI_LEGACY
#if defined(MODULE)
    /* Canonical identity is established here. Each actual typed import call
     * retains compiler-generated legacy CFI; a void* prototype is no type ID. */
    if (!msu_legacy_module_text(prototype, sizeof(u32))) return -ESTALE;
    return msu_legacy_resolve_entry(READ_ONCE(native_lookup), name, address);
#else
    return -EOPNOTSUPP;
#endif
#else
    if (!READ_ONCE(native_lookup)) return -EAGAIN;
    found = msu_init_bridge_lookup(name);
#if MSU_INIT_BRIDGE_CFI_KCFI
    expected = msu_native_cfi_hash((void *)prototype);
    if (!expected || !found || msu_native_cfi_hash((void *)found) != expected)
        return -EOPNOTSUPP;
#else
    if (!found || (found & 3)) return -EOPNOTSUPP;
#endif
    *address = found;
    return 0;
#endif
}

static noinline int native_size_prototype(unsigned long address,
    unsigned long *bytes, unsigned long *offset)
{
    (void)address; (void)bytes; (void)offset;
    return 0;
}
_Static_assert(__builtin_types_compatible_p(typeof(&native_size_prototype),
    typeof(&kallsyms_lookup_size_offset)), "target symbol size prototype");

int msu_init_bridge_lookup_size(const char *name, unsigned long *address,
    unsigned long *bytes)
{
    typeof(&kallsyms_lookup_size_offset) size_of;
    unsigned long entry, function, size = 0, offset = 0;
    int error;

    if (!name || !*name || !address || !bytes) return -EINVAL;
    entry = msu_init_bridge_lookup(name);
    if (!entry) return -ENOENT;
    error = msu_init_bridge_resolve_cfi("kallsyms_lookup_size_offset",
        (void *)native_size_prototype, &function);
    if (error) return error;
    size_of = (typeof(size_of))function;
    if (!size_of(entry, &size, &offset) || offset || !size || size > ~0UL - entry)
        return -EOPNOTSUPP;
    *address = entry; *bytes = size;
    return 0;
}

#if MSU_INIT_BRIDGE_CFI_NONE
static unsigned long native_symbol_entry(unsigned long address)
{
    char symbol[KSYM_SYMBOL_LEN], trailing;
    unsigned long offset, size;
    unsigned int instruction;

    /* Use the normal exported formatter before the first private call. Its
     * real symbol offset distinguishes entry from a kprobe that skipped BTI. */
    if (sprint_symbol(symbol, address) <= 0 ||
        sscanf(symbol, "kallsyms_lookup_name+%lx/%lx%c", &offset, &size, &trailing) != 2 ||
        size <= offset || (offset != 0 && offset != 4) || address < offset)
        return 0;
    if (offset && (copy_from_kernel_nofault(&instruction,
            (void *)(address - offset), sizeof(instruction)) || instruction != 0xd503245f))
        return 0;
    return address - offset;
}
#endif

int msu_init_bridge_lookup_init(void)
{
#if MSU_INIT_BRIDGE_CFI_LEGACY
#if defined(MODULE)
    typeof(native_lookup) lookup;
    int error;

    if (READ_ONCE(native_lookup)) return -EALREADY;
    error = msu_legacy_bootstrap_lookup(&lookup);
    if (error) return error;
    WRITE_ONCE(native_lookup, lookup);
    return 0;
#else
    /* Raw copied payloads retain their real missing-owner failure. */
    return -EOPNOTSUPP;
#endif
#else
    struct kprobe probe = { .symbol_name = "kallsyms_lookup_name" };
    unsigned long address, entry = 0;
    typeof(native_lookup) lookup;
#if MSU_INIT_BRIDGE_CFI_KCFI
    unsigned int expected, instruction;
#endif
    int error;

    if (!in_task() || in_atomic() || irqs_disabled()) return -EWOULDBLOCK;
    if (READ_ONCE(native_lookup)) return -EALREADY;
#if MSU_INIT_BRIDGE_CFI_KCFI
    expected = msu_native_cfi_hash((void *)msu_init_bridge_lookup);
    if (!expected) return -EOPNOTSUPP;
#endif
    error = register_kprobe(&probe);
    if (error) return error;
    address = (unsigned long)probe.addr;
    unregister_kprobe(&probe);
    if (!address || (address & 3)) return -EOPNOTSUPP;
#if MSU_INIT_BRIDGE_CFI_KCFI
    /* Reads follow unregister, after the native instruction is restored. */
    if (msu_native_cfi_hash((void *)address) == expected) entry = address;
    if (address >= 4 && !copy_from_kernel_nofault(&instruction,
            (void *)(address - 4), sizeof(instruction)) && instruction == 0xd503245f &&
        msu_native_cfi_hash((void *)(address - 4)) == expected) {
        if (entry) return -EOPNOTSUPP;
        entry = address - 4;
    }
#else
    entry = native_symbol_entry(address);
#endif
    if (!entry) return -EOPNOTSUPP;
    lookup = (typeof(native_lookup))entry;
    /* KCFI retains the real compiler check; no-CFI retains the target ABI. */
    if (lookup("kallsyms_lookup_name") != entry) return -EOPNOTSUPP;
    WRITE_ONCE(native_lookup, lookup);
    return 0;
#endif
}
