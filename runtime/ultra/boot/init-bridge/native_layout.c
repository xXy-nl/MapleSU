// SPDX-License-Identifier: GPL-3.0-only
#include <linux/cred.h>
#include <linux/compiler.h>
#include <linux/errno.h>
#include <linux/kprobes.h>
#include <linux/sched.h>
#include <linux/stddef.h>
#include <linux/printk.h>
#include <asm/page.h>
#include <asm/ptrace.h>
#include "native_layout.h"
#if defined(MSU_INIT_BRIDGE_RUNTIME_FACTS) && MSU_INIT_BRIDGE_RUNTIME_FACTS
#include <asm/sysreg.h>
#include "manager_runtime_btf.h"
#endif

#ifndef CONFIG_ARM64
#error "Ultra init bridge native facts require an actual ARM64 kernel target"
#endif

_Static_assert(sizeof(void *) == 8, "ARM64 kernel pointer width");
_Static_assert(sizeof(((struct task_struct *)0)->cred) == 8, "task cred pointer");
_Static_assert(sizeof(((struct cred *)0)->suid) == 4, "saved UID width");
_Static_assert(sizeof(((struct cred *)0)->securebits) == 4, "securebits width");
_Static_assert(sizeof(((struct kprobe *)0)->addr) == 8, "probe address width");
_Static_assert(sizeof(((struct kprobe *)0)->symbol_name) == 8, "probe name width");
_Static_assert(sizeof(((struct kprobe *)0)->pre_handler) == 8, "probe callback width");
_Static_assert(sizeof(((struct pt_regs *)0)->pc) == 8, "native PC width");
#ifdef CONFIG_SECCOMP
_Static_assert(sizeof(((struct task_struct *)0)->seccomp.mode) == 4, "seccomp mode width");
#endif

/* Keep the existing wire shape so the target object can be compared with BTF.
 * Allocator and release fields here are not qualified defaults: the function
 * below always replaces both with the producer's explicit variant selection. */
const struct msu_boot_sdk_layout msu_init_bridge_compiled_layout
    __attribute__((used, section(".msu.init_bridge.layout"))) = {
    .version = 1,
    .bytes = sizeof(struct msu_boot_sdk_layout),
    .page_bytes = PAGE_SIZE,
    .task_bytes = sizeof(struct task_struct),
    .cred_bytes = sizeof(struct cred),
    .task_cred = offsetof(struct task_struct, cred),
    .cred_suid = offsetof(struct cred, suid),
    .cred_securebits = offsetof(struct cred, securebits),
    .cred_usage = offsetof(struct cred, usage),
    .cred_usage_size = sizeof(((struct cred *)0)->usage),
    .kprobe_bytes = sizeof(struct kprobe),
    .kp_addr = offsetof(struct kprobe, addr),
    .kp_name = offsetof(struct kprobe, symbol_name),
    .kp_pre = offsetof(struct kprobe, pre_handler),
    .regs_pc = offsetof(struct pt_regs, pc),
    .environment = 1,
#ifdef CONFIG_SECCOMP
    .seccomp = offsetof(struct task_struct, seccomp.mode),
#endif
};

struct msu_init_bridge_runtime_layout msu_init_bridge_runtime_layout
    __attribute__((used, section(".msu.init_bridge.runtime_layout"))) = {
    .magic = MSU_INIT_BRIDGE_RUNTIME_MAGIC,
    .schema = MSU_INIT_BRIDGE_RUNTIME_SCHEMA,
    .bytes = sizeof(struct msu_init_bridge_runtime_layout),
    .ready = 0,
    .sdk = {
    .version = 1,
    .bytes = sizeof(struct msu_boot_sdk_layout),
    .page_bytes = PAGE_SIZE,
    .task_bytes = sizeof(struct task_struct),
    .cred_bytes = sizeof(struct cred),
    .task_cred = offsetof(struct task_struct, cred),
    .cred_suid = offsetof(struct cred, suid),
    .cred_securebits = offsetof(struct cred, securebits),
    .cred_usage = offsetof(struct cred, usage),
    .cred_usage_size = sizeof(((struct cred *)0)->usage),
    .kprobe_bytes = sizeof(struct kprobe),
    .kp_addr = offsetof(struct kprobe, addr),
    .kp_name = offsetof(struct kprobe, symbol_name),
    .kp_pre = offsetof(struct kprobe, pre_handler),
    .regs_pc = offsetof(struct pt_regs, pc),
    .environment = 1,
#ifdef CONFIG_SECCOMP
    .seccomp = offsetof(struct task_struct, seccomp.mode),
#endif
},
};

#if defined(MSU_INIT_BRIDGE_RUNTIME_FACTS) && MSU_INIT_BRIDGE_RUNTIME_FACTS
static int native_layout_field(int (*query)(const char *, const char *, struct msu_runtime_btf_field *),
    const char *owner, const char *member, u32 width, u32 *offset, u32 *owner_bytes)
{
    struct msu_runtime_btf_field field;
    int error = query(owner, member, &field);
    if (!error && (!field.bytes || (width && field.bytes != width) ||
        !field.owner_bytes || field.offset > field.owner_bytes ||
        field.bytes > field.owner_bytes - field.offset ||
        (*owner_bytes && *owner_bytes != field.owner_bytes))) error = -EOPNOTSUPP;
    if (error) {
        pr_err("MapleSU runtime SDK layout: %s.%s: %d\n", owner, member, error);
        return error;
    }
    *offset = field.offset; *owner_bytes = field.owner_bytes;
    return 0;
}

static int native_layout_object(int (*query)(const char *, const char *, struct msu_runtime_btf_field *),
    const char *owner, const char *member, u32 at, u32 width, u32 extent, u32 *offset, u32 *owner_bytes)
{
#ifdef MODULE
    /* Native API objects follow the selected DDK, as in pinned KernelSU.
     * Optional BTF is not a second ABI gate for module-owned objects. */
    (void)query; (void)owner; (void)member; (void)width;
    *offset = at; *owner_bytes = extent;
    return 0;
#else
    (void)at; (void)extent;
    return native_layout_field(query, owner, member, width, offset, owner_bytes);
#endif
}

int msu_init_bridge_native_layout_init(int (*query)(const char *, const char *,
    struct msu_runtime_btf_field *))
{
    struct msu_boot_sdk_layout next = { .version = 1, .bytes = sizeof(next), .environment = 1 };
    struct msu_runtime_btf_field usage;
    u32 regs_bytes = 0, page_code = read_sysreg(tcr_el1) >> 30 & 3;
    int error;

    WRITE_ONCE(msu_init_bridge_runtime_layout.ready, 0);
    if (!query) return -EINVAL;
    if (msu_init_bridge_runtime_layout.magic != MSU_INIT_BRIDGE_RUNTIME_MAGIC ||
        msu_init_bridge_runtime_layout.schema != MSU_INIT_BRIDGE_RUNTIME_SCHEMA ||
        msu_init_bridge_runtime_layout.bytes != sizeof(msu_init_bridge_runtime_layout)) return -EPROTO;
    next.page_bytes = page_code == 1 ? 16384 : page_code == 2 ? 4096 : page_code == 3 ? 65536 : 0;
    /* TG1 describes the actual TTBR1 kernel granule, not the container's
     * alignment or the component's configured page size. */
    if (next.page_bytes != PAGE_SIZE) return -EOPNOTSUPP;
#define FIELD(owner, member, width, key, size) do { \
    error = native_layout_field(query, owner, member, width, &next.key, &size); \
    if (error) return error; \
} while (0)
    FIELD("task_struct", "cred", 8, task_cred, next.task_bytes);
    FIELD("cred", "suid", 4, cred_suid, next.cred_bytes);
    FIELD("cred", "securebits", 4, cred_securebits, next.cred_bytes);
    error = query("cred", "usage", &usage);
    if (error || (usage.bytes != 4 && usage.bytes != 8)) {
        pr_err("MapleSU runtime SDK layout: cred.usage: %d\n", error ? error : -EOPNOTSUPP);
        return error ? error : -EOPNOTSUPP;
    }
    FIELD("cred", "usage", usage.bytes, cred_usage, next.cred_bytes);
    next.cred_usage_size = usage.bytes;
#define NATIVE_FIELD(owner, member, key, size) do { \
    error = native_layout_object(query, #owner, #member, offsetof(struct owner, member), \
        sizeof(((struct owner *)0)->member), sizeof(struct owner), &next.key, &size); \
    if (error) return error; \
} while (0)
    NATIVE_FIELD(kprobe, addr, kp_addr, next.kprobe_bytes);
    NATIVE_FIELD(kprobe, symbol_name, kp_name, next.kprobe_bytes);
    NATIVE_FIELD(kprobe, pre_handler, kp_pre, next.kprobe_bytes);
    NATIVE_FIELD(pt_regs, pc, regs_pc, regs_bytes);
#undef NATIVE_FIELD
#ifdef CONFIG_SECCOMP
    FIELD("task_struct", "seccomp.mode", 4, seccomp, next.task_bytes);
#endif
#undef FIELD
    if (!msu_boot_sdk_layout_valid(&next, PAGE_SIZE)) return -EOPNOTSUPP;
    msu_init_bridge_runtime_layout.sdk = next;
    smp_store_release(&msu_init_bridge_runtime_layout.ready, 1);
    return 0;
}
#endif

int msu_init_bridge_native_layout(unsigned int allocator_flags,
    unsigned int execmem_free, struct msu_boot_sdk_layout *output)
{
    struct msu_boot_sdk_layout layout = msu_init_bridge_compiled_layout;
    unsigned int ready = smp_load_acquire(&msu_init_bridge_runtime_layout.ready);

    if (!output) return -EINVAL;
#if defined(MSU_INIT_BRIDGE_RUNTIME_FACTS) && MSU_INIT_BRIDGE_RUNTIME_FACTS
    if (ready != 1) return -EAGAIN;
#endif
    if (ready) {
        if (msu_init_bridge_runtime_layout.ready != 1 ||
            msu_init_bridge_runtime_layout.magic != MSU_INIT_BRIDGE_RUNTIME_MAGIC ||
            msu_init_bridge_runtime_layout.schema != MSU_INIT_BRIDGE_RUNTIME_SCHEMA ||
            msu_init_bridge_runtime_layout.bytes != sizeof(msu_init_bridge_runtime_layout))
            return -EPROTO;
        layout = msu_init_bridge_runtime_layout.sdk;
    }
    layout.allocator_noprof = allocator_flags;
    layout.execmem_free = execmem_free;
    /* The shared producer still requires its exact legacy saved-ID window.
     * An incompatible target stays unsupported; no offsets are inferred. */
    if (!msu_boot_sdk_layout_valid(&layout, PAGE_SIZE)) return -EOPNOTSUPP;
    *output = layout;
    return 0;
}
