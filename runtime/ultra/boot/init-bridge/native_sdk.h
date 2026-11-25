/* SPDX-License-Identifier: GPL-3.0-only */
#ifndef MAPLESU_INIT_BRIDGE_NATIVE_SDK_H
#define MAPLESU_INIT_BRIDGE_NATIVE_SDK_H
#include <linux/cred.h>
#include <linux/kprobes.h>
#include <linux/sched.h>
#include <linux/uaccess.h>
#include <linux/vmalloc.h>
#include "native_cfi.h"
#include "boot_sdk_abi.h"

/* Same producer state machine; these kernel-only entries take real kernel
 * values, not prctl user pointers and not an L3 control subject. */
int msu_boot_sdk_native_start(const struct msu_boot_sdk_layout *layout,
    const char credential[MSU_BOOT_SDK_KEY_BYTES]);
int msu_boot_sdk_native_abort(void);
int msu_init_bridge_host_start(unsigned long image, const void *append,
    unsigned int bytes, const char *credential);
int msu_init_bridge_host_abort(void);
unsigned long msu_init_bridge_checked_lookup(const char *name);
unsigned long msu_init_bridge_observation_entry(const char *name);
int msu_init_bridge_environment_filename(unsigned int *offset);

static inline int msu_sdk_native_register(void *probe)
{
    return register_kprobe((struct kprobe *)probe);
}
static inline void msu_sdk_native_unregister(void *probe)
{
    unregister_kprobe((struct kprobe *)probe);
}
#endif
