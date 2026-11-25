/* SPDX-License-Identifier: GPL-3.0-only */
#ifndef MAPLESU_INIT_BRIDGE_NATIVE_LAYOUT_H
#define MAPLESU_INIT_BRIDGE_NATIVE_LAYOUT_H

#include "boot_sdk_abi.h"

/* Target Kbuild facts only. The allocator variant must already be qualified by
 * the existing producer; zero is a real variant, not an unknown-value sentinel.
 * This does not initialize a host, register a service or grant credentials.
 * On failure, output is unchanged. Full environment support is mandatory. */
int msu_init_bridge_native_layout(unsigned int allocator_flags,
    unsigned int execmem_free, struct msu_boot_sdk_layout *output);
struct msu_runtime_btf_field;
int msu_init_bridge_native_layout_init(int (*query)(const char *, const char *,
    struct msu_runtime_btf_field *));

#define MSU_INIT_BRIDGE_RUNTIME_MAGIC 0x4d534942U
#define MSU_INIT_BRIDGE_RUNTIME_SCHEMA 1U
struct msu_init_bridge_runtime_layout {
    unsigned int magic, schema, bytes, ready;
    struct msu_boot_sdk_layout sdk;
};
extern struct msu_init_bridge_runtime_layout msu_init_bridge_runtime_layout;
extern const struct msu_boot_sdk_layout msu_init_bridge_compiled_layout;
#endif
