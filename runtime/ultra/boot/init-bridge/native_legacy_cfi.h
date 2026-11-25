/* SPDX-License-Identifier: GPL-3.0-only */
#ifndef MAPLESU_INIT_BRIDGE_NATIVE_LEGACY_CFI_H
#define MAPLESU_INIT_BRIDGE_NATIVE_LEGACY_CFI_H
#include <linux/kallsyms.h>

/* Only the actual Kbuild module path owns this contract. A copied raw payload
 * cannot acquire ownership by filling a module pointer or publishing shadow. */
/* Loader lifecycle/context only; native compiler checks remain at calls. */
int msu_legacy_module_ready(void);
bool msu_legacy_module_text(const void *first, unsigned long bytes);
bool msu_legacy_probe_matches(unsigned long canonical, unsigned long probed);
int msu_legacy_bootstrap_lookup(typeof(&kallsyms_lookup_name) *result);
int msu_legacy_resolve_entry(typeof(&kallsyms_lookup_name) lookup,
    const char *name, unsigned long *result);
#endif
