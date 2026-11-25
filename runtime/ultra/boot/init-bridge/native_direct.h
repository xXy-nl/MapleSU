/* SPDX-License-Identifier: GPL-3.0-only */
#ifndef MAPLESU_INIT_BRIDGE_NATIVE_DIRECT_H
#define MAPLESU_INIT_BRIDGE_NATIVE_DIRECT_H
#include "native_cfi.h"
#if MSU_INIT_BRIDGE_CFI_LEGACY && defined(MODULE)
/* Included before kernel headers so their real inline helpers retain exact
 * native semantics and emit a direct relocation to the declared target. */
#define __put_cred msu_direct_target___put_cred
#define cancel_work msu_direct_target_cancel_work
#define prepare_creds msu_direct_target_prepare_creds
#define override_creds msu_direct_target_override_creds
#define revert_creds msu_direct_target_revert_creds
#define path_get msu_direct_target_path_get
#define iterate_dir msu_direct_target_iterate_dir
#define fsnotify_alloc_group msu_direct_target_fsnotify_alloc_group
#define fsnotify_init_mark msu_direct_target_fsnotify_init_mark
#define fsnotify_add_mark msu_direct_target_fsnotify_add_mark
#define fsnotify_destroy_mark msu_direct_target_fsnotify_destroy_mark
#define fsnotify_put_group msu_direct_target_fsnotify_put_group
#define fsnotify_put_mark msu_direct_target_fsnotify_put_mark
#define fortify_panic msu_direct_target_fortify_panic
#endif
#endif
