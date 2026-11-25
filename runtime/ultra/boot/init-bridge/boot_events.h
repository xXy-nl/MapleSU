/* SPDX-License-Identifier: GPL-3.0-only */
#ifndef MAPLESU_INIT_BRIDGE_BOOT_EVENTS_H
#define MAPLESU_INIT_BRIDGE_BOOT_EVENTS_H
#include "manager_deployment_namespace.h"

struct msu_resident_slot;
/* The paired raw v3 constructor binds its INITIALIZING Image allocation.
 * Register before PID1 enters userspace, but publish proxy fops only after
 * matching READY. READY is permanently Image-owned, including callback tails;
 * failed startup never binds a file and synchronously unregisters on discard. */
int msu_boot_events_bind_boot_resident(const struct msu_resident_slot *slot,
    const void *memory, msu_loader_u64 allocation_bytes);

/* PID1/module-init caller only. The canonical image record selects the future
 * /data/<namespace>/init exec path; no installed helper or pre-mounted /data is
 * required to append init events. The path grants no helper/session authority.
 * The first native EOF reads the root-owned module-initrc snapshot from the
 * preferred metadata/maplesu directory and appends it after the helper actions.
 * Custom-rc errors retain their raw diagnostic and skip only custom actions.
 * Zero means only read-probe registration, never helper/SU/custom-rc readiness.
 * The bridge caller holds its module lifetime across start/stop; a raw caller
 * first binds the boot-owned Image allocation as described above. */
int msu_boot_events_start(const struct msu_deployment_namespace_record *deployment);

/* Unregister and synchronize the probe before examining the bound file.
 * -EBUSY retains all live proxy resources; no restore/free races an entered
 * or branch-before-enter reader. After close, call again from a pinned caller.
 * A zero return is cleanup completion, never an init-event success receipt. */
int msu_boot_events_stop(void);
#endif
