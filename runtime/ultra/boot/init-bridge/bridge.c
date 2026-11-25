// SPDX-License-Identifier: GPL-3.0-only
#include <linux/errno.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/pid.h>
#include <linux/sched.h>
#include <linux/string.h>
#include <linux/version.h>
#include "manager_dynamic_layout.h"
#if defined(MSU_INIT_BRIDGE_RUNTIME_FACTS) && MSU_INIT_BRIDGE_RUNTIME_FACTS
#include "manager_runtime_btf.h"
#include "manager_runtime_accessor.h"
#endif
#include "manager_resident_host.h"
#include "boot_events.h"
#include "preinit.h"
#include "native_imports.h"
#include "native_layout.h"
#include "native_lookup.h"
#include "native_sdk.h"

static char credential[49];
module_param_string(credential, credential, 49, 0);

static char deployment_namespace[17];
module_param_string(deployment_namespace, deployment_namespace, 17, 0);

static int bridge_first_error;
static bool host_attempted;

static int bridge_deployment_record(struct msu_deployment_namespace_record *record)
{
    memset(record, 0, sizeof(*record));
    if (!deployment_namespace[0]) return 0;
    if (strnlen(deployment_namespace, sizeof deployment_namespace) != MSU_DEPLOYMENT_NAMESPACE_BYTES)
        return -EINVAL;
    record->magic = MSU_DEPLOYMENT_NAMESPACE_MAGIC;
    record->schema = MSU_DEPLOYMENT_NAMESPACE_SCHEMA;
    record->bytes = sizeof(*record);
    memcpy(record->name, deployment_namespace, sizeof record->name);
    return msu_deployment_namespace_valid(record) ? 0 : -EINVAL;
}

int msu_init_bridge_host_start(unsigned long image, const void *append,
    unsigned int bytes, const char *credential)
{
    struct msu_deployment_namespace_record deployment;
    int error = bridge_deployment_record(&deployment);

    if (error) goto clear;
    host_attempted = true;
    /* The selected host synchronously retains its own record copy. */
    if (deployment_namespace[0]) {
        struct msu_resident_config_v2 config = {
            .version = 2, .config_bytes = sizeof(config), .append_bytes = bytes,
            .namespace_record_bytes = sizeof(deployment), .image = (void *)image,
            .append = append, .credential = credential, .namespace_record = &deployment,
        };

        error = msu_manager_resident_init((const struct msu_resident_config *)&config);
    } else {
        struct msu_resident_config config = {
            .version = 1, .append_bytes = bytes,
            .image = (void *)image, .append = append, .credential = credential,
        };

        error = msu_manager_resident_init(&config);
    }
clear:
    memzero_explicit(&deployment, sizeof deployment);
    return error;
}

int msu_init_bridge_host_abort(void)
{
    int error;

    if (!host_attempted) return 0;
    error = msu_manager_resident_discard();
    if (!error) host_attempted = false;
    return error;
}

static int __init msu_init_bridge_start(void)
{
    struct msu_boot_sdk_layout layout;
    struct msu_deployment_namespace_record deployment;
    unsigned int allocator_flags = 0;
#if __has_include(<linux/execmem.h>)
    unsigned int execmem_free = 1;
#else
    unsigned int execmem_free = 0;
#endif
    unsigned int n;
    int error, events_cleanup = 0, native_cleanup = 0;
    bool events_attempted = false, native_attempted = false;

#if !defined(MSU_INIT_BRIDGE_RUNTIME_FACTS) || !MSU_INIT_BRIDGE_RUNTIME_FACTS
    if (!msu_runtime_layout_ready()) { error = -EPROTO; goto clear; }
    if (READ_ONCE(MSU_DYN_FIELD(current, task_struct, pid)) != 1) { error = -EPERM; goto clear; }
#endif
    if (strnlen(credential, sizeof credential) != MSU_BOOT_SDK_KEY_BYTES) {
        error = -EINVAL;
        goto clear;
    }
    for (n = 0; n < MSU_BOOT_SDK_KEY_BYTES; ++n) {
        unsigned char c = credential[n];
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z'))) {
            error = -EINVAL;
            goto clear;
        }
    }
    error = bridge_deployment_record(&deployment);
    if (error) goto clear;
    error = msu_init_bridge_lookup_init();
    if (error) goto clear;
    error = msu_init_bridge_imports_init();
    if (error) goto clear;
#if defined(MSU_INIT_BRIDGE_RUNTIME_FACTS) && MSU_INIT_BRIDGE_RUNTIME_FACTS
    /* No relocated field is consumed until both producers publish complete
     * live layouts. The selected KMI module supplies code, never target offsets. */
    error = msu_runtime_btf_init(msu_init_bridge_lookup);
    if (error == -ENOENT) {
        error = msu_runtime_accessor_init(msu_init_bridge_lookup, msu_init_bridge_resolve_cfi);
        if (error) pr_err("MapleSU runtime native accessor initialization: %d\n", error);
    } else if (error) pr_err("MapleSU runtime BTF initialization: %d\n", error);
    if (error) goto clear;
    error = msu_runtime_layout_init(msu_runtime_facts_field);
    if (error) goto clear;
    error = msu_init_bridge_native_layout_init(msu_runtime_facts_field);
    if (error) goto clear;
    if (!msu_runtime_layout_ready()) { error = -EPROTO; goto clear; }
    if (READ_ONCE(MSU_DYN_FIELD(current, task_struct, pid)) != 1) { error = -EPERM; goto clear; }
#endif
    if (!msu_init_bridge_checked_lookup("vmalloc")) allocator_flags = MSU_BOOT_SDK_ALLOCATOR_NOPROF;
    if (!msu_init_bridge_checked_lookup("__vmalloc_node_range") &&
        !msu_init_bridge_checked_lookup("__vmalloc_node_range_noprof"))
        allocator_flags |= MSU_BOOT_SDK_ALLOCATOR_INNER | MSU_BOOT_SDK_ALLOCATOR_SEGMENTED;
    error = msu_init_bridge_native_layout(allocator_flags, execmem_free, &layout);
    if (error) goto clear;
    /* Preserve the native producer's environment facts in the SDK append.
     * Publishing those fields grants no helper or application authority. */
    if (deployment_namespace[0]) {
        events_attempted = true;
        error = msu_preinit_start();
        if (error) pr_warn("MapleSU preinit staging skipped: %d\n", error);
        /* Optional preinit staging failure must not block native SU/events. */
        error = msu_boot_events_start(&deployment);
        if (error) goto failed;
    }
    native_attempted = true;
    error = msu_boot_sdk_native_start(&layout, credential);
    memzero_explicit(credential, sizeof credential);
    memzero_explicit(deployment_namespace, sizeof deployment_namespace);
    if (error) goto failed;
    /* Same host's published callbacks and event proxy are boot-owned. */
    __module_get(THIS_MODULE);
    pr_info("MapleSU init bridge channel initialized; environment=%u\n", layout.environment);
    error = 0;
    goto clear;
failed:
    bridge_first_error = error;
    msu_preinit_release();
    if (events_attempted) events_cleanup = msu_boot_events_stop();
    if (native_attempted) native_cleanup = msu_boot_sdk_native_abort();
    if (events_cleanup || native_cleanup) {
        /* Every cleanup is consumed even if another retained live callbacks.
         * A failed init would free module text, so quarantine keeps its pin. */
        __module_get(THIS_MODULE);
        pr_err("MapleSU init bridge quarantined: first=%d events=%d sdk=%d; SDK not ready\n",
            error, events_cleanup, native_cleanup);
        error = 0;
    }
clear:
#if defined(MSU_INIT_BRIDGE_RUNTIME_FACTS) && MSU_INIT_BRIDGE_RUNTIME_FACTS
    /* A quarantined module retains its live facts with its callbacks. */
    if (error) msu_runtime_btf_release();
#endif
    memzero_explicit(&deployment, sizeof deployment);
    memzero_explicit(credential, sizeof credential);
    memzero_explicit(deployment_namespace, sizeof deployment_namespace);
    return error;
}

static void __exit msu_init_bridge_exit(void)
{
    /* A forced unload is outside the supported boot-live host contract. */
    WARN_ON_ONCE(host_attempted || bridge_first_error);
}

module_init(msu_init_bridge_start);
module_exit(msu_init_bridge_exit);
MODULE_LICENSE("GPL");
#if defined(MSU_INIT_BRIDGE_RUNTIME_FACTS) && MSU_INIT_BRIDGE_RUNTIME_FACTS
MODULE_INFO(maplesu_runtime_facts, "1");
#endif
MODULE_DESCRIPTION("MapleSU native init_boot SDK/owner-host bridge candidate");
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 13, 0)
MODULE_IMPORT_NS("VFS_internal_I_am_really_a_filesystem_and_am_NOT_a_driver");
MODULE_IMPORT_NS("ANDROID_GKI_VFS_internal_I_am_really_a_filesystem_and_am_NOT_a_driver");
#else
MODULE_IMPORT_NS(VFS_internal_I_am_really_a_filesystem_and_am_NOT_a_driver);
MODULE_IMPORT_NS(ANDROID_GKI_VFS_internal_I_am_really_a_filesystem_and_am_NOT_a_driver);
#endif
