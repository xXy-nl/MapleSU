"""Narrow source/lookup fixtures; not target ABI, CFI or loading qualification.

The import fixture supplies int/size_t random declarations and mocks resolution;
only compiler-owned forwarding entries reach mocked native functions. Producer
checks preprocess real source with includes removed, not a complete kernel TU.
Run only through the central evidence executor after producer owner integration.
"""
import os
from pathlib import Path
import re
import subprocess
import tempfile
import unittest

BRIDGE = Path(__file__).resolve().parents[1]
AFTER = BRIDGE.parents[3]
PRODUCER = AFTER / "jailbreak-providers/root-loader/module/maplesu_boot_sdk.c"
CC = os.environ.get("BRIDGE_FIXTURE_CC", "C:/msys64/ucrt64/bin/gcc.exe")
INCLUDES = re.compile(r"^\s*#\s*include[^\n]*", re.MULTILINE)
DEFINITIONS = r"""
#include <assert.h>
#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#ifndef ESTALE
#define ESTALE 116
#endif
#include <string.h>
#define noinline __attribute__((noinline))
#define KERNEL_VERSION(a,b,c) (((a)<<16)|((b)<<8)|(c))
#define LINUX_VERSION_CODE KERNEL_VERSION(5,15,0)
#define __used __attribute__((used))
#define __user
#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))
typedef unsigned int gfp_t;
typedef struct { unsigned long pgprot; } pgprot_t;
struct cred; struct task_struct; struct pt_regs;
struct filename { const char *name; };
static unsigned int released_environment;
#if __has_include(<linux/execmem.h>)
static void msu_native_execmem_free(void *address) { (void)address; ++released_environment; }
#else
static void msu_native_module_memfree(void *address) { (void)address; ++released_environment; }
#endif
struct maplesu_legacy_hook_provider;
int maplesu_legacy_hook_provider_get(const struct maplesu_legacy_hook_provider **, void **);
void maplesu_legacy_hook_provider_put(void *);
void get_random_bytes(void *, RANDOM_LENGTH);
long copy_from_user_nofault(void *, const void *, size_t);
long copy_to_user_nofault(void *, const void *, size_t);
long copy_from_kernel_nofault(void *, const void *, size_t);
long copy_to_kernel_nofault(void *, const void *, size_t);
void *vmalloc(unsigned long);
void *__vmalloc_node_range(unsigned long, unsigned long, unsigned long,
    unsigned long, gfp_t, pgprot_t, unsigned long, int, const void *);
void vfree(const void *);
void caches_clean_inval_pou(unsigned long, unsigned long);
struct cred *prepare_creds(void);
int commit_creds(struct cred *);
const struct cred *get_task_cred(struct task_struct *);
void __put_cred(struct cred *);
#define MEMORY(name) int msu_native_##name(unsigned long a, int b) { return !!a + b; }
MEMORY(set_memory_ro)
MEMORY(set_memory_rw)
MEMORY(set_memory_x)
MEMORY(set_memory_nx)
static unsigned int checked_calls, address_calls;
static int resolver_error;
static const void *resolver_reject_reference, *resolver_last_reference;
static int msu_init_bridge_resolve_cfi(const char *name, const void *reference,
    unsigned long *address)
{
    assert(name && reference && address);
    ++checked_calls;
    resolver_last_reference = reference;
    if (resolver_error) return resolver_error;
    if (reference == resolver_reject_reference) return -EPERM;
    *address = 0x1000;
    return 0;
}
static unsigned long msu_init_bridge_lookup(const char *name)
{
    assert(name);
    ++address_calls;
    return 0x2000;
}
"""
CASES = r"""
int main(void)
{
    unsigned int filename = 99;
    assert(!msu_init_bridge_environment_filename(&filename) && filename == 0);
    assert(msu_init_bridge_environment_filename(NULL) == -EINVAL);
#if __has_include(<linux/execmem.h>)
    void (*release_environment)(const void *) = (void *)msu_init_bridge_checked_lookup("execmem_free");
    assert(release_environment && !msu_init_bridge_checked_lookup("module_memfree"));
#else
    void (*release_environment)(const void *) = (void *)msu_init_bridge_checked_lookup("module_memfree");
    assert(release_environment && !msu_init_bridge_checked_lookup("execmem_free"));
#endif
    release_environment(NULL); assert(released_environment == 1);
    assert(!msu_init_bridge_checked_lookup(NULL));
    assert(!msu_init_bridge_checked_lookup("get_random_bytes"));
    assert(!msu_init_bridge_checked_lookup("unknown"));
    assert(!checked_calls && !address_calls);
    assert(!strcmp(sdk_symbols[ARRAY_SIZE(sdk_symbols) - 2].name, "maplesu_legacy_hook_provider_get"));
    assert(!strcmp(sdk_symbols[ARRAY_SIZE(sdk_symbols) - 1].name, "maplesu_legacy_hook_provider_put"));
    for (unsigned int i = 0; i < ARRAY_SIZE(sdk_symbols); ++i) {
        unsigned int before = checked_calls;
        resolver_error = -EPERM;
        assert(!msu_init_bridge_checked_lookup(sdk_symbols[i].name));
        assert(checked_calls == before + 1 && !sdk_symbols[i].address);
        resolver_error = 0;
        assert(msu_init_bridge_checked_lookup(sdk_symbols[i].name) == 0x1000);
        assert(checked_calls == before + 2);
        assert(msu_init_bridge_checked_lookup(sdk_symbols[i].name) == 0x1000);
        assert(checked_calls == before + 2);
    }
    assert(msu_init_bridge_checked_lookup("vmalloc") == 0x1000);
    assert(msu_init_bridge_checked_lookup("set_memory_ro") == 0x1000);
    assert(msu_init_bridge_checked_lookup("_text") == 0x2000);
    assert(address_calls == 1);
    _Static_assert(__builtin_types_compatible_p(typeof(&reference_vmalloc_segmented_range),
        void *(*)(unsigned long,unsigned long,unsigned int,unsigned int,unsigned int,unsigned int,
            unsigned long,unsigned long,gfp_t,pgprot_t,unsigned long,int,const void *)), "segmented native ABI");
    resolver_error = -EPERM;
    assert(!msu_init_bridge_checked_lookup("___vmalloc_node_range"));
    resolver_error = 0;
    assert(msu_init_bridge_checked_lookup("___vmalloc_node_range") == 0x1000);
    assert(msu_init_bridge_checked_lookup("___vmalloc_node_range_noprof") == 0x1000);
    unsigned int before = checked_calls;
    resolver_reject_reference = reference_vmalloc_segmented_range;
    assert(msu_init_bridge_checked_lookup("___vmalloc_node_range") == 0x1000);
    assert(checked_calls == before + 2 && resolver_last_reference == reference_vmalloc_range);
    return 0;
}
"""


LEGACY_DEFINITIONS = r"""
#define MSU_INIT_BRIDGE_CFI_LEGACY 1
#define MODULE 1
#define MSU_MANAGEMENT_RESIDENT_TEXT_OWNER 1
static unsigned int direct_calls;
#define COPY(name) long msu_direct_target_##name(void *to, const void *from, size_t bytes) { (void)to; (void)from; (void)bytes; ++direct_calls; return 17; }
COPY(copy_from_user_nofault)
COPY(copy_to_user_nofault)
COPY(copy_from_kernel_nofault)
COPY(copy_to_kernel_nofault)
#undef COPY
void *msu_direct_target_vmalloc(unsigned long bytes) { (void)bytes; ++direct_calls; return (void *)0x3000; }
void *msu_direct_target_vmalloc_user(unsigned long bytes) { (void)bytes; ++direct_calls; return (void *)0x3100; }
void *msu_direct_target___vmalloc_node_range(unsigned long size, unsigned long align,
    unsigned long start, unsigned long end, gfp_t flags, pgprot_t prot,
    unsigned long vm_flags, int node, const void *caller)
{ (void)size; (void)align; (void)start; (void)end; (void)flags; (void)prot; (void)vm_flags; (void)node; (void)caller; ++direct_calls; return (void *)0x3200; }
void msu_direct_target_vfree(const void *address) { (void)address; ++direct_calls; }
void msu_direct_target_caches_clean_inval_pou(unsigned long start, unsigned long end) { (void)start; (void)end; ++direct_calls; }
struct cred *msu_direct_target_prepare_creds(void) { ++direct_calls; return (struct cred *)0x4000; }
int msu_direct_target_commit_creds(struct cred *cred) { (void)cred; ++direct_calls; return 0; }
const struct cred *msu_direct_target_get_task_cred(struct task_struct *task) { (void)task; ++direct_calls; return (struct cred *)0x4100; }
void msu_direct_target___put_cred(struct cred *cred) { (void)cred; ++direct_calls; }
long msu_direct_target___arm64_sys_execve(const struct pt_regs *regs) { (void)regs; ++direct_calls; return 19; }
int maplesu_legacy_hook_provider_get(const struct maplesu_legacy_hook_provider **provider, void **lease)
{ (void)provider; (void)lease; ++direct_calls; return -ENOENT; }
void maplesu_legacy_hook_provider_put(void *lease) { (void)lease; ++direct_calls; }
"""
LEGACY_CASES = r"""
int main(void)
{
    unsigned int filename = 99;
    assert(!msu_init_bridge_environment_filename(&filename) && filename == 0);
#if __has_include(<linux/execmem.h>)
    void (*release_environment)(const void *) = (void *)msu_init_bridge_checked_lookup("execmem_free");
    assert(release_environment && !msu_init_bridge_checked_lookup("module_memfree"));
#else
    void (*release_environment)(const void *) = (void *)msu_init_bridge_checked_lookup("module_memfree");
    assert(release_environment && !msu_init_bridge_checked_lookup("execmem_free"));
#endif
    release_environment(NULL); assert(released_environment == 1);
    assert(!msu_init_bridge_checked_lookup(NULL));
    assert(!msu_init_bridge_checked_lookup("unknown"));
    for (unsigned int i = 0; i < ARRAY_SIZE(sdk_symbols); ++i)
        assert(msu_init_bridge_checked_lookup(sdk_symbols[i].name) == (unsigned long)sdk_symbols[i].reference);
    assert(!checked_calls && !address_calls);
    long (*copy)(void *, const void *, size_t) = (void *)msu_init_bridge_checked_lookup("copy_from_kernel_nofault");
    long (*exec)(const struct pt_regs *) = (void *)msu_init_bridge_checked_lookup("__arm64_sys_execve");
    struct cred *(*prepare)(void) = (void *)msu_init_bridge_checked_lookup("prepare_creds");
    assert(copy(NULL,NULL,0) == 17 && exec(NULL) == 19 && prepare() == (void *)0x4000);
    assert(direct_calls == 3 && !checked_calls && !address_calls);
    assert(msu_init_bridge_checked_lookup("vmalloc") == (unsigned long)reference_vmalloc);
    assert(!msu_init_bridge_checked_lookup("vmalloc_noprof"));
    assert(msu_init_bridge_checked_lookup("caches_clean_inval_pou") == (unsigned long)reference_cache);
    assert(!msu_init_bridge_checked_lookup("__flush_icache_range"));
    assert(msu_init_bridge_observation_entry("__arm64_sys_execve") == 0x2000);
    assert(msu_init_bridge_observation_entry("__vmalloc_node_range") == 0x2000);
    assert(!msu_init_bridge_observation_entry("prepare_creds"));
    assert(!msu_init_bridge_observation_entry(NULL));
    assert(address_calls == 2 && !checked_calls);
    resolver_error = -ESTALE;
    assert(!msu_init_bridge_checked_lookup("kallsyms_lookup_name"));
    assert(checked_calls == 1);
    assert(!msu_init_bridge_checked_lookup("___vmalloc_node_range"));
    resolver_error = 0;
    assert(msu_init_bridge_checked_lookup("___vmalloc_node_range") == 0x1000);
    unsigned int before = checked_calls;
    resolver_reject_reference = reference_vmalloc_segmented_range;
    assert(msu_init_bridge_checked_lookup("___vmalloc_node_range") == 0x1000);
    assert(checked_calls == before + 2 && resolver_last_reference == reference_vmalloc_range);
    return 0;
}
"""


def host_fixture(text):
    # ARM64 is LP64; only the Windows host fixture needs pointer-width carriers.
    return text.replace("unsigned long", "uintptr_t") if os.name == "nt" else text


class SdkImportChecks(unittest.TestCase):
    def test_imports_without_random_binding_accept_both_declared_prototypes(self):
        original = (BRIDGE / "native_sdk_imports.c").read_bytes()
        source_text = INCLUDES.sub("", original.decode("utf-8"))
        for length, execmem in ((length, execmem) for length in ("int", "size_t") for execmem in (False, True)):
            with self.subTest(random_length=length, execmem=execmem), tempfile.TemporaryDirectory(
                    prefix="bridge-sdk-imports-") as directory:
                output = Path(directory)
                if execmem:
                    (output / "linux").mkdir()
                    (output / "linux/execmem.h").write_text("")
                source = output / "fixture.c"
                source.write_text(host_fixture(DEFINITIONS.replace("RANDOM_LENGTH", length)
                                  + source_text + CASES), encoding="utf-8")
                binary = output / "fixture.exe"
                # Match the prepared kernel's zero-filled trailing-field policy.
                subprocess.run([CC, "-std=gnu11", "-O2", "-Wall", "-Wextra",
                                "-Wno-missing-field-initializers", "-I", str(output),
                                "-Werror", "-UNDEBUG", str(source), "-o", str(binary)],
                               check=True, timeout=25)
                subprocess.run([str(binary)], check=True, timeout=5)
        self.assertEqual((BRIDGE / "native_sdk_imports.c").read_bytes(), original)

    def test_legacy_sdk_calls_module_typed_entries_and_separates_observation(self):
        original = (BRIDGE / "native_sdk_imports.c").read_bytes()
        source_text = INCLUDES.sub("", original.decode("utf-8"))
        for execmem in (False, True):
            with self.subTest(execmem=execmem), tempfile.TemporaryDirectory(prefix="bridge-sdk-direct-v2-") as directory:
                output = Path(directory)
                if execmem:
                    (output / "linux").mkdir()
                    (output / "linux/execmem.h").write_text("")
                source = output / "fixture.c"
                source.write_text(host_fixture(DEFINITIONS.replace("RANDOM_LENGTH", "int") + LEGACY_DEFINITIONS + source_text + LEGACY_CASES), encoding="utf-8")
                binary = output / "fixture.exe"
                subprocess.run([CC, "-std=gnu11", "-O2", "-Wall", "-Wextra", "-Werror", "-UNDEBUG",
                                "-Wno-missing-field-initializers", "-I", str(output), str(source), "-o", str(binary)], check=True, timeout=25)
                subprocess.run([str(binary)], check=True, timeout=5)
        self.assertEqual((BRIDGE / "native_sdk_imports.c").read_bytes(), original)

    def preprocess_producer(self, native):
        source = INCLUDES.sub("", PRODUCER.read_text(encoding="utf-8"))
        argv = [CC, "-E", "-P", "-Werror", "-x", "c", "-",
                "-DMSU_BS_STATIC_BOOTSTRAP=0", "-DMSU_BS_ENVIRONMENT=0",
                "-DMSU_INIT_BRIDGE_CFI_NONE=1"]
        if native:
            argv.append("-DMSU_BOOT_SDK_NATIVE=1")
        return subprocess.run(argv, input=source, text=True, capture_output=True,
                              check=True, timeout=10).stdout

    def test_native_producer_uses_installed_credential_without_random_dependency(self):
        source = self.preprocess_producer(True)
        self.assertNotRegex(source, r"\b(?:random_bytes|get_random_bytes)\b",
                            "producer owner must guard declaration, RESOLVE and required check")
        self.assertIn("root_key[n] = native_credential[n]", source)
        self.assertIn("msu_sdk_bind_key(root_key, delta)", source)
        self.assertIn("memcmp(original_root_key, native_credential, MSU_BOOT_SDK_KEY_BYTES)", source)

    def test_non_native_producer_keeps_random_generation_and_required_lookup(self):
        source = self.preprocess_producer(False)
        self.assertIn("random_bytes(random, sizeof random)", source)
        self.assertRegex(source, r'random_bytes\s*=\s*\(void\s*\*\)lookup_name\("get_random_bytes"\)')
        self.assertRegex(source, r"!\s*random_bytes\b")


if __name__ == "__main__":
    unittest.main()
