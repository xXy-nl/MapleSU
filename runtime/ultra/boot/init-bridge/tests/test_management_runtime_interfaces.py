"""Execute production management branches with user-access and task-state seams.

Only unsigned-long pointer carriers are translated to uintptr_t for Windows
LLP64. This is host evidence, not a target uaccess or scheduler qualification.
"""
import os
from pathlib import Path
import re
import subprocess
import tempfile
import unittest

import test_stage

ROOT = Path(__file__).resolve().parents[5]
SOURCE = ROOT / "runtime/ultra/identity/kernel/manager_management.c"
CC = os.environ.get("BRIDGE_FIXTURE_CC", "C:/msys64/ucrt64/bin/gcc.exe")


def function(text, signature):
    start = text.index(signature)
    brace = text.index("{", start)
    depth, end = 1, brace + 1
    while depth:
        depth += (text[end] == "{") - (text[end] == "}")
        end += 1
    return text[start:end]


def run_c(source):
    with tempfile.TemporaryDirectory(prefix="bridge-management-interface-") as directory:
        path = Path(directory) / "fixture.c"
        binary = Path(directory) / "fixture.exe"
        path.write_text(source.replace("unsigned long", "uintptr_t"), encoding="utf-8")
        subprocess.run([CC, "-std=gnu11", "-O1", "-Wall", "-Wextra", "-Werror",
                        str(path), "-o", str(binary)], check=True, timeout=20)
        subprocess.run([str(binary)], check=True, timeout=5)


COMMON = r"""
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
typedef uint64_t u64; typedef uint32_t u32;
#ifndef ESTALE
#define ESTALE 116
#endif
#define __user
#define CONFIG_ARM64 1
#define untagged_addr(x) ((uintptr_t)((int64_t)((uint64_t)(x) << 8) >> 8))
#define CHECK(x) do { if (!(x)) { fprintf(stderr, "management line %d: %s\n", __LINE__, #x); return 1; } } while (0)
"""

USER_FIXTURE = r"""
#define MAPLESU_MANAGEMENT_WRITE_TEXT 1
#define MAPLESU_EFFECT_WRITTEN 1
#define ALIGN(x, a) (((x) + (a) - 1) & ~((a) - 1))
#define raw_spin_lock_irqsave(lock, flags) ((void)(lock), (flags) = 0)
#define raw_spin_unlock_irqrestore(lock, flags) ((void)(lock), (void)(flags))
#define mutex_lock(lock) ((void)(lock))
#define mutex_unlock(lock) ((void)(lock))
int msu_management_lock, text_mutex;
struct msu_management_session { int unused; };
struct publication { void *service; };
struct msu_management_resource { struct publication *publication; u64 uploaded, bytes; void *address; };
typedef struct { u64 handle, address, data_user; u32 flags, length; } maplesu_management_v3;
typedef struct { u64 result; u32 metadata_length; } maplesu_response_owner_v3;
static unsigned char input[] = { 1, 2, 3, 4 }, output[4];
static const uintptr_t user_address = 0x1234000;
static struct msu_management_resource resource = { NULL, 0, sizeof(output), output };
static int validate_error;
static struct msu_management_resource *msu_management_resource(struct msu_management_session *session, u64 handle)
{ (void)session; return handle == 1 ? &resource : NULL; }
static int msu_management_check(struct msu_management_session *session)
{ (void)session; return validate_error; }
static int msu_management_protected(u64 address, u32 bytes)
{ (void)address; (void)bytes; return 0; }
static void *vmalloc(size_t bytes) { return malloc(bytes); }
static void vfree(void *value) { free(value); }
static int copy_from_user_nofault(void *to, const void *from, size_t bytes)
{
    if ((uintptr_t)from != user_address || bytes > sizeof(input)) return -EFAULT;
    memcpy(to, input, bytes); return 0;
}
static int copy_to_kernel_nofault(void *to, const void *from, size_t bytes)
{ (void)to; (void)from; (void)bytes; return -EFAULT; }
static int msu_management_write_text(struct msu_management_session *session,
    const maplesu_management_v3 *operation, u32 *instructions, maplesu_response_owner_v3 *response)
{ (void)session; (void)operation; (void)instructions; (void)response; return -EOPNOTSUPP; }
"""

USER_CASES = r"""
int main(void)
{
    struct msu_management_session session = {0};
    maplesu_management_v3 op = { .handle = 1, .data_user = user_address, .length = sizeof(input) };
    maplesu_response_owner_v3 response = {0};
    const u64 tags[] = { 0, 0xab, 0xff, 1 };
    for (unsigned int i = 0; i < sizeof(tags) / sizeof(tags[0]); ++i) {
        op.data_user = user_address | tags[i] << 56;
        memset(output, 0, sizeof(output)); response = (maplesu_response_owner_v3){0};
        CHECK(msu_management_user_range(op.data_user, op.length));
        CHECK(msu_management_write(&session, &op, &response) == 0);
        CHECK(!memcmp(output, input, sizeof(input)) && response.result == sizeof(input));
        CHECK(response.metadata_length == MAPLESU_EFFECT_WRITTEN);
    }
    CHECK(!msu_management_user_range(0xab00000000000000ULL, 1));
    CHECK(!msu_management_user_range(0xffff000000001000ULL, 1));
    CHECK(!msu_management_user_range(user_address, 0));
    op.data_user = user_address + 1; response = (maplesu_response_owner_v3){0};
    CHECK(msu_management_write(&session, &op, &response) == -EFAULT && !response.result && !response.metadata_length);
    op.data_user = user_address | 0xab00000000000000ULL; validate_error = -ESTALE;
    CHECK(msu_management_write(&session, &op, &response) == -ESTALE && !response.result && !response.metadata_length);
    return 0;
}
"""

READ_FIXTURE = r"""
#define MSU_DEPLOYMENT_NAMESPACE_MAGIC 42
#define MAPLESU_DEPLOYMENT_NAMESPACE_MAGIC 42
#define MSU_DEPLOYMENT_NAMESPACE_SCHEMA 1
#define MAPLESU_DEPLOYMENT_NAMESPACE_SCHEMA 1
#define MSU_DEPLOYMENT_NAMESPACE_BYTES 4
struct msu_deployment_namespace_record { u32 magic, schema, bytes; char name[4]; };
typedef struct { u32 magic, schema, bytes; char name[4]; } maplesu_deployment_namespace_v3;
typedef struct { u64 data_user; } maplesu_management_v3;
typedef struct { u64 result; } maplesu_response_owner_v3;
static maplesu_deployment_namespace_v3 received;
static int producer_error;
static int msu_manager_resident_deployment(struct msu_deployment_namespace_record *out)
{
    if (producer_error) return producer_error;
    *out = (struct msu_deployment_namespace_record){42, 1, sizeof(*out), "abc"};
    return 0;
}
static bool msu_deployment_namespace_valid(const struct msu_deployment_namespace_record *value)
{ return value->magic == 42 && value->schema == 1; }
static int copy_to_user_nofault(void *to, const void *from, size_t bytes)
{
    if ((uintptr_t)to != 0x1234000 || bytes != sizeof(received)) return -EFAULT;
    memcpy(&received, from, bytes); return 0;
}
"""

READ_CASES = r"""
int main(void)
{
    maplesu_management_v3 op = { .data_user = 0xab00000001234000ULL };
    maplesu_response_owner_v3 response = {0};
    CHECK(msu_management_deployment(&op, &response) == 0);
    CHECK(response.result == sizeof(received) && received.magic == 42 && !strcmp(received.name, "abc"));
    response.result = 0; op.data_user++;
    CHECK(msu_management_deployment(&op, &response) == -EFAULT && !response.result);
    producer_error = -EIO;
    CHECK(msu_management_deployment(&op, &response) == -EIO && !response.result);
    return 0;
}
"""

TASK_FIXTURE = r"""
#define MAPLESU_MANAGEMENT_CAPABILITIES 1ULL
#define MAPLESU_CAP_TEXT_WRITE 2ULL
#define MAPLESU_CAP_SHARED_BOOL 4ULL
#define MAPLESU_CAP_UID_SNAPSHOT 8ULL
#define MAPLESU_CAP_TASK_STATE 16ULL
#define MAPLESU_CAP_PROCATTR 32ULL
#define MAPLESU_CAP_CODE_RESERVE 64ULL
#define MAPLESU_CAP_PUBLICATION 128ULL
#define MAPLESU_REQUEST_TASK_STATE 7
struct msu_management_session { int live; };
typedef struct { u32 metadata_length; u64 result; } response_type;
static int calls, validator_calls, producer_error;
static bool msu_management_code_available(void) { return true; }
static __attribute__((unused)) int msu_management_validate_credentials(void *context)
{ struct msu_management_session *s = context; ++validator_calls; return s->live ? 0 : -ESTALE; }
static __attribute__((unused)) int msu_task_state_release_current(int (*validate)(void *), void *context, u32 *effects, u64 *previous)
{
    ++calls; int error = validate(context); if (error) return error;
    *effects = 3; *previous = 2; return producer_error;
}
"""

TASK_CASES = r"""
int main(void)
{
    struct msu_management_session session = { .live = 1 };
    response_type response = {0};
    CHECK(msu_management_capabilities() & MAPLESU_CAP_TASK_STATE);
    CHECK(dispatch(MAPLESU_REQUEST_TASK_STATE, &session, &response) == 0);
    CHECK(calls == 1 && validator_calls == 1 && response.metadata_length == 3 && response.result == 2);
    producer_error = -EIO;
    CHECK(dispatch(MAPLESU_REQUEST_TASK_STATE, &session, &response) == -EIO && calls == 2);
    session.live = 0; response = (response_type){0};
    CHECK(dispatch(MAPLESU_REQUEST_TASK_STATE, &session, &response) == -ESTALE && calls == 3);
    CHECK(!response.metadata_length && !response.result);
    return 0;
}
"""


class ManagementRuntimeInterfaceChecks(unittest.TestCase):
    def test_tagged_write_reaches_real_write_branch_and_keeps_errors(self):
        source = SOURCE.read_text(encoding="utf-8")
        helper = function(source, "static void __user *msu_management_user_pointer(") if "static void __user *msu_management_user_pointer(" in source else ""
        run_c(COMMON + USER_FIXTURE + helper + function(source, "static bool msu_management_user_range(") +
              function(source, "static int msu_management_write(") + USER_CASES)

    def test_every_protocol_user_pointer_uses_canonical_user_access(self):
        source = SOURCE.read_text(encoding="utf-8")
        direct = re.search(r"\([^\n;]*__user\s*\*\)\s*\(unsigned long\)\s*(?:operation|descriptor)(?:->|\.)", source)
        self.assertIsNone(direct, "protocol user pointer bypasses canonical user access")
        for member in ("operation->data_user", "descriptor.members_user", "descriptor.destination_user"):
            self.assertIn("msu_management_user_pointer(" + member + ")", source)

    def test_tagged_readback_reaches_real_copy_to_user_branch(self):
        source = SOURCE.read_text(encoding="utf-8")
        helper = function(source, "static void __user *msu_management_user_pointer(") if "static void __user *msu_management_user_pointer(" in source else ""
        run_c(COMMON + READ_FIXTURE + helper + function(source, "static int msu_management_deployment(") + READ_CASES)

    def test_real_stage_enables_task_state_capability_and_dispatch(self):
        case = test_stage.StageChecks(); case.setUp()
        receipt = case.run_stage()
        self.assertIn("host/manager_task_state.o", receipt["selectedCoreDependencyObjects"])
        config = case.files[case.output / "host/msu_resolver_build_config.h"].decode()
        source = SOURCE.read_text(encoding="utf-8")
        start = source.index("    case MAPLESU_REQUEST_TASK_STATE:", source.index("void msu_management_dispatch("))
        end = source.index("    case MAPLESU_REQUEST_PUBLICATION_PREPARE:", start)
        branch = source[start:end]
        wrapper = "static int dispatch(int command, struct msu_management_session *session, response_type *response) { int error = -EINVAL; (void)session; (void)response; switch (command) {\n" + branch + "} return error; }\n"
        run_c(COMMON + config + TASK_FIXTURE + function(source, "u64 msu_management_capabilities(") + wrapper + TASK_CASES)

    def test_publication_capability_tracks_native_backend_not_review_flag(self):
        source = SOURCE.read_text(encoding="utf-8")
        for native, rcu in ((1, 1), (1, 0), (0, 1)):
            with self.subTest(native=native, rcu=rcu):
                config = "#define MSU_MANAGEMENT_PUBLICATION_GATE_VERIFIED 0\n"
                if native:
                    config += "#define MSU_MANAGEMENT_NATIVE_TEXT_OWNER 1\n"
                if rcu:
                    config += "#define CONFIG_TASKS_RCU 1\n"
                cases = "int main(void) { CHECK(!!(msu_management_capabilities() & MAPLESU_CAP_PUBLICATION) == " + str(native and rcu) + "); return 0; }\n"
                run_c(COMMON + config + TASK_FIXTURE + function(source, "u64 msu_management_capabilities(") + cases)


if __name__ == "__main__":
    unittest.main()
