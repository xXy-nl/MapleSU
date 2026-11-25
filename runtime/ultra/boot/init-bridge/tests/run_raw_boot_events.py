#!/usr/bin/env python3
"""Focused production producer/host lifecycle and real helper dispatch fixture.

Kernel/VFS/runtime boundaries are recorded mocks. Host init/discard bodies and
boot_events.c are compiled without edits. This does not execute Android init.
"""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
BRIDGE = HERE.parent
IMAGE = 'sha256:272ada1e61c525116032246df2a790d1ccec1804b7a9e0b09203c5e650dcb78e'

HOST_BOUNDARIES = r'''
#include "request_protocol.h"
#include "manager_claim_entry.h"
struct msu_manager_owner { int value; };
static bool msu_resident_raw_targets_bound, msu_resident_boot_events_stopped;
static DEFINE_MUTEX(msu_resident_discard_mutex);
static unsigned int msu_resident_discard_stage;
static int fault_stage, discard_failure, discard_calls;
static int msu_resident_retirement_prepare(const struct msu_resident_config_v3 *config) {
    (void)config; return fault_stage == 10 ? -ENOMEM : 0;
}
static int mutex_trylock(struct mutex *lock) {
    if (lock->held) return 0; lock->held = 1; return 1;
}
static int msu_manager_owner_init(struct msu_manager_owner *owner) {
    (void)owner; return fault_stage == 1 ? -EIO : 0;
}
static void get_random_bytes(void *out, size_t bytes) { memset(out, fault_stage == 2 ? 0 : 1, bytes); }
static int msu_management_init(struct msu_manager_owner *owner, const maplesu_host_instance *instance) {
    (void)owner; (void)instance; return fault_stage == 3 ? -EIO : 0;
}
static u32 msu_management_capabilities(void) { return 0; }
static int msu_su_nonroot_work_bind_boot_resident(const struct msu_resident_slot *slot, const void *memory, u64 bytes) {
    (void)slot; (void)memory; (void)bytes; return fault_stage == 11 ? -EIO : 0;
}
static int msu_su_exec_session_bind_boot_resident(const struct msu_resident_slot *slot, const void *memory, u64 bytes) {
    (void)slot; (void)memory; (void)bytes; return fault_stage == 12 ? -EIO : 0;
}
static int __attribute__((unused)) msu_ksu_compat_bind_boot_resident(const struct msu_resident_slot *slot, const void *memory, u64 bytes) {
    (void)slot; (void)memory; (void)bytes; return fault_stage == 13 ? -EIO : 0;
}
static int msu_init_bridge_lookup_init(void) { return fault_stage == 4 ? -EIO : 0; }
static unsigned long msu_init_bridge_lookup(const char *name) { (void)name; return 1; }
static int msu_init_bridge_resolve_cfi(const char *name, const void *prototype, unsigned long *address) {
    (void)name; (void)prototype; *address = 1; return 0;
}
static int msu_su_runtime_target_bind(unsigned long (*lookup)(const char *),
    int (*cfi)(const char *, const void *, unsigned long *)) {
    (void)lookup; (void)cfi; return fault_stage == 5 ? -EIO : 0;
}
static int msu_early_runtime_target_bind(unsigned long (*lookup)(const char *),
    int (*cfi)(const char *, const void *, unsigned long *)) {
    (void)lookup; (void)cfi; return fault_stage == 6 ? -EIO : 0;
}
static int msu_installation_init(const maplesu_host_instance *instance, const unsigned char *name) {
    (void)instance; (void)name; return fault_stage == 7 ? -EIO : 0;
}
static int msu_su_runtime_init(const maplesu_host_instance *instance,
    const struct msu_deployment_namespace_record *record) {
    (void)instance; (void)record; return fault_stage == 8 ? -EIO : 0;
}
static int discard_boundary(int stage) {
    ++discard_calls; return discard_failure == stage ? -EINPROGRESS : 0;
}
static int msu_su_runtime_close(void) { return discard_boundary(1); }
static int msu_management_discard_unpublished(void) { return discard_boundary(2); }
static int msu_su_runtime_discarded(void) { return discard_boundary(3); }
static int msu_installation_discard_unpublished(void) { return discard_boundary(4); }
static int msu_manager_owner_discard_unpublished(struct msu_manager_owner *owner) {
    (void)owner; return discard_boundary(5);
}
'''

RAW_CASES = r'''
extern char __executable_start[], _end[];
static struct msu_resident_slot *slot;
static struct msu_deployment_namespace_record namespace;
static struct msu_resident_config_v3 config;
static unsigned char image[64], append[MAPLESU_LEGACY_METADATA_V2_BYTES];
static int reset_raw(bool iter) {
    reset_boot(iter); memset(&boot_resident, 0, sizeof boot_resident); memset(&host, 0, sizeof host);
    msu_resident_discard_stage = 0; msu_resident_discard_mutex.held = 0;
    msu_resident_raw_targets_bound = msu_resident_boot_events_stopped = false;
    fault_stage = discard_failure = discard_calls = preinit_releases = 0;
    if (slot) free(slot);
    slot = aligned_alloc(64, sizeof *slot); CHECK(slot != NULL); memset(slot, 0, sizeof *slot);
    slot->boot_magic = MSU_RESIDENT_BOOT_MAGIC; slot->state = MSU_RESIDENT_INITIALIZING;
    namespace = deployment();
    config = (struct msu_resident_config_v3){
        .base = {.version = 3, .config_bytes = sizeof config, .append_bytes = sizeof append,
            .namespace_record_bytes = sizeof namespace, .image = image, .append = append,
            .credential = "0123456789abcdef0123456789abcdef0123456789abcdef", .namespace_record = &namespace},
        .slot = slot, .memory = __executable_start, .allocation_bytes = (u64)(_end - __executable_start),
    };
    return 0;
}
static void publish_ready(void) {
    slot->memory = (unsigned long)config.memory; slot->allocation_bytes = config.allocation_bytes;
    smp_store_release(&slot->state, MSU_RESIDENT_READY);
}
static int check_raw_stream(bool iter, const char *rc_output) {
    CHECK(reset_raw(iter) == 0);
    CHECK(msu_manager_resident_init((const void *)&config) == 0);
    CHECK(registrations == 1 && events.started && host.initialized && init_task.refs == 2);
    CHECK(module_get_calls == 0 && bridge_module.refs == 0 && preinit_releases == 0);
    CHECK(bind_file() == 0 && rc_file.f_op == &native_ops); /* INITIALIZING cannot publish. */
    publish_ready(); CHECK(bind_file() == 0 && rc_file.f_op == &events.proxy && events.proxy.owner == NULL);
    CHECK(queued_work && !removals && work_schedules == 1);
    if (iter) run_queued_work();
    else run_work_during_cancel = true;
    CHECK(msu_manager_resident_discard() == -EBUSY && removals == 1 && discard_calls == 0);
    CHECK(!queued_work && work_runs == 1 && !events.registered);
    char output[2048]; size_t used = 0;
    for (;;) {
        ssize_t got = read_file(output + used, 5); CHECK(got >= 0 && got <= 5);
        if (!got) break; used += (size_t)got; CHECK(used < sizeof output);
    }
    CHECK(used == sizeof original_bytes - 1 + events.rc_bytes && events.emitted == events.rc_bytes);
    CHECK(!memcmp(output, original_bytes, sizeof original_bytes - 1));
    CHECK(!memcmp(output + sizeof original_bytes - 1, events.rc, events.rc_bytes));
    CHECK(strstr(events.rc, "on post-fs-data") && strstr(events.rc, "on nonencrypted") &&
        strstr(events.rc, "vold.decrypt=trigger_restart_framework") && strstr(events.rc, "sys.boot_completed=1"));
    CHECK(!strstr(events.rc, "--boot-event post-mount"));
    if (rc_output) {
        FILE *out = fopen(rc_output, "wb"); CHECK(out != NULL);
        CHECK(fwrite(output + sizeof original_bytes - 1, 1, events.rc_bytes, out) == events.rc_bytes);
        CHECK(fclose(out) == 0);
    }
    CHECK(rc_file.f_op->release(&rc_inode, &rc_file) == -EIO && release_calls == 1);
    CHECK(fs_module.refs == 0 && init_task.refs == 1 && events.state == EVENTS_CLOSED);
    CHECK(msu_manager_resident_discard() == 0 && removals == 1 && discard_calls == 5 && !host.initialized);
    /* READY Image owns the proxy/release return tail even before final fops_put. */
    CHECK(slot->state == MSU_RESIDENT_READY && rc_file.f_op->owner == NULL);
    fops_put(rc_file.f_op);
    CHECK(module_get_calls == 0 && bridge_module.refs == 0 && preinit_releases == 0);
    return 0;
}
int main(int argc, char **argv) {
    CHECK(argc == 2); CHECK(check_raw_stream(false, argv[1]) == 0); CHECK(check_raw_stream(true, NULL) == 0);
    CHECK(reset_raw(false) == 0); CHECK(msu_manager_resident_init((const void *)&config) == 0);
    publish_ready(); CHECK(bind_file() == 0 && queued_work);
    CHECK(msu_manager_resident_discard() == -EBUSY && removals == 1 && !queued_work && !work_runs);
    CHECK(rc_file.f_op->release(&rc_inode, &rc_file) == -EIO); fops_put(rc_file.f_op);
    CHECK(msu_manager_resident_discard() == 0 && removals == 1 && !queued_work && !module_get_calls);
    for (int failure = 1; failure <= 13; ++failure) {
        if (failure == 9) continue;
        CHECK(reset_raw(false) == 0); fault_stage = failure;
        CHECK(msu_manager_resident_init((const void *)&config) == (failure == 10 ? -ENOMEM : -EIO));
        CHECK(!host.initialized && !registrations && rc_file.f_op == &native_ops);
        CHECK(msu_manager_resident_discard() == 0 && !events.owner && !events.registered && !events.rc_bytes && !queued_work);
    }
    CHECK(reset_raw(false) == 0); probe_error = -EPERM;
    CHECK(msu_manager_resident_init((const void *)&config) == -EPERM && !host.initialized && !events.owner);
    CHECK(msu_manager_resident_discard() == 0 && !removals && module_get_calls == 0 && !queued_work);
    CHECK(reset_raw(false) == 0); CHECK(msu_manager_resident_init((const void *)&config) == 0);
    slot->state = MSU_RESIDENT_QUARANTINED;
    CHECK(bind_file() == 0 && rc_file.f_op == &native_ops);
    CHECK(msu_manager_resident_discard() == 0 && removals == 1 && init_task.refs == 1);
    CHECK(reset_raw(false) == 0); CHECK(msu_manager_resident_init((const void *)&config) == 0);
    publish_ready(); ++slot->allocation_bytes; CHECK(bind_file() == 0 && rc_file.f_op == &native_ops);
    CHECK(msu_manager_resident_discard() == 0 && removals == 1);
    for (int failure = 1; failure <= 5; ++failure) {
        CHECK(reset_raw(false) == 0); CHECK(msu_manager_resident_init((const void *)&config) == 0);
        discard_failure = failure; CHECK(msu_manager_resident_discard() == -EINPROGRESS);
        CHECK(removals == 1 && !events.registered && !events.owner && !events.rc_bytes);
        discard_failure = 0; CHECK(msu_manager_resident_discard() == 0 && removals == 1 && discard_calls == 6);
    }
    CHECK(reset_raw(false) == 0); msu_resident_discard_mutex.held = 1;
    CHECK(msu_manager_resident_discard() == -EINPROGRESS && !removals && !discard_calls);
    msu_resident_discard_mutex.held = 0; free(slot); slot = NULL;
    puts("PASS raw producer + actual resident init/discard bodies: READY gate, read/read_iter, one-shot probe work, queued/dispatched discard drain, 13 init failures, 5 pending retire stages");
    return 0;
}
'''

HELPER_CASES = r'''
int main(int argc, char **argv) {
    check(argc == 2, "producer rc input required");
    helper_ops ops{};
    ops.open_path = open_path; ops.fstat = stat_fd; ops.read = read_fd; ops.write = write_fd;
    ops.close = close_fd; ops.fsync = sync_fd; ops.flock_dir = lock_fd;
    ops.renameat = rename_at; ops.unlinkat = unlink_at;
    ops.read_self_path = self_path; ops.read_boot_id = boot_id; ops.execve = execute; ops.log_line = log_line;
    fs::create_directories(fs::path(self).parent_path());
    put(std::string(fs::path(self).parent_path()) + "/install.mode", "boot");
    fs::create_directories("/data/adb/maplesu/bin"); fs::create_directories("/system/bin");
    fs::create_symlink("/bin/sh", "/system/bin/sh");
    const std::string dispatcher = "/data/adb/maplesu/bin/module-boot.sh";
    put(dispatcher, "#!/bin/sh\nprintf '%s\\n' \"$1\" >> /tmp/helper-events\nif [ \"$1\" = post-fs-data ]; then printf 'post-fs-data\\n' >> /tmp/native-init; fi\nexit 0\n");
    check(chmod(dispatcher.c_str(), 0755) == 0, "publish persistent fixture dispatcher");
    std::ifstream rc(argv[1]); check(rc.good(), "read actual producer stream");
    std::string line, trigger;
    std::vector<std::vector<std::string>> actions;
    int encrypted_service = 0;
    while (std::getline(rc, line)) {
        if (line.rfind("on ", 0) == 0) { trigger = line.substr(3); continue; }
        if (line.find("exec -- ") == std::string::npos) continue;
        std::istringstream input(line); std::string exec, delimiter, path, option, event;
        input >> exec >> delimiter >> path >> option >> event;
        check(exec == "exec" && delimiter == "--" && path == self && option == "--boot-event",
            "real producer selects installed helper and boot-event argument");
        if (trigger == "property:vold.decrypt=trigger_restart_framework") {
            check(event == "service", "encrypted boot uses same service event"); ++encrypted_service;
        } else actions.push_back({path, option, event});
    }
    check(actions.size() == 3 && encrypted_service == 1, "three actual unencrypted init stages and encrypted service branch");
    for (auto &action : actions) {
        char *args[] = {action[0].data(), action[1].data(), action[2].data(), nullptr};
        check(helper_run_boot(&ops, 3, args, nullptr) == 0, "producer action reaches real helper dispatcher");
    }
    check(get("/tmp/helper-events") == "post-fs-data\nservice\nboot-completed\n", "all producer stages survive real fork exec wait");
    check(get("/tmp/native-init") == "core\npost-fs-data\nmodules\n", "actual early dispatcher precedes modules and native initialization runs once");
    check(get(std::string(self) + HELPER_SUFFIX_SAFE_FLAG) == "2", "completed native session retains its real boot receipt");
    std::cout << "PASS actual producer RC -> helper/session fork/exec/wait -> persistent dispatcher: post-fs-data, service, boot-completed\n";
    return 0;
}
'''


def function(text, name):
    start = text.index('int ' + name + '(') if name != 'msu_resident_sleepable' else text.index('static bool ' + name + '(')
    begin = text.index('{', start)
    depth = 1
    end = begin + 1
    while depth:
        depth += (text[end] == '{') - (text[end] == '}')
        end += 1
    return text[start:end]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--host-source', type=Path, help='Use a frozen predecessor to demonstrate the same wiring test red')
    args = parser.parse_args()
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=True)
    specification = importlib.util.spec_from_file_location('boot_fixture', HERE / 'test_boot_events.py')
    common = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(common)
    host_path = (args.host_source or ROOT / 'runtime/ultra/identity/kernel/manager_resident_host.c').resolve()
    inputs = [Path(__file__), HERE / 'test_boot_events.py', BRIDGE / 'boot_events.c', BRIDGE / 'boot_events.h', host_path]
    kernel_headers = ROOT / 'runtime/ultra/identity/kernel'
    headers = [kernel_headers / name for name in ('manager_resident_abi.h', 'manager_claim_loader.h',
        'manager_deployment_namespace.h', 'manager_claim_entry.h', 'manager_claim_abi.h', 'manager_apk_identity.h')]
    headers.append(ROOT / 'runtime/ultra/authorization/request_protocol.h')
    inputs += headers
    sdk = ROOT / 'runtime/maplesu-sdk/sdk'
    helper_sources = [sdk / name for name in ('tools/tests/p6_boot/test_boot.cpp', 'tools/tests/p6_boot/worker_boundary.cpp',
        'src/helper/helper_boot.cpp', 'src/helper/helper_session.cpp', 'src/helper/helper_text.cpp',
        'include/maplesu_module_environment_private.h')]
    inputs += helper_sources + [ROOT / 'runtime/ultra/boot/bootstrap_finish.c']
    before = {str(p): hashlib.sha256(p.read_bytes()).hexdigest() for p in inputs}
    for p in [BRIDGE / 'boot_events.c', BRIDGE / 'boot_events.h', *headers]:
        (out / p.name).write_bytes(p.read_bytes())
    for name in ('cred', 'dcache', 'err', 'fs', 'file', 'fcntl', 'slab', 'irqflags', 'kernel', 'kprobes',
        'limits', 'module', 'mutex', 'pid', 'preempt', 'sched', 'sched/task', 'string', 'uaccess', 'uio', 'types', 'stddef', 'workqueue'):
        p = out / 'linux' / (name + '.h')
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text('/* explicit kernel boundary mock */\n')
    (out / 'asm').mkdir(exist_ok=True)
    (out / 'asm/ptrace.h').write_text('/* explicit ARM64 register boundary mock */\n')
    (out / 'manager_dynamic_layout.h').write_text('/* explicit dynamic field boundary mock */\n')
    source = host_path.read_text(encoding='utf-8-sig')
    owner = source[source.index('static struct {'):source.index('static bool msu_resident_sleepable')]
    bodies = '\n'.join(function(source, name) for name in ('msu_resident_sleepable', 'msu_manager_resident_init', 'msu_manager_resident_discard'))
    prefix = '#define __KERNEL__ 1\n#define MSU_BOOT_EVENTS_RAW_RESIDENT 1\n#define MSU_RAW_RESIDENT_LOOKUP 1\n'
    definitions = common.DEFINITIONS.replace('typedef unsigned int u32;', 'typedef unsigned char u8;\ntypedef unsigned short u16;\ntypedef long long s64;\ntypedef unsigned int u32;')
    cases = common.CASES.split('static int close_file(')[0].replace('aB3dE6gH9jK2mN5p', '0123456789abcdef')
    cases = cases.replace('static int arm(', 'static int __attribute__((unused)) arm(')
    (out / 'raw-fixture.c').write_text(prefix + definitions + '\n#include "boot_events.c"\n' +
        cases + HOST_BOUNDARIES + owner + bodies + RAW_CASES)
    argv = ['docker', 'run', '--rm', '--pull', 'never', '--network', 'none', '--read-only',
        '--tmpfs', '/tmp:rw,exec,size=16m', '--mount', f'type=bind,source={out},target=/work',
        '-w', '/work', '--entrypoint', '/bin/sh', IMAGE, '-ec',
        'gcc -std=gnu11 -O1 -Wall -Wextra -Werror -Wno-misleading-indentation -I/work -no-pie raw-fixture.c -o raw-fixture && exec ./raw-fixture /work/produced-init.rc']
    done = subprocess.run(argv, capture_output=True, text=True, encoding='utf-8', errors='replace', timeout=40)
    (out / 'run.log').write_text(done.stdout + done.stderr)
    commands = [{'argv': argv, 'exit': done.returncode}]
    output = done.stdout + done.stderr
    if done.returncode == 0:
        helper = helper_sources[0].read_text(encoding='utf-8-sig').split('int main() {')[0]
        (out / 'helper-dispatch.cpp').write_text('#include <sstream>\n#include <vector>\n' + helper + HELPER_CASES)
        prefix = '/repo/runtime/maplesu-sdk/sdk/'
        source_names = [prefix + p.relative_to(sdk).as_posix() for p in helper_sources[1:5]]
        script = 'set -eu\ngcc -O1 -Wall -Wextra -Werror -c /repo/runtime/ultra/boot/bootstrap_finish.c -o finish.o\n'
        script += 'g++ -std=c++20 -O1 -Wall -Wextra -Werror -I' + prefix + 'src/helper -I' + prefix + 'include '
        script += '-I/repo/runtime/maplesu-sdk/include -I' + prefix + 'tools/tests/p6_boot '
        script += 'helper-dispatch.cpp ' + ' '.join(source_names) + ' finish.o -o helper-dispatch\n'
        script += 'exec ./helper-dispatch /work/produced-init.rc\n'
        (out / 'helper-dispatch.sh').write_text(script, newline='\n')
        helper_argv = ['docker', 'run', '--rm', '--pull', 'never', '--network', 'none', '--read-only',
            '--tmpfs', '/tmp:rw,exec,size=32m', '--tmpfs', '/data:rw,exec,size=16m', '--tmpfs', '/system:rw,exec,size=4m',
            '--mount', f'type=bind,source={ROOT},target=/repo,readonly', '--mount', f'type=bind,source={out},target=/work',
            '-w', '/work', '--entrypoint', '/bin/sh', IMAGE, '/work/helper-dispatch.sh']
        done = subprocess.run(helper_argv, capture_output=True, text=True, encoding='utf-8', errors='replace', timeout=40)
        (out / 'helper-dispatch.log').write_text(done.stdout + done.stderr)
        commands.append({'argv': helper_argv, 'exit': done.returncode})
        output += done.stdout + done.stderr
    stable = all(before[str(p)] == hashlib.sha256(p.read_bytes()).hexdigest() for p in inputs)
    (out / 'RESULT.json').write_text(json.dumps({'passed': done.returncode == 0 and stable, 'exit': done.returncode,
        'commands': commands, 'inputs': before, 'sourceInputsStable': stable, 'deviceTested': False,
        'scope': 'production boot_events.c and complete actual resident init/discard bodies; mocked kernel/runtime dependencies'}, indent=2) + '\n')
    print(output)
    raise SystemExit(done.returncode or (0 if stable else 1))


if __name__ == '__main__':
    main()
