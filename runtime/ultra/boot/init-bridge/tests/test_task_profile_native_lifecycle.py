"""Execute the production native callback and synchronous marker functions.

The C port models native RCU/list and registration boundaries, not a kernel or
PREEMPT_RT device. DDK callback-type compilation is a separate integration check.
"""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[5]
SOURCE = Path(os.environ.get("MAPLESU_TASK_PROFILE_SOURCE_ROOT", ROOT / "runtime/ultra/identity/kernel"))
FIXTURE = Path(__file__).with_name("fixtures") / "task_profile_native_lifecycle.c"
IMAGE = "sha256:51159bc935c75a282fc65bc87e02f16bd098d1cdf55dc558c4fdd0fcf7a132e2"


def function(text, signature):
    start = text.index(signature)
    begin = text.index("{", start)
    depth = 1
    end = begin + 1
    while depth:
        depth += (text[end] == "{") - (text[end] == "}")
        end += 1
    return text[start:end] + "\n"


class TaskProfileNativeLifecycleTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix="maplesu-profile-")
        cls.out = Path(cls.temporary.name)
        runtime = (SOURCE / "manager_task_profile_runtime.c").read_text(encoding="utf-8-sig")
        state = (SOURCE / "manager_task_state.c").read_text(encoding="utf-8-sig")
        header = (SOURCE / "manager_task_state.h").read_text(encoding="utf-8-sig")
        binding = header[header.index("struct msu_task_profile_marker_binding {"):]
        binding = binding[:binding.index("};") + 2]
        (cls.out / "binding.inc").write_text(binding, encoding="utf-8")
        helpers = ""
        if "static int msu_profile_native_lock(" in runtime:
            helpers += function(runtime, "static int msu_profile_native_lock(")
        helpers += function(runtime, "static int msu_profile_trace_callback(")
        helpers += function(runtime, "static int msu_profile_marker(")
        (cls.out / "producer.inc").write_text(helpers, encoding="utf-8")
        start = state.index("struct msu_task_profile_marker_binding msu_task_profile_marker_target")
        end = state.index("int msu_task_profile_flags_supported(", start)
        (cls.out / "consumer.inc").write_text(state[start:end], encoding="utf-8")
        (cls.out / "fixture.c").write_bytes(FIXTURE.read_bytes())
        cls.prefix = ["docker", "run", "--rm", "--pull", "never", "--network", "none",
                      "--read-only", "--tmpfs", "/tmp:rw,exec,size=32m", "--mount",
                      f"type=bind,source={cls.out.as_posix()},target=/out", "-w", "/out",
                      "--entrypoint", "/bin/sh", IMAGE, "-ec"]
        result = subprocess.run(cls.prefix + [
            "cc -std=gnu11 -O1 -g -Wall -Wextra -Werror "
            "-Wno-unused-function -Wno-unused-variable -fsanitize=address,undefined "
            "-fno-omit-frame-pointer fixture.c -o fixture"], capture_output=True, text=True)
        if result.returncode:
            raise AssertionError(result.stdout + result.stderr)

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def check_case(self, case):
        result = subprocess.run(self.prefix + [f"ulimit -c 0; ./fixture {case}"], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


for _case in ("callback-no-peer", "rt-producer", "bind-no-tasklist", "rt-open", "atomic-scan",
              "own-subscriber", "other-subscriber", "exit-subscriber", "mode-change",
              "clone", "leader-exit", "de-thread", "probe-register-error", "trace-register-error",
              "close-order", "close-error", "closed-no-scan", "private-fact-error",
              "unused-lock-receipt", "irrelevant-tracepoint", "probe-missed",
              "subscriber-remove", "close-other-subscriber"):
    setattr(TaskProfileNativeLifecycleTest, "test_" + _case.replace("-", "_"),
            lambda self, case=_case: self.check_case(case))


if __name__ == "__main__":
    unittest.main()
