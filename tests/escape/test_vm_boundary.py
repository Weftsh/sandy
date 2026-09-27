"""MicroVM boundary checks (Firecracker only)."""
import pytest

from conftest import run_py

pytestmark = pytest.mark.vm


def test_guest_runs_its_own_kernel_under_a_hypervisor(attacker):
    out = attacker.commands.run("uname -r; grep -c hypervisor /proc/cpuinfo").stdout.split()
    assert "weft" in out[0], f"unexpected kernel {out[0]}"
    assert int(out[1]) >= 1


def test_no_kvm_device_and_no_loadable_modules(attacker):
    code, out, _ = run_py(attacker, "import os; print(os.path.exists('/dev/kvm'), os.path.exists('/proc/modules'))")
    assert out.strip() == "False False"


def test_guest_sees_only_its_own_memory_and_processes(attacker):
    mem_kb = int(attacker.commands.run("awk '/MemTotal/ {print $2}' /proc/meminfo").stdout)
    assert mem_kb < 64 * 1024 * 1024, "guest must not see host memory"
    procs = attacker.commands.run("ls /proc | grep -c '^[0-9]'", user="root").stdout.strip()
    assert int(procs) < 200


def test_serial_console_flood_does_not_break_the_sandbox(attacker):
    attacker.commands.run("head -c 50000000 /dev/zero > /dev/ttyS0 || true", user="root", timeout=120)
    assert attacker.commands.run("echo alive").stdout.strip() == "alive"


def test_filling_the_disk_stays_inside_the_sandbox(attacker):
    attacker.commands.run("dd if=/dev/zero of=/fill bs=1M 2>/dev/null || true; sync", user="root", timeout=300)
    assert attacker.commands.run("rm -f /fill; echo ok", user="root").stdout.strip() == "ok"
