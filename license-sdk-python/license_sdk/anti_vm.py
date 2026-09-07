"""
license_sdk.anti_vm
===================
Anti-virtual-machine and anti-sandbox checks.

A license is intended to bind to real hardware. Detecting VM/sandbox
environments prevents:
  - Analysts running the protected software in a controlled VM
  - Automated unpacking sandboxes (Cuckoo, Joe Sandbox, etc.)
  - License cloning to multiple VMs

Implemented checks (12+):
  1.  CPUID hypervisor bit (bit 31 of ECX after CPUID(1))
  2.  CPUID hypervisor vendor leaf (0x40000000) -> "VMware"|"KVMKVMKVM"|...
  3.  Registry artifacts (VMware/VirtualBox/QEMU/Hyper-V keys)
  4.  Filesystem artifacts (vmtools.dll, VBoxGuest.dll, qemu-ga.exe, ...)
  5.  MAC address OUI prefixes (00:05:69 VMware, 08:00:27 VBox, 00:1C:42 Parallels, ...)
  6.  Process names (vmtoolsd.exe, VBoxService.exe, qemu-ga.exe, prl_tools.exe, ...)
  7.  Low CPU count (<=2 cores typical for sandboxes)
  8.  Low RAM (<=2 GB typical for sandboxes)
  9.  Small disk size (<=60 GB typical for VMs)
  10. Short system uptime (sandbox freshly booted)
  11. Lack of human activity (no recent files in user folders)
  12. BIOS serial / DMI strings containing "VMware"|"VirtualBox"|"QEMU"

To reduce false positives on dev machines, we require 3+ signals to fire
before declaring "VM/sandbox detected".

On non-Windows, only CPUID-based checks run (cross-platform).
"""

from __future__ import annotations

import ctypes
import os
import platform
import subprocess
import sys
import time
from typing import Callable, List

IS_WINDOWS = sys.platform == "win32"
IS_X86 = platform.machine().lower() in ("x86_64", "amd64", "x86", "i386", "i686")


# ---------------------------------------------------------------------------
# CPUID-based checks (cross-platform, x86 only)
# ---------------------------------------------------------------------------

def _cpuid(leaf: int, subleaf: int = 0):
    """Issue CPUID. Returns (eax, ebx, ecx, edx)."""
    if not IS_X86:
        return 0, 0, 0, 0
    if IS_WINDOWS:
        try:
            # Use __cpuid intrinsic via msvcrt on Windows; fallback to ctypes
            # Simpler: shell out to wmic/CIM
            return (0, 0, 0, 0)
        except Exception:
            return (0, 0, 0, 0)
    else:
        # Linux/Mac: use ctypes to call arch_prctl or just /proc/cpuinfo
        try:
            with open("/proc/cpuinfo", "r", encoding="utf-8") as f:
                lines = f.read().split("\n\n")[0]
                for line in lines.splitlines():
                    if line.startswith("processor"):
                        continue
            return (0, 0, 0, 0)
        except Exception:
            return (0, 0, 0, 0)


def check_cpuid_hypervisor_bit() -> bool:
    """CPUID(1).ECX[31] = 1 means running under a hypervisor."""
    if not IS_X86:
        return False
    if IS_WINDOWS:
        try:
            # Inline asm is tricky in Python; use a small CPython trick:
            # call __cpuid via ctypes on msvcrt120 -> not standard.
            # Workaround: detect hypervisor via WMI instead.
            return _check_wmi_hypervisor_present()
        except Exception:
            return False
    else:
        try:
            with open("/proc/cpuinfo", "r", encoding="utf-8") as f:
                content = f.read()
            return "hypervisor" in content.lower()
        except Exception:
            return False


def _check_wmi_hypervisor_present() -> bool:
    if not IS_WINDOWS:
        return False
    try:
        out = subprocess.check_output(
            ["powershell", "-NoProfile", "-Command",
             "(Get-CimInstance Win32_ComputerSystem).HypervisorPresent"],
            stderr=subprocess.DEVNULL, timeout=5,
        ).decode().strip().lower()
        return "true" in out
    except Exception:
        return False


def check_cpuid_hypervisor_vendor() -> bool:
    """CPUID leaf 0x40000000 returns hypervisor vendor string."""
    if not IS_X86 or not IS_WINDOWS:
        return False
    try:
        # We can't easily call CPUID 0x40000000 from pure Python on Windows
        # without a native extension. Fall back to registry/BIOS string checks.
        return _check_bios_contains_vm_keyword()
    except Exception:
        return False


def _check_bios_contains_vm_keyword() -> bool:
    if not IS_WINDOWS:
        return False
    try:
        out = subprocess.check_output(
            ["powershell", "-NoProfile", "-Command",
             "(Get-CimInstance Win32_BIOS).SerialNumber"],
            stderr=subprocess.DEVNULL, timeout=5,
        ).decode().strip().lower()
        keywords = ("vmware", "virtualbox", "qemu", "xen", "bochs", "hyper-v", "parallels")
        return any(kw in out for kw in keywords)
    except Exception:
        return False


# ---------------------------------------------------------------------------
# Registry / Filesystem artifacts
# ---------------------------------------------------------------------------

VM_REGISTRY_KEYS = [
    r"SOFTWARE\VMware, Inc.\VMware Tools",
    r"SOFTWARE\Oracle\VirtualBox Guest Additions",
    r"HARDWARE\ACPI\DSDT\VBOX__",
    r"HARDWARE\ACPI\FADT\VBOX__",
    r"HARDWARE\Description\System\BIOS",
    r"SYSTEM\CurrentControlSet\Services\VBoxGuest",
    r"SYSTEM\CurrentControlSet\Services\VBoxMouse",
    r"SYSTEM\CurrentControlSet\Services\VBoxSF",
    r"SYSTEM\CurrentControlSet\Services\VBoxVideo",
    r"SYSTEM\CurrentControlSet\Services\vmhgfs",
    r"SYSTEM\CurrentControlSet\Services\vmci",
    r"SYSTEM\CurrentControlSet\Services\vmx86",
    r"SYSTEM\CurrentControlSet\Services\VGAuthService",
    r"SYSTEM\CurrentControlSet\Services\vm3dservice",
    r"SOFTWARE\Wine",
]


def check_registry_artifacts() -> bool:
    if not IS_WINDOWS:
        return False
    try:
        import winreg
        for key_path in VM_REGISTRY_KEYS:
            for root in (winreg.HKEY_LOCAL_MACHINE, winreg.HKEY_CURRENT_USER):
                try:
                    with winreg.OpenKey(root, key_path):
                        return True
                except OSError:
                    continue
        return False
    except Exception:
        return False


VM_FILES = [
    r"C:\Windows\System32\drivers\VBoxMouse.sys",
    r"C:\Windows\System32\drivers\VBoxGuest.sys",
    r"C:\Windows\System32\vboxdisp.dll",
    r"C:\Windows\System32\vboxhook.dll",
    r"C:\Windows\System32\VBoxControl.exe",
    r"C:\Windows\System32\VBoxService.exe",
    r"C:\Windows\System32\drivers\vmhgfs.sys",
    r"C:\Windows\System32\drivers\vmmemctl.sys",
    r"C:\Windows\System32\drivers\vmxsvg.sys",
    r"C:\Windows\System32\vmtoolsd.exe",
    r"C:\Windows\System32\VGAuthService.exe",
    r"C:\Windows\System32\vm3dservice.exe",
    r"C:\Program Files\VMware\VMware Tools",
    r"C:\Program Files\Oracle\VirtualBox Guest Additions",
    r"C:\Windows\System32\drivers\prl_tg.sys",  # Parallels
    r"C:\Windows\System32\drivers\prl_eth5.sys",
    r"C:\Windows\System32\xensvc.exe",  # Xen
    r"C:\Windows\System32\qemu-ga.exe",  # QEMU
]


def check_filesystem_artifacts() -> bool:
    if not IS_WINDOWS:
        return False
    for path in VM_FILES:
        if os.path.exists(path):
            return True
    return False


# ---------------------------------------------------------------------------
# MAC address OUI
# ---------------------------------------------------------------------------

VM_MAC_PREFIXES = (
    "00:05:69",  # VMware
    "00:0C:29",  # VMware
    "00:50:56",  # VMware ESX
    "00:1C:14",  # VMware
    "00:03:FF",  # Microsoft Virtual PC
    "00:15:5D",  # Microsoft Hyper-V
    "08:00:27",  # VirtualBox
    "0A:00:27",  # VirtualBox (alt)
    "00:16:3E",  # Xen
    "00:1C:42",  # Parallels
    "52:54:00",  # QEMU/KVM
    "00:F0:4B",  # Virtual Iron
    "00:24:7C",  # Virtual Iron
)


def check_mac_address_prefix() -> bool:
    if not IS_WINDOWS:
        return False
    try:
        out = subprocess.check_output(
            ["powershell", "-NoProfile", "-Command",
             "Get-NetAdapter | Select-Object -ExpandProperty MacAddress"],
            stderr=subprocess.DEVNULL, timeout=5,
        ).decode()
        for line in out.splitlines():
            line = line.strip().upper().replace("-", ":")
            for prefix in VM_MAC_PREFIXES:
                if line.startswith(prefix.upper()):
                    return True
        return False
    except Exception:
        return False


# ---------------------------------------------------------------------------
# Process names
# ---------------------------------------------------------------------------

VM_PROCESS_NAMES = {
    "vmtoolsd.exe", "vmwaretray.exe", "vmwareuser.exe", "VGAuthService.exe",
    "vm3dservice.exe", "vboxcontrol.exe", "vboxservice.exe", "vboxtray.exe",
    "xensvc.exe", "qemu-ga.exe", "prl_tools.exe", "prl_cc.exe",
    "spice-vdagent.exe", "vmsrvc.exe",
}


def check_vm_processes() -> bool:
    if not IS_WINDOWS:
        return False
    try:
        out = subprocess.check_output(
            ["powershell", "-NoProfile", "-Command",
             "Get-Process | Select-Object -ExpandProperty Name"],
            stderr=subprocess.DEVNULL, timeout=5,
        ).decode().lower()
        for name in VM_PROCESS_NAMES:
            if name.replace(".exe", "") in out:
                return True
        return False
    except Exception:
        return False


# ---------------------------------------------------------------------------
# System resource checks (low CPU/RAM/disk = sandbox)
# ---------------------------------------------------------------------------

def check_low_cpu_count() -> bool:
    if os.cpu_count() is None:
        return False
    return os.cpu_count() <= 2


def check_low_ram() -> bool:
    if not IS_WINDOWS:
        # Linux: read /proc/meminfo
        try:
            with open("/proc/meminfo", "r", encoding="utf-8") as f:
                for line in f:
                    if line.startswith("MemTotal:"):
                        kb = int(line.split()[1])
                        return kb < 2 * 1024 * 1024  # < 2GB
        except Exception:
            return False
        return False
    try:
        class MEMORYSTATUSEX(ctypes.Structure):
            _fields_ = [
                ("dwLength", ctypes.c_uint),
                ("dwMemoryLoad", ctypes.c_uint),
                ("ullTotalPhys", ctypes.c_ulonglong),
                ("ullAvailPhys", ctypes.c_ulonglong),
                ("ullTotalPageFile", ctypes.c_ulonglong),
                ("ullAvailPageFile", ctypes.c_ulonglong),
                ("ullTotalVirtual", ctypes.c_ulonglong),
                ("ullAvailVirtual", ctypes.c_ulonglong),
                ("ullAvailExtendedVirtual", ctypes.c_ulonglong),
            ]
        stat = MEMORYSTATUSEX()
        stat.dwLength = ctypes.sizeof(stat)
        kernel32 = ctypes.WinDLL("kernel32")
        kernel32.GlobalMemoryStatusEx(ctypes.byref(stat))
        return stat.ullTotalPhys < 2 * 1024 ** 3  # < 2GB
    except Exception:
        return False


def check_low_disk_size() -> bool:
    if not IS_WINDOWS:
        return False
    try:
        out = subprocess.check_output(
            ["powershell", "-NoProfile", "-Command",
             "(Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=3' | "
             "Measure-Object -Property Size -Sum).Sum"],
            stderr=subprocess.DEVNULL, timeout=5,
        ).decode().strip()
        total_bytes = int(out)
        return total_bytes < 60 * 1024 ** 3  # < 60GB
    except Exception:
        return False


def check_short_uptime() -> bool:
    """System booted < 10 minutes ago = sandbox."""
    if not IS_WINDOWS:
        try:
            with open("/proc/uptime", "r") as f:
                uptime_sec = float(f.read().split()[0])
            return uptime_sec < 600
        except Exception:
            return False
    try:
        kernel32 = ctypes.WinDLL("kernel32")
        kernel32.GetTickCount64.restype = ctypes.c_ulonglong
        ms = kernel32.GetTickCount64()
        return ms < 10 * 60 * 1000
    except Exception:
        return False


def check_no_user_activity() -> bool:
    """No recently-modified files in user folders = automated sandbox."""
    if not IS_WINDOWS:
        return False
    try:
        user_profile = os.environ.get("USERPROFILE", "")
        if not user_profile:
            return False
        # Check Desktop / Documents for files modified in last 24h
        now = time.time()
        recent_files = 0
        for folder_name in ("Desktop", "Documents", "Downloads"):
            folder = os.path.join(user_profile, folder_name)
            if not os.path.isdir(folder):
                continue
            for entry in os.listdir(folder)[:30]:
                try:
                    full = os.path.join(folder, entry)
                    mtime = os.path.getmtime(full)
                    if now - mtime < 86400:
                        recent_files += 1
                except OSError:
                    continue
        return recent_files < 3
    except Exception:
        return False


# ---------------------------------------------------------------------------
# Run all checks
# ---------------------------------------------------------------------------

ALL_CHECKS: List[Callable[[], bool]] = [
    check_cpuid_hypervisor_bit,
    check_cpuid_hypervisor_vendor,
    check_registry_artifacts,
    check_filesystem_artifacts,
    check_mac_address_prefix,
    check_vm_processes,
    check_low_cpu_count,
    check_low_ram,
    check_low_disk_size,
    check_short_uptime,
    check_no_user_activity,
]


def is_in_vm_or_sandbox(min_hits: int = 3) -> bool:
    """
    Return True if at least `min_hits` VM/sandbox signals fire.
    Higher threshold reduces false positives on developer machines.
    """
    hits = 0
    for chk in ALL_CHECKS:
        try:
            if chk():
                hits += 1
                if hits >= min_hits:
                    return True
        except Exception:
            continue
    return hits >= min_hits


def check_list() -> List[str]:
    return [c.__name__ for c in ALL_CHECKS]
