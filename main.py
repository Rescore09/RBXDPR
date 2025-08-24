import ctypes
import ctypes.wintypes as wintypes
import sys
import time
import json

from colorama import Fore

# rescore99

with open("patterns.json", "r") as f:
    patterns = json.load(f)

TH32CS_SNAPPROCESS = 0x00000002
TH32CS_SNAPMODULE = 0x00000008
TH32CS_SNAPMODULE32 = 0x00000010

PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_VM_READ = 0x0010

MEM_COMMIT = 0x1000
PAGE_GUARD = 0x100
PAGE_NOACCESS = 0x01
kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)

class PROCESSENTRY32(ctypes.Structure):
    _fields_ = [
        ('dwSize', wintypes.DWORD),
        ('cntUsage', wintypes.DWORD),
        ('th32ProcessID', wintypes.DWORD),
        ('th32DefaultHeapID', ctypes.POINTER(wintypes.ULONG)),
        ('th32ModuleID', wintypes.DWORD),
        ('cntThreads', wintypes.DWORD),
        ('th32ParentProcessID', wintypes.DWORD),
        ('pcPriClassBase', wintypes.LONG),
        ('dwFlags', wintypes.DWORD),
        ('szExeFile', wintypes.CHAR * 260),
    ]

class MODULEENTRY32(ctypes.Structure):
    _fields_ = [
        ('dwSize', wintypes.DWORD),
        ('th32ModuleID', wintypes.DWORD),
        ('th32ProcessID', wintypes.DWORD),
        ('GlblcntUsage', wintypes.DWORD),
        ('ProccntUsage', wintypes.DWORD),
        ('modBaseAddr', ctypes.POINTER(ctypes.c_byte)),
        ('modBaseSize', wintypes.DWORD),
        ('hModule', wintypes.HMODULE),
        ('szModule', wintypes.CHAR * 256),
        ('szExePath', wintypes.CHAR * wintypes.MAX_PATH)
    ]

class MEMORY_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("BaseAddress",       ctypes.c_void_p),
        ("AllocationBase",    ctypes.c_void_p),
        ("AllocationProtect", wintypes.DWORD),
        ("RegionSize",        ctypes.c_size_t),
        ("State",             wintypes.DWORD),
        ("Protect",           wintypes.DWORD),
        ("Type",              wintypes.DWORD),
    ]

def get_pid(process_name):
    snapshot = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    if snapshot == wintypes.HANDLE(-1).value:
        return 0
    entry = PROCESSENTRY32()
    entry.dwSize = ctypes.sizeof(PROCESSENTRY32)
    if not kernel32.Process32First(snapshot, ctypes.byref(entry)):
        kernel32.CloseHandle(snapshot)
        return 0
    while True:
        exe_name = entry.szExeFile.decode(errors='ignore')
        if exe_name.lower() == process_name.lower():
            pid = entry.th32ProcessID
            kernel32.CloseHandle(snapshot)
            return pid
        if not kernel32.Process32Next(snapshot, ctypes.byref(entry)):
            break
    kernel32.CloseHandle(snapshot)
    return 0

def get_module_info(pid, module_name):
    snapshot = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid)
    if snapshot == wintypes.HANDLE(-1).value:
        return 0, 0
    module_entry = MODULEENTRY32()
    module_entry.dwSize = ctypes.sizeof(MODULEENTRY32)
    if not kernel32.Module32First(snapshot, ctypes.byref(module_entry)):
        kernel32.CloseHandle(snapshot)
        return 0, 0
    while True:
        mod_name = module_entry.szModule.decode(errors='ignore')
        if mod_name.lower() == module_name.lower():
            base = ctypes.cast(module_entry.modBaseAddr, ctypes.c_void_p).value
            size = module_entry.modBaseSize
            kernel32.CloseHandle(snapshot)
            return base, size
        if not kernel32.Module32Next(snapshot, ctypes.byref(module_entry)):
            break
    kernel32.CloseHandle(snapshot)
    return 0, 0

def pattern_to_bytes(pattern):
    bytes_arr = []
    mask = ""
    i = 0
    length = len(pattern)
    while i < length:
        if pattern[i] == ' ':
            i += 1
            continue
        if pattern[i] == '?':
            bytes_arr.append(0)
            mask += '?'
            i += 1
            if i < length and pattern[i] == '?':
                i += 1
        else:
            if i + 1 >= length:
                return None, None
            def hex_char_to_int(c):
                if '0' <= c <= '9': return ord(c) - ord('0')
                if 'a' <= c <= 'f': return ord(c) - ord('a') + 10
                if 'A' <= c <= 'F': return ord(c) - ord('A') + 10
                return -1
            high = hex_char_to_int(pattern[i])
            low = hex_char_to_int(pattern[i+1])
            if high == -1 or low == -1:
                return None, None
            bytes_arr.append((high << 4) | low)
            mask += 'x'
            i += 2
    return bytes_arr, mask

def dc(data, pattern, mask):
    for i in range(len(pattern)):
        if mask[i] == 'x' and data[i] != pattern[i]:
            return False
    return True

def scan_region(h_process, base, size, pattern, mask):
    ReadProcessMemory = kernel32.ReadProcessMemory
    ReadProcessMemory.argtypes = [wintypes.HANDLE, wintypes.LPCVOID, wintypes.LPVOID, ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
    ReadProcessMemory.restype = wintypes.BOOL
    buffer = (ctypes.c_ubyte * size)()
    bytes_read = ctypes.c_size_t(0)
    if not ReadProcessMemory(h_process, ctypes.c_void_p(base), buffer, size, ctypes.byref(bytes_read)):
        return 0
    if bytes_read.value < len(pattern):
        return 0
    data = bytearray(buffer)[:bytes_read.value]
    plen = len(pattern)
    for i in range(bytes_read.value - plen + 1):
        if dc(data[i:i+plen], pattern, mask):
            return base + i
    return 0

def virtual_query_ex(h_process, address):
    mbi = MEMORY_BASIC_INFORMATION()
    result = kernel32.VirtualQueryEx(h_process, ctypes.c_void_p(address), ctypes.byref(mbi), ctypes.sizeof(mbi))
    if result != ctypes.sizeof(mbi):
        return None
    return mbi

def op(pid):
    return kernel32.OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, pid)

def close_handle(handle):
    kernel32.CloseHandle(handle)

def main():
    target_process = "RobloxPlayerBeta.exe"
    pid = get_pid(target_process)
    if not pid:
        print(f"[{Fore.RED}ERROR{Fore.RESET}] Roblox process not found.")
        input(f"[SYSTEM] Press Enter to exit...")
        sys.exit(1)    
    print(f"[{Fore.LIGHTBLUE_EX}INFO{Fore.RESET}] Starting Roblox Dumper")
    print(f"[{Fore.LIGHTBLUE_EX}INFO{Fore.RESET}] RBXDPR version: 0.1.0 [BETA]")
    print(f"[{Fore.YELLOW}WARN{Fore.RESET}] This tool is for education purposes only. I am not responsible for any damages caused with this")

    print(f"[{Fore.LIGHTBLUE_EX}INFO{Fore.RESET}] Roblox PID: {pid}")

    base, size = get_module_info(pid, target_process)
    if not base or not size:
        print("[ERROR] Failed to get module info.")
        input(f"[SYSTEM] Press Enter to exit...")
        sys.exit(1)

    print(f"[{Fore.LIGHTBLUE_EX}INFO{Fore.RESET}] Module Base Address: 0x{base:016X}")
    print(f"[{Fore.LIGHTBLUE_EX}INFO{Fore.RESET}] Module Size: 0x{size:X} bytes")

    h_process = op(pid)
    if not h_process:
        print(f"[{Fore.RED}ERROR{Fore.RESET}] Failed to open Roblox process.")
        input(f"[SYSTEM] Press Enter to exit...")
        sys.exit(1)

    start = base
    end = base + size

    found_offsets = {}

    current = start
    while current < end:
        mbi = virtual_query_ex(h_process, current)
        if not mbi:
            break
        if (mbi.State == MEM_COMMIT and
            not (mbi.Protect & PAGE_GUARD) and
            not (mbi.Protect & PAGE_NOACCESS) and
            mbi.BaseAddress >= start and mbi.BaseAddress < end):

            region_start = mbi.BaseAddress
            region_size = mbi.RegionSize
            if region_start + region_size > end:
                region_size = end - region_start

            for pattern_str, name in patterns:
                pattern_bytes, mask = pattern_to_bytes(pattern_str)
                if pattern_bytes is None:
                    print(f"[WARN] Failed to parse pattern '{name}'")
                    continue
                found = scan_region(h_process, region_start, region_size, pattern_bytes, mask)
                if found:
                    offset = found - base
                    found_offsets[name] = offset
                    print(f"[{Fore.GREEN}FOUND{Fore.RESET}] {name:15} -> Address: 0x{found:016X} | Offset: 0x{offset:X}")

        current = mbi.BaseAddress + mbi.RegionSize

    if not found_offsets:
        print(f"[{Fore.LIGHTBLUE_EX}INFO{Fore.RESET}] No patterns found.")

    else:
        with open("offsets.txt", "w") as f:
            for name, offset in found_offsets.items():
                f.write(f"{name} = 0x{offset:X}\n")
        print(f"\n[{Fore.LIGHTBLUE_EX}INFO{Fore.RESET}] Offsets saved to offsets.txt")

    close_handle(h_process)
    input(f"[SYSTEM] Press Enter to exit...")

if __name__ == "__main__":
    main()

