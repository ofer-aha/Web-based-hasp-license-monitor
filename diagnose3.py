"""
diagnose3.py — elevated memory scan + AksFridge IOCTL sweep
Run on SWCOMP99: python diagnose3.py
"""
import ctypes, ctypes.wintypes, struct, re, os, json, subprocess, socket

results = {}
k32 = ctypes.windll.kernel32

# ── Enable SeDebugPrivilege ────────────────────────────────────────────────
try:
    import win32security, win32api, win32con
    priv_flags = (win32security.TOKEN_ADJUST_PRIVILEGES |
                  win32security.TOKEN_QUERY)
    htok = win32security.OpenProcessToken(win32api.GetCurrentProcess(),
                                          priv_flags)
    priv_id = win32security.LookupPrivilegeValue(None, "SeDebugPrivilege")
    win32security.AdjustTokenPrivileges(
        htok, False,
        [(priv_id, win32security.SE_PRIVILEGE_ENABLED)])
    results["sedebug"] = "ENABLED"
except Exception as e:
    results["sedebug"] = "FAILED: " + str(e)

# ── Read haspaddr.dat ────────────────────────────────────────────────────────
for dat in [r"C:\Windows\SysWOW64\haspaddr.dat",
            r"C:\Windows\System32\haspaddr.dat"]:
    if os.path.exists(dat):
        try:
            results["haspaddr_dat"] = open(dat, "rb").read().hex()
        except Exception as e:
            results["haspaddr_dat"] = str(e)
        break

# ── List HASP LM directory ────────────────────────────────────────────────────
for d in [r"C:\Program Files (x86)\Aladdin\HASP LM",
          r"C:\Program Files\Aladdin\HASP LM",
          r"C:\Program Files (x86)\Aladdin\Monitor"]:
    if os.path.isdir(d):
        results.setdefault("hasp_lm_files", {})[d] = os.listdir(d)

# ── AksFridge IOCTL sweep ─────────────────────────────────────────────────────
import win32file
try:
    hdev = win32file.CreateFile(
        r"\\.\AksFridge",
        win32file.GENERIC_READ | win32file.GENERIC_WRITE,
        win32file.FILE_SHARE_READ | win32file.FILE_SHARE_WRITE,
        None, win32file.OPEN_EXISTING, 0, None)
    results["aksfridge_open"] = "OK"

    fridge_hits = {}
    # Try function codes 0 through 0x3FF, method 0 (buffered), access 0
    # IOCTL = (0x22 << 16) | (0 << 14) | (func << 2) | 0
    for func in range(0x400):
        ioctl = (0x22 << 16) | (func << 2)
        for inbuf in [b"", b"\x00" * 4, b"\x00" * 16, b"\x00" * 64]:
            try:
                ret = win32file.DeviceIoControl(hdev, ioctl, inbuf, 4096)
                if ret:
                    fridge_hits[f"func_{func:03x}_in{len(inbuf)}"] = ret.hex()[:256]
                    print(f"  AksFridge HIT: func=0x{func:03x} inlen={len(inbuf)} → {ret.hex()[:64]}")
                    break  # got a hit, try next func
            except Exception:
                pass

    results["aksfridge_ioctl_hits"] = fridge_hits
    hdev.Close()
except Exception as e:
    results["aksfridge_open"] = str(e)[:120]

# ── ReadProcessMemory with SeDebugPrivilege ──────────────────────────────────
PROCESS_VM_READ   = 0x0010
PROCESS_QUERY_INFO = 0x0400
MEM_COMMIT = 0x1000
PAGE_NOACCESS = 0x001

class MBI(ctypes.Structure):
    _fields_ = [
        ("BaseAddress",       ctypes.c_void_p),
        ("AllocationBase",    ctypes.c_void_p),
        ("AllocationProtect", ctypes.c_uint32),
        ("RegionSize",        ctypes.c_size_t),
        ("State",             ctypes.c_uint32),
        ("Protect",           ctypes.c_uint32),
        ("Type",              ctypes.c_uint32),
    ]

def find_pid(name):
    out = subprocess.run(
        ["powershell","-NoProfile","-Command",
         f"(Get-Process '{name}' -EA SilentlyContinue|Select -First 1).Id"],
        capture_output=True, text=True, timeout=10).stdout.strip()
    return int(out) if out.isdigit() else None

def read_mem(h, addr, size):
    buf = ctypes.create_string_buffer(size)
    read = ctypes.c_size_t(0)
    ok = k32.ReadProcessMemory(h, ctypes.c_void_p(addr), buf, size, ctypes.byref(read))
    return bytes(buf[:read.value]) if ok and read.value else None

pid = find_pid("nhsrvice")
results["nhsrvice_pid"] = pid

if pid:
    flags = PROCESS_VM_READ | PROCESS_QUERY_INFO
    handle = k32.OpenProcess(flags, False, pid)
    err = k32.GetLastError()
    results["nhsrvice_handle"] = "OK" if handle else f"FAILED err={err}"

    if handle:
        mbi = MBI()
        addr = 0
        session_candidates = []
        total_bytes = 0
        regions = 0

        while addr < 0x7FFFFFFF:
            ret = k32.VirtualQueryEx(handle, ctypes.c_void_p(addr),
                                     ctypes.byref(mbi), ctypes.sizeof(mbi))
            if not ret:
                break
            if (mbi.State == MEM_COMMIT
                    and mbi.Protect not in (1, 0x100)  # not NOACCESS, not GUARD
                    and mbi.Protect & 0xFF != 0x01):
                size = min(int(mbi.RegionSize), 2 * 1024 * 1024)
                data = read_mem(handle, addr, size)
                if data:
                    total_bytes += len(data)
                    regions += 1
                    # Look for hostname-like: printable ASCII 4-30 chars + null byte
                    for m in re.finditer(rb'([A-Za-z][A-Za-z0-9\-\.]{3,29})\x00', data):
                        word = m.group(1).decode("ascii", errors="ignore")
                        # Must start with letter, contain only hostname chars
                        if re.fullmatch(r'[A-Za-z][A-Za-z0-9\-\.]{3,29}', word):
                            # Skip common Windows/system strings
                            skip = {"ntdll","kernel","System","Windows","Program",
                                    "Microsoft","MSDOS","Config","SYSTEM","Local",
                                    "Default","Common","Desktop","nhsrvice",
                                    "network","Network"}
                            if word in skip or word.lower() in {s.lower() for s in skip}:
                                continue
                            ctx_start = max(0, m.start() - 16)
                            ctx_end   = min(len(data), m.end() + 80)
                            ctx = data[ctx_start:ctx_end]
                            session_candidates.append({
                                "word": word,
                                "vaddr": hex(addr + m.start()),
                                "ctx_hex": ctx.hex(),
                                "ctx_printable": "".join(
                                    chr(b) if 0x20 <= b < 0x7f else "." for b in ctx),
                            })
            addr += mbi.RegionSize or 0x1000

        results["mem_total_bytes"] = total_bytes
        results["mem_regions"] = regions

        # Deduplicate and count occurrences
        from collections import Counter
        word_ct = Counter(s["word"] for s in session_candidates)
        # Session table entries repeat predictably — 1-5 occurrences
        interesting = {w: ct for w, ct in word_ct.items() if 1 <= ct <= 8}
        results["mem_word_counts"] = dict(
            sorted(interesting.items(), key=lambda x: -x[1])[:60])
        results["mem_samples"] = [
            s for s in session_candidates
            if s["word"] in list(interesting.keys())[:15]
        ][:25]

        k32.CloseHandle(handle)

# ── Output ────────────────────────────────────────────────────────────────────
out = os.path.join(os.path.dirname(os.path.abspath(__file__)), "diagnose3_out.json")
with open(out, "w", encoding="utf-8") as f:
    json.dump(results, f, indent=2, ensure_ascii=False)

print(f"\nDone → {out}")
print(f"SeDebugPrivilege: {results.get('sedebug')}")
print(f"nhsrvice handle:  {results.get('nhsrvice_handle')}")
print(f"Memory scanned:   {results.get('mem_total_bytes',0)//1024}KB / {results.get('mem_regions',0)} regions")
print(f"Word counts (top 20): {dict(list(results.get('mem_word_counts',{}).items())[:20])}")
print(f"AksFridge hits:   {list(results.get('aksfridge_ioctl_hits',{}).keys())}")
