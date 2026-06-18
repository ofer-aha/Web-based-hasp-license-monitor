"""
diagnose2.py — memory scan approach for nhsrvice.exe session data
Run on example-host: python diagnose2.py
Strategy: read nhsrvice.exe process memory directly (it's in Session 0,
our process is also in Session 0 as SYSTEM with SeDebugPrivilege).
Look for hostname patterns in the session table.
"""
import ctypes, ctypes.wintypes, struct, re, os, json, subprocess, socket

results = {}

# ── helpers ──────────────────────────────────────────────────────────────────
k32 = ctypes.windll.kernel32

PROCESS_ALL_ACCESS      = 0x1F0FFF
PROCESS_VM_READ         = 0x0010
PROCESS_QUERY_INFO      = 0x0400
MEM_COMMIT              = 0x1000
PAGE_NOACCESS           = 0x001
PAGE_GUARD              = 0x100

class MEMORY_BASIC_INFORMATION(ctypes.Structure):
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
    import subprocess
    out = subprocess.run(
        ["powershell","-NoProfile","-Command",
         f"(Get-Process {name} -ErrorAction SilentlyContinue | Select-Object -First 1).Id"],
        capture_output=True, text=True, timeout=10
    ).stdout.strip()
    return int(out) if out.isdigit() else None

def read_mem(handle, addr, size):
    buf = ctypes.create_string_buffer(size)
    read = ctypes.c_size_t(0)
    ok = k32.ReadProcessMemory(handle, ctypes.c_void_p(addr), buf, size, ctypes.byref(read))
    if ok and read.value > 0:
        return bytes(buf[:read.value])
    return None

# ── 1. nhsrvice.exe strings (no keyword filter) ──────────────────────────────
nhsrv_exe = r"C:\Windows\SysWOW64\nhsrvice.exe"
if os.path.exists(nhsrv_exe):
    raw = open(nhsrv_exe, "rb").read()
    all_strs = re.findall(rb"[\x20-\x7e]{5,}", raw)
    results["nhsrvice_all_strings_sample"] = [
        s.decode("ascii", errors="ignore") for s in all_strs[:100]
    ]
    # Also look for ALL strings ≥3 chars (might have shorter protocol tokens)
    short_strs = re.findall(rb"[\x20-\x7e]{3,4}", raw)
    results["nhsrvice_short_strings"] = list(set(
        s.decode("ascii", errors="ignore") for s in short_strs
    ))[:80]
else:
    results["nhsrvice_all_strings_sample"] = "file not found"

# ── 2. Files in Aladdin directories ──────────────────────────────────────────
aladdin_files = {}
for d in [r"C:\Program Files (x86)\Aladdin",
          r"C:\Program Files\Aladdin",
          r"C:\Windows\SysWOW64"]:
    if os.path.isdir(d):
        try:
            files = [f for f in os.listdir(d)
                     if any(k in f.lower() for k in
                            ["hasp","aks","nhsr","nhl","aladdin","sentinel"])]
            aladdin_files[d] = files
        except Exception as e:
            aladdin_files[d] = str(e)
results["aladdin_files"] = aladdin_files

# ── 3. Device objects (kernel drivers) ───────────────────────────────────────
device_names = [
    r"\\.\AksHASP", r"\\.\AksHHL", r"\\.\Aksdf", r"\\.\AksFridge",
    r"\\.\AksUsb",  r"\\.\hasp",   r"\\.\HASP",  r"\\.\Sentinel",
    r"\\.\aksusb",  r"\\.\akshasp",r"\\.\AKS",   r"\\.\nhsrvice",
]
import win32file
device_results = {}
for dev in device_names:
    try:
        h = win32file.CreateFile(
            dev,
            win32file.GENERIC_READ | win32file.GENERIC_WRITE,
            win32file.FILE_SHARE_READ | win32file.FILE_SHARE_WRITE,
            None, win32file.OPEN_EXISTING, 0, None
        )
        device_results[dev] = "OPENED"
        # Try a few DeviceIoControl calls with common IOCTL patterns
        import win32con
        for ioctl in [0x222000, 0x222004, 0x222008, 0x22200C, 0x222010,
                      0x220000, 0x220004, 0x224000, 0x228000]:
            try:
                import win32file as wf
                buf = b"\x00" * 256
                ret = wf.DeviceIoControl(h, ioctl, buf, 1024)
                if ret and any(b > 0x1f for b in ret[:8]):
                    device_results[f"{dev}_ioctl_{ioctl:x}"] = ret.hex()[:128]
            except:
                pass
        h.Close()
    except Exception as e:
        device_results[dev] = str(e)[:80]
results["device_ioctl"] = device_results

# ── 4. ReadProcessMemory scan of nhsrvice.exe ────────────────────────────────
pid = find_pid("nhsrvice")
results["nhsrvice_pid"] = pid

if pid:
    handle = k32.OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFO, False, pid)
    results["nhsrvice_handle"] = "OK" if handle else "FAILED (err=" + str(k32.GetLastError()) + ")"

    if handle:
        # Walk all readable memory regions
        mbi = MEMORY_BASIC_INFORMATION()
        addr = 0
        sessions_found = []
        all_readable = []
        scan_total = 0
        scan_count = 0

        while addr < 0xFFFFFFFF:  # 32-bit process
            ret = k32.VirtualQueryEx(handle, ctypes.c_void_p(addr),
                                     ctypes.byref(mbi), ctypes.sizeof(mbi))
            if not ret:
                break

            # Only scan committed, readable, non-guard pages
            if (mbi.State == MEM_COMMIT
                    and mbi.Protect not in (PAGE_NOACCESS, PAGE_GUARD)
                    and mbi.Protect & 0xFF not in (0x01,)):
                size = min(mbi.RegionSize, 4 * 1024 * 1024)  # max 4MB per region
                data = read_mem(handle, addr, size)
                if data:
                    scan_total += len(data)
                    scan_count += 1

                    # Search for hostname-like patterns:
                    # - printable ASCII strings of 6-64 chars followed by null bytes
                    # - These look like "PCNAME\x00\x00..." or "192.168.x.x\x00..."
                    for m in re.finditer(rb'([A-Za-z0-9_\-\.]{4,30})\x00', data):
                        word = m.group(1).decode("ascii", errors="ignore")
                        # Skip obvious non-hostnames
                        if word.lower() in ("ntsystem","windows","system32","nhsrvice"):
                            continue
                        # Looks like a potential hostname or login ID
                        if re.match(r'^[A-Za-z0-9]([A-Za-z0-9\-\.]*[A-Za-z0-9])?$', word):
                            ctx_start = max(0, m.start() - 4)
                            ctx_end   = min(len(data), m.end() + 64)
                            ctx = data[ctx_start:ctx_end]
                            sessions_found.append({
                                "addr": hex(addr + m.start()),
                                "word": word,
                                "ctx_hex": ctx.hex(),
                                "ctx_ascii": ctx.decode("ascii", errors="."),
                            })

            addr += mbi.RegionSize
            if addr == 0:
                break

        results["memory_scan_total_bytes"] = scan_total
        results["memory_scan_regions"] = scan_count

        # Filter to the most interesting hostname-like matches
        # (short words, not path fragments, repeated patterns = session records)
        from collections import Counter
        word_counts = Counter(s["word"] for s in sessions_found)
        # Candidates: words that appear in non-trivial pattern (1-5 occurrences)
        candidates = [w for w, c in word_counts.most_common(200)
                      if 1 <= c <= 10 and 4 <= len(w) <= 30
                      and not w.lower().startswith(("ntdl","wow6","kern"))]
        results["memory_candidate_hostnames"] = candidates[:50]
        results["memory_matches_sample"] = [
            s for s in sessions_found
            if s["word"] in candidates[:20]
        ][:30]

        k32.CloseHandle(handle)
else:
    results["memory_scan_error"] = "nhsrvice not found"

# ── 5. UDP probe with larger packets ─────────────────────────────────────────
# Try 44-byte and 66-byte UDP packets (typical NH protocol sizes)
udp_results = {}
my_ip = socket.gethostbyname(socket.gethostname())
my_host = socket.gethostname().encode("ascii", errors="ignore")[:16].ljust(16, b"\x00")

for size in [16, 32, 44, 64, 66, 88, 128]:
    # Build a packet with typical NH format:
    # Station(2) + Prog(2) + Passwd(2) + Svc(2) + Attr(2) + Mfg(2) + ... + zeros
    pkt_base = struct.pack("<HHHHHH", 0, 3, 0, 0, 0, 0)  # station=0 prog=3 rest=0
    pkt = (pkt_base + my_host + b"\x00" * max(0, size - len(pkt_base) - 16))[:size]

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(2)
        s.sendto(pkt, ("127.0.0.1", 475))
        resp, addr = s.recvfrom(1024)
        udp_results[f"udp_{size}b"] = resp.hex()[:128]
        s.close()
    except socket.timeout:
        udp_results[f"udp_{size}b"] = "timeout"
    except Exception as e:
        udp_results[f"udp_{size}b"] = str(e)[:60]
results["udp_larger_probes"] = udp_results

# ── 6. Try binding source port 475 for UDP (server-to-server mode) ────────────
try:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(2)
    s.bind(("0.0.0.0", 475))  # bind our port to 475
    pkt = struct.pack("<HHHHHH", 0, 3, 0, 0, 0, 0) + b"\x00" * 38
    s.sendto(pkt, ("127.0.0.1", 475))
    resp, addr = s.recvfrom(1024)
    results["udp_src475"] = resp.hex()[:128]
    s.close()
except Exception as e:
    results["udp_src475"] = str(e)[:80]

# ── Output ────────────────────────────────────────────────────────────────────
out = os.path.join(os.path.dirname(os.path.abspath(__file__)), "diagnose2_out.json")
with open(out, "w", encoding="utf-8") as f:
    json.dump(results, f, indent=2, ensure_ascii=False)

print(f"Done → {out}")
print(f"Memory scan: {results.get('memory_scan_total_bytes',0)//1024}KB across {results.get('memory_scan_regions',0)} regions")
print(f"Candidate hostnames: {results.get('memory_candidate_hostnames',[])[:10]}")
print(f"Devices opened: {[k for k,v in results.get('device_ioctl',{}).items() if v=='OPENED']}")
print(f"UDP results: {results.get('udp_larger_probes',{})}")
