"""
diagnose.py — standalone HASP session diagnostic
Run on SWCOMP99: python diagnose.py
Outputs JSON with:
  - TCP command scan (find nhsrvice session-query command)
  - nhsrvice.exe binary strings (find IPC clues)
  - Full named pipe list
  - Aladdin registry tree
"""
import socket, re, os, json, subprocess, sys

results = {}

# ── 1. nhsrvice.exe registry path ──────────────────────────────────────────
def ps(cmd):
    try:
        r = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", cmd],
            capture_output=True, text=True, timeout=15
        )
        return (r.stdout or "").strip()
    except Exception as e:
        return "PS_ERR:" + str(e)

svc_path_raw = ps(
    "(Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\nhsrvice' "
    "-ErrorAction SilentlyContinue).ImagePath"
)
results["nhsrvice_reg_path"] = svc_path_raw

candidates = [
    svc_path_raw.strip('"').strip(),
    r"C:\Windows\System32\nhsrvice.exe",
    r"C:\Windows\SysWOW64\nhsrvice.exe",
    r"C:\Program Files (x86)\Aladdin\nhsrvice.exe",
    r"C:\Program Files\Aladdin\nhsrvice.exe",
]
nhsrv_exe = next((p for p in candidates if p and os.path.exists(p)), None)
results["nhsrvice_exe_found"] = nhsrv_exe

# ── 2. Read nhsrvice.exe strings ───────────────────────────────────────────
if nhsrv_exe:
    try:
        raw = open(nhsrv_exe, "rb").read()
        all_strs = re.findall(rb"[\x20-\x7e]{5,}", raw)
        kws = [b"pipe", b"session", b"login", b"monitor", b"hasp",
               b"socket", b"shared", b"mutex", b"semaphor", b"event",
               b"memory", b"server", b"port", b"listen", b"global"]
        matched = [s.decode("ascii", errors="ignore")
                   for s in all_strs if any(k in s.lower() for k in kws)]
        results["nhsrvice_strings"] = matched[:80]
        results["nhsrvice_total_strings"] = len(all_strs)
    except Exception as e:
        results["nhsrvice_strings"] = "ERR:" + str(e)
else:
    results["nhsrvice_strings"] = "file_not_found"

# ── 3. TCP command scan on port 475 ────────────────────────────────────────
# We know 000300000000 (BIG-ENDIAN length=3, payload=000000) gets a response.
# Try all command bytes 0x00..0x1F + some extras with lengths 1,3,5.
# An "error/null" response is all 0xFE/0xFF bytes; we want something different.

tcp_scan = {}
interesting = {}

cmds = list(range(0x20)) + [0x30, 0x40, 0x50, 0x80, 0xFE, 0xFF]
lengths = [1, 3, 5]

for plen in lengths:
    for cmd in cmds:
        payload = bytes([cmd] + [0] * (plen - 1))
        packet  = bytes([0x00, plen]) + payload
        key = f"L{plen}_x{cmd:02x}"
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(2)
            s.connect(("127.0.0.1", 475))
            s.send(packet)
            s.settimeout(1)
            try:
                resp = s.recv(1024)
                h = resp.hex()
                tcp_scan[key] = h[:80]
                # Flag responses that aren't all-0xFF/0xFE (i.e. real data)
                if resp and not all(b >= 0xFE for b in resp[:8]):
                    interesting[key] = h
                    print(f"  INTERESTING: {key} → {h[:80]}", flush=True)
            except socket.timeout:
                tcp_scan[key] = "timeout"
            except Exception as re2:
                tcp_scan[key] = "recv_err:" + str(re2)
            s.close()
        except OSError as ce:
            tcp_scan[key] = "conn_err:" + str(ce)

results["tcp_cmd_scan"] = tcp_scan
results["tcp_interesting"] = interesting

# Also try a few specific "known" NH monitor packets (program=3 in various positions)
monitor_probes = {
    "prog3_L3_v1": bytes([0x00, 0x03, 0x03, 0x00, 0x00]),  # L=3, cmd=0x03
    "prog3_L5_v1": bytes([0x00, 0x05, 0x00, 0x03, 0x00, 0x00, 0x00]),  # L=5, prog=3
    "prog3_L5_v2": bytes([0x00, 0x05, 0x03, 0x00, 0x03, 0x00, 0x00]),  # L=5, cmd=3 prog=3
    "length0":     bytes([0x00, 0x00]),                      # L=0, no payload
    "length1_ff":  bytes([0x00, 0x01, 0xFF]),                # L=1, cmd=0xFF
    "length1_fe":  bytes([0x00, 0x01, 0xFE]),                # L=1, cmd=0xFE
    "length3_prog3_a": bytes([0x00, 0x03, 0x00, 0x03, 0x00]),  # L=3, byte1=prog3
    "length3_prog3_b": bytes([0x00, 0x03, 0x00, 0x00, 0x03]),  # L=3, byte2=3
}
monitor_results = {}
for name, pkt in monitor_probes.items():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2)
        s.connect(("127.0.0.1", 475))
        s.send(pkt)
        s.settimeout(1)
        try:
            resp = s.recv(1024)
            h = resp.hex()
            monitor_results[name] = h
            not_ff = resp and not all(b >= 0xFE for b in resp[:8])
            if not_ff:
                print(f"  MONITOR HIT: {name} → {h[:80]}", flush=True)
        except socket.timeout:
            monitor_results[name] = "timeout"
        except Exception as re2:
            monitor_results[name] = "recv_err:" + str(re2)
        s.close()
    except OSError as ce:
        monitor_results[name] = "conn_err:" + str(ce)
results["monitor_probes"] = monitor_results

# ── 4. Full named pipe list ────────────────────────────────────────────────
pipe_raw = ps(r"[System.IO.Directory]::GetFiles('\\.\pipe\') | Select-Object -First 300")
results["all_named_pipes"] = [p.strip() for p in pipe_raw.splitlines() if p.strip()]

# ── 5. Aladdin registry tree ───────────────────────────────────────────────
results["aladdin_reg_32"] = ps(
    "Get-ChildItem 'HKLM:\\SOFTWARE\\Wow6432Node\\Aladdin' -Recurse -ErrorAction SilentlyContinue "
    "| ForEach-Object { $_.Name + ' -- ' + ($_ | Get-ItemProperty -EA SilentlyContinue | "
    "ConvertTo-Json -Compress) }"
)
results["aladdin_reg_64"] = ps(
    "Get-ChildItem 'HKLM:\\SOFTWARE\\Aladdin' -Recurse -ErrorAction SilentlyContinue "
    "| ForEach-Object { $_.Name + ' -- ' + ($_ | Get-ItemProperty -EA SilentlyContinue | "
    "ConvertTo-Json -Compress) }"
)

# ── 6. Shared memory / global objects (NtQueryDirectoryObject approach) ────
shared_mem = ps(
    r"$a=@(); Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Services' -EA SilentlyContinue | "
    r"Where-Object { $_.Name -match 'hasp|aladdin|nhsrv|aks|sentinel' } | "
    r"ForEach-Object { $a += $_.Name }; $a"
)
results["hasp_related_services"] = [l.strip() for l in shared_mem.splitlines() if l.strip()]

# ── 7. Process handle enumeration (look for shared sections/events) ────────
handles_out = ps(
    r"Get-Process nhsrvice -ErrorAction SilentlyContinue | "
    r"Select-Object Id, ProcessName, @{N='Modules';E={($_.Modules | "
    r"Select-Object -ExpandProperty ModuleName) -join ','}}"
)
results["nhsrvice_modules"] = handles_out

# ── Output ─────────────────────────────────────────────────────────────────
out_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "diagnose_out.json")
with open(out_path, "w", encoding="utf-8") as f:
    json.dump(results, f, indent=2, ensure_ascii=False)

print(f"\nDone. Results saved to: {out_path}")
print(f"Interesting TCP commands found: {len(interesting)}")
print(f"Named pipes found: {len(results['all_named_pipes'])}")
print(f"nhsrvice.exe: {nhsrv_exe}")
