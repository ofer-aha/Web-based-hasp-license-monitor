"""
diagnose4.py — probe hlmon.dll and hsmon.dll (the actual monitor DLLs)
Run on example-host: python diagnose4.py
"""
import os, json, struct, subprocess, re

results = {}
MON_DIR = r"C:\Program Files (x86)\Aladdin\Monitor"
LM_DIR  = r"C:\Program Files (x86)\Aladdin\HASP LM"

# ── 1. Read ini files ─────────────────────────────────────────────────────────
for ini in [os.path.join(MON_DIR, "nethasp.ini"),
            os.path.join(LM_DIR,  "nhsrv.ini")]:
    if os.path.exists(ini):
        try:
            results[os.path.basename(ini)] = open(ini, "r",
                encoding="utf-8", errors="ignore").read()
        except Exception as e:
            results[os.path.basename(ini)] = str(e)

# ── 2. Parse PE exports ───────────────────────────────────────────────────────
def get_exports(path):
    try:
        data = open(path, "rb").read()
        pe_off = struct.unpack_from("<I", data, 0x3C)[0]
        if data[pe_off:pe_off+4] != b"PE\x00\x00":
            return [], "not_pe"
        opt_off = pe_off + 24
        opt_size = struct.unpack_from("<H", data, pe_off + 20)[0]
        export_rva  = struct.unpack_from("<I", data, opt_off + 96)[0]
        export_size = struct.unpack_from("<I", data, opt_off + 100)[0]
        if not export_rva:
            return [], "no_export_dir"
        num_sects = struct.unpack_from("<H", data, pe_off + 6)[0]
        sect_base = pe_off + 24 + opt_size
        sects = []
        for i in range(num_sects):
            s = sect_base + i * 40
            va  = struct.unpack_from("<I", data, s + 12)[0]
            vsz = struct.unpack_from("<I", data, s + 16)[0]
            raw = struct.unpack_from("<I", data, s + 20)[0]
            sects.append((va, vsz, raw))

        def r2o(rva):
            for va, vsz, raw in sects:
                if va <= rva < va + vsz:
                    return raw + (rva - va)
            return None

        eo = r2o(export_rva)
        if eo is None:
            return [], "rva_not_mapped"
        num_names = struct.unpack_from("<I", data, eo + 24)[0]
        num_funcs = struct.unpack_from("<I", data, eo + 20)[0]
        rva_names = struct.unpack_from("<I", data, eo + 32)[0]
        rva_ords  = struct.unpack_from("<I", data, eo + 36)[0]
        rva_funcs = struct.unpack_from("<I", data, eo + 28)[0]
        base_ord  = struct.unpack_from("<I", data, eo + 16)[0]

        exports = []
        no = r2o(rva_names); oo = r2o(rva_ords); fo = r2o(rva_funcs)
        named = set()
        if no and oo and fo:
            for i in range(num_names):
                n_rva = struct.unpack_from("<I", data, no + i*4)[0]
                ord_i = struct.unpack_from("<H", data, oo + i*2)[0]
                f_rva = struct.unpack_from("<I", data, fo + ord_i*4)[0]
                noff  = r2o(n_rva)
                if noff:
                    end  = data.index(b"\x00", noff)
                    name = data[noff:end].decode("ascii", errors="ignore")
                    exports.append({
                        "name": name,
                        "ordinal": base_ord + ord_i,
                        "rva": hex(f_rva)
                    })
                    named.add(ord_i)
        if fo:
            for i in range(num_funcs):
                if i not in named:
                    f_rva = struct.unpack_from("<I", data, fo + i*4)[0]
                    if f_rva:
                        exports.append({
                            "name": None,
                            "ordinal": base_ord + i,
                            "rva": hex(f_rva)
                        })
        return exports, "ok"
    except Exception as e:
        return [], str(e)

for dll_name in ["hlmon.dll", "hsmon.dll", "aksmon_ge.dll", "nhlminst.dll"]:
    path = os.path.join(MON_DIR, dll_name)
    if os.path.exists(path):
        exp, status = get_exports(path)
        results[dll_name + "_exports"] = {"status": status, "exports": exp}

# ── 3. Call hlmon.dll and hsmon.dll via 32-bit PowerShell ────────────────────
PS32 = r"C:\Windows\SysWOW64\WindowsPowerShell\v1.0\powershell.exe"

def run_ps32(cmd, timeout=20):
    try:
        r = subprocess.run(
            [PS32, "-NoProfile", "-NonInteractive", "-Command", cmd],
            capture_output=True, text=True, timeout=timeout)
        return (r.stdout or "").strip(), (r.stderr or "").strip()
    except subprocess.TimeoutExpired:
        return "TIMEOUT", ""
    except Exception as e:
        return "ERR:" + str(e), ""

# Build P/Invoke callers for each discovered export
for dll_name in ["hlmon.dll", "hsmon.dll"]:
    key = dll_name + "_exports"
    if key not in results:
        continue
    named_exports = [e for e in results[key]["exports"] if e["name"]]
    results[dll_name + "_calls"] = {}

    dll_path = os.path.join(MON_DIR, dll_name).replace("\\", "\\\\")

    for export in named_exports:
        fname = export["name"]
        # Try calling with no args, then (int,IntPtr,int), then (string,IntPtr,int)
        # Use cdecl and stdcall variants

        cs = f"""
try {{
Add-Type -TypeDefinition @'
using System; using System.Runtime.InteropServices; using System.Text;
public class MonCall {{
  [DllImport(@"{dll_path}", EntryPoint="{fname}", CallingConvention=CallingConvention.Cdecl)]
  public static extern int Call_C0();
  [DllImport(@"{dll_path}", EntryPoint="{fname}", CallingConvention=CallingConvention.StdCall)]
  public static extern int Call_S0();
  [DllImport(@"{dll_path}", EntryPoint="{fname}", CallingConvention=CallingConvention.Cdecl)]
  public static extern int Call_C1(IntPtr buf, int sz);
  [DllImport(@"{dll_path}", EntryPoint="{fname}", CallingConvention=CallingConvention.StdCall)]
  public static extern int Call_S1(IntPtr buf, int sz);
  [DllImport(@"{dll_path}", EntryPoint="{fname}", CallingConvention=CallingConvention.Cdecl)]
  public static extern int Call_C2([MarshalAs(UnmanagedType.LPStr)] string sv, IntPtr buf, int sz);
  [DllImport(@"{dll_path}", EntryPoint="{fname}", CallingConvention=CallingConvention.StdCall)]
  public static extern int Call_S2([MarshalAs(UnmanagedType.LPStr)] string sv, IntPtr buf, int sz);
}}
'@ -EA SilentlyContinue
}} catch {{}}

$buf = [System.Runtime.InteropServices.Marshal]::AllocHGlobal(4096)
[System.Runtime.InteropServices.Marshal]::Copy([byte[]]::new(4096), 0, $buf, 4096)
$results = @()
foreach ($sv in @("127.0.0.1", "example-host", "", "localhost")) {{
  try {{ $r=[MonCall]::Call_C0(); $b=[byte[]]::new(64); [System.Runtime.InteropServices.Marshal]::Copy($buf,0,$b,0,64); $results += "C0_ret="+$r+" "+[BitConverter]::ToString($b).Replace('-','') }} catch {{}}
  try {{ $r=[MonCall]::Call_S0(); $b=[byte[]]::new(64); [System.Runtime.InteropServices.Marshal]::Copy($buf,0,$b,0,64); $results += "S0_ret="+$r+" "+[BitConverter]::ToString($b).Replace('-','') }} catch {{}}
  try {{ $r=[MonCall]::Call_C1($buf,4096); $b=[byte[]]::new(64); [System.Runtime.InteropServices.Marshal]::Copy($buf,0,$b,0,64); $results += "C1_ret="+$r+" sv=$sv "+[BitConverter]::ToString($b).Replace('-','') }} catch {{}}
  try {{ $r=[MonCall]::Call_S1($buf,4096); $b=[byte[]]::new(64); [System.Runtime.InteropServices.Marshal]::Copy($buf,0,$b,0,64); $results += "S1_ret="+$r+" sv=$sv "+[BitConverter]::ToString($b).Replace('-','') }} catch {{}}
  try {{ $r=[MonCall]::Call_C2($sv,$buf,4096); $b=[byte[]]::new(64); [System.Runtime.InteropServices.Marshal]::Copy($buf,0,$b,0,64); $results += "C2_ret="+$r+" sv=$sv "+[BitConverter]::ToString($b).Replace('-','') }} catch {{}}
  try {{ $r=[MonCall]::Call_S2($sv,$buf,4096); $b=[byte[]]::new(64); [System.Runtime.InteropServices.Marshal]::Copy($buf,0,$b,0,64); $results += "S2_ret="+$r+" sv=$sv "+[BitConverter]::ToString($b).Replace('-','') }} catch {{}}
}}
[System.Runtime.InteropServices.Marshal]::FreeHGlobal($buf)
$results
"""
        out, err = run_ps32(cs, timeout=15)
        # Look for non-zero return values or non-zero buffer contents
        if out and "TIMEOUT" not in out:
            results[dll_name + "_calls"][fname] = {
                "out": out[:800],
                "err": err[:200] if err else ""
            }
        else:
            results[dll_name + "_calls"][fname] = "no_output"

# ── 4. Check hls32svc.exe ─────────────────────────────────────────────────────
out, _ = run_ps32(
    "Get-Process hls32svc -EA SilentlyContinue | Select Id,ProcessName,@{N='S';E={$_.SessionId}}")
results["hls32svc_running"] = out

# ── Output ────────────────────────────────────────────────────────────────────
out_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "diagnose4_out.json")
with open(out_path, "w", encoding="utf-8") as f:
    json.dump(results, f, indent=2, ensure_ascii=False)

print(f"\nDone → {out_path}")
for dll in ["hlmon.dll", "hsmon.dll"]:
    exp = results.get(dll+"_exports", {}).get("exports", [])
    print(f"{dll} exports: {[e['name'] for e in exp if e['name']]}")
for dll in ["hlmon.dll", "hsmon.dll"]:
    calls = results.get(dll+"_calls", {})
    for fn, val in calls.items():
        if isinstance(val, dict) and val.get("out") and val["out"] != "no_output":
            print(f"  HIT: {dll}::{fn} → {val['out'][:200]}")
