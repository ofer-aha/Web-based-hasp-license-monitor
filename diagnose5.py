"""
diagnose5.py — call mightyfunc correctly + extract .hlp strings
Run on example-host: python diagnose5.py
"""
import os, json, subprocess, re, struct

results = {}
MON_DIR = r"C:\Program Files (x86)\Aladdin\Monitor"
PS32 = r"C:\Windows\SysWOW64\WindowsPowerShell\v1.0\powershell.exe"

def run_ps32(cmd, timeout=25):
    try:
        r = subprocess.run(
            [PS32, "-NoProfile", "-NonInteractive", "-Command", cmd],
            capture_output=True, text=True, timeout=timeout)
        return (r.stdout or "").strip(), (r.stderr or "").strip()
    except subprocess.TimeoutExpired:
        return "TIMEOUT", ""
    except Exception as e:
        return "ERR:" + str(e), ""

# ── 1. Load DLL + call mightyfunc via LoadLibrary/GetProcAddress ──────────────
# NOTE: use SetDllDirectory + short name (no full path escaping issues)
# NOTE: no double-backslash, use verbatim path directly

for dll_name, dll_short in [("hlmon.dll", "hlmon"), ("hsmon.dll", "hsmon")]:
    ps_script = r"""
$dir = 'C:\Program Files (x86)\Aladdin\Monitor'
Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
using System.Text;
public class WinApi {
    [DllImport("kernel32")] public static extern IntPtr LoadLibrary(string p);
    [DllImport("kernel32")] public static extern IntPtr GetProcAddress(IntPtr h, string n);
    [DllImport("kernel32")] public static extern bool SetDllDirectory(string p);
    [DllImport("kernel32")] public static extern bool FreeLibrary(IntPtr h);
    [DllImport("kernel32")] public static extern uint GetLastError();
    [DllImport("kernel32")] public static extern void RtlZeroMemory(IntPtr dest, int sz);

    // Many possible signatures for mightyfunc
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    public delegate int MF_v_C();
    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    public delegate int MF_v_S();
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    public delegate int MF_i_C(int a);
    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    public delegate int MF_i_S(int a);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    public delegate int MF_pi_C(IntPtr buf, int sz);
    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    public delegate int MF_pi_S(IntPtr buf, int sz);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    public delegate int MF_ipi_C(int a, IntPtr buf, int sz);
    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    public delegate int MF_ipi_S(int a, IntPtr buf, int sz);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    public delegate int MF_spi_C(string sv, IntPtr buf, int sz);
    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    public delegate int MF_spi_S(string sv, IntPtr buf, int sz);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    public delegate int MF_ispi_C(int a, string sv, IntPtr buf, int sz);
    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    public delegate int MF_ispi_S(int a, string sv, IntPtr buf, int sz);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    public delegate int MF_sipi_C(string sv, int a, IntPtr buf, int sz);
    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    public delegate int MF_sipi_S(string sv, int a, IntPtr buf, int sz);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    public delegate int MF_ipip_C(IntPtr p1, int a1, IntPtr p2, int a2);
    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    public delegate int MF_ipip_S(IntPtr p1, int a1, IntPtr p2, int a2);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    public delegate int MF_iipi_C(int a1, int a2, IntPtr buf, int sz);
    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    public delegate int MF_iipi_S(int a1, int a2, IntPtr buf, int sz);

    public static T GetDelegate<T>(IntPtr pfn) where T : class {
        return Marshal.GetDelegateForFunctionPointer(pfn, typeof(T)) as T;
    }
}
'@ -EA Stop

[WinApi]::SetDllDirectory($dir)
$DLLNAME = 'REPLACEME'
$h = [WinApi]::LoadLibrary("$dir\$DLLNAME")
Write-Host "LoadLibrary($DLLNAME) = $h  (err=$([WinApi]::GetLastError()))"

if ($h -ne 0 -and $h -ne [IntPtr]::Zero) {
    $pfn = [WinApi]::GetProcAddress($h, 'mightyfunc')
    Write-Host "GetProcAddress(mightyfunc) = $pfn"

    $buf = [System.Runtime.InteropServices.Marshal]::AllocHGlobal(8192)
    [System.Runtime.InteropServices.Marshal]::Copy([byte[]]::new(8192), 0, $buf, 8192)

    function ShowBuf {
        param($label, $ret, $n=128)
        $b = [byte[]]::new($n)
        [System.Runtime.InteropServices.Marshal]::Copy($buf, $b, 0, $n)
        $hex = [BitConverter]::ToString($b).Replace('-','')
        $asc = -join ($b | %{ if($_ -ge 0x20 -and $_ -lt 0x7f){[char]$_}else{'.'} })
        Write-Host "${label}: ret=$ret hex=$hex asc=$asc"
    }

    foreach ($sv in @('127.0.0.1', 'example-host', 'localhost', '')) {
        [System.Runtime.InteropServices.Marshal]::Copy([byte[]]::new(8192), 0, $buf, 8192)
        foreach ($a in @(0, 1, 2, 3, 5, 10)) {
            try {
                $d = [WinApi]::GetDelegate[WinApi+MF_v_C]($pfn)
                $r = $d.Invoke()
                ShowBuf "v_C a=$a sv=$sv" $r
            } catch {}
            try {
                $d = [WinApi]::GetDelegate[WinApi+MF_pi_C]($pfn)
                $r = $d.Invoke($buf, 8192)
                ShowBuf "pi_C a=$a sv=$sv" $r
            } catch {}
            try {
                $d = [WinApi]::GetDelegate[WinApi+MF_pi_S]($pfn)
                $r = $d.Invoke($buf, 8192)
                ShowBuf "pi_S a=$a sv=$sv" $r
            } catch {}
            try {
                $d = [WinApi]::GetDelegate[WinApi+MF_ipi_C]($pfn)
                $r = $d.Invoke($a, $buf, 8192)
                ShowBuf "ipi_C a=$a sv=$sv" $r
            } catch {}
            try {
                $d = [WinApi]::GetDelegate[WinApi+MF_ipi_S]($pfn)
                $r = $d.Invoke($a, $buf, 8192)
                ShowBuf "ipi_S a=$a sv=$sv" $r
            } catch {}
            try {
                $d = [WinApi]::GetDelegate[WinApi+MF_spi_C]($pfn)
                $r = $d.Invoke($sv, $buf, 8192)
                ShowBuf "spi_C a=$a sv=$sv" $r
            } catch {}
            try {
                $d = [WinApi]::GetDelegate[WinApi+MF_spi_S]($pfn)
                $r = $d.Invoke($sv, $buf, 8192)
                ShowBuf "spi_S a=$a sv=$sv" $r
            } catch {}
            try {
                $d = [WinApi]::GetDelegate[WinApi+MF_ispi_C]($pfn)
                $r = $d.Invoke($a, $sv, $buf, 8192)
                ShowBuf "ispi_C a=$a sv=$sv" $r
            } catch {}
            try {
                $d = [WinApi]::GetDelegate[WinApi+MF_ispi_S]($pfn)
                $r = $d.Invoke($a, $sv, $buf, 8192)
                ShowBuf "ispi_S a=$a sv=$sv" $r
            } catch {}
            try {
                $d = [WinApi]::GetDelegate[WinApi+MF_sipi_C]($pfn)
                $r = $d.Invoke($sv, $a, $buf, 8192)
                ShowBuf "sipi_C a=$a sv=$sv" $r
            } catch {}
            try {
                $d = [WinApi]::GetDelegate[WinApi+MF_sipi_S]($pfn)
                $r = $d.Invoke($sv, $a, $buf, 8192)
                ShowBuf "sipi_S a=$a sv=$sv" $r
            } catch {}
            try {
                $d = [WinApi]::GetDelegate[WinApi+MF_iipi_C]($pfn)
                $r = $d.Invoke($a, 3, $buf, 8192)
                ShowBuf "iipi_C a=$a prog=3 sv=$sv" $r
            } catch {}
            try {
                $d = [WinApi]::GetDelegate[WinApi+MF_iipi_S]($pfn)
                $r = $d.Invoke($a, 3, $buf, 8192)
                ShowBuf "iipi_S a=$a prog=3 sv=$sv" $r
            } catch {}
        }
    }
    [System.Runtime.InteropServices.Marshal]::FreeHGlobal($buf)
    [WinApi]::FreeLibrary($h) | Out-Null
}
"""
    ps_script = ps_script.replace("REPLACEME", dll_name)
    out, err = run_ps32(ps_script, timeout=30)
    results[dll_name + "_mightyfunc"] = {"out": out[:3000], "err": err[:500]}
    print(f"\n=== {dll_name} ===")
    print(out[:2000] or "(no output)")
    if err:
        print("ERR:", err[:300])

# ── 2. Extract strings from .hlp files ───────────────────────────────────────
for hlp in ["aksmon_en.hlp", "nhsrvw32.hlp"]:
    path = os.path.join(MON_DIR, hlp)
    if not os.path.exists(path):
        path = os.path.join(r"C:\Program Files (x86)\Aladdin\HASP LM", hlp)
    if os.path.exists(path):
        data = open(path, "rb").read()
        # Extract all printable ASCII strings >= 8 chars
        strs = [s.decode("ascii", errors="ignore")
                for s in re.findall(rb"[\x20-\x7e]{8,}", data)]
        results[hlp + "_strings"] = strs[:200]
        print(f"\n=== {hlp} strings (first 30) ===")
        for s in strs[:30]:
            print(" ", repr(s))

# ── 3. aksmon.exe strings (packed but try anyway) ─────────────────────────────
aksmon_path = os.path.join(MON_DIR, "aksmon.exe")
if os.path.exists(aksmon_path):
    data = open(aksmon_path, "rb").read()
    strs = [s.decode("ascii", errors="ignore")
            for s in re.findall(rb"[\x20-\x7e]{6,}", data)]
    results["aksmon_strings"] = strs[:200]
    print(f"\n=== aksmon.exe strings (first 40) ===")
    for s in strs[:40]:
        print(" ", repr(s))

# ── Output ────────────────────────────────────────────────────────────────────
out_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "diagnose5_out.json")
with open(out_path, "w", encoding="utf-8") as f:
    json.dump(results, f, indent=2, ensure_ascii=False)
print(f"\nDone → {out_path}")
