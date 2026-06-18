"""
diagnose7.py
1. Extract string literals from hsmon.dll → find valid command names
2. Compile 32-bit C# probe that passes arg3 as IntPtr (pointer to int)
3. Try every extracted string + known candidates as commands
Run on example-host: python diagnose7.py
"""
import os, json, re, struct, subprocess

results = {}
MON_DIR = r"C:\Program Files (x86)\Aladdin\Monitor"

# ── 1. Extract strings from hsmon.dll + hlmon.dll ────────────────────────────
def extract_strings(path, min_len=4):
    data = open(path, "rb").read()
    return [s.decode("ascii", errors="ignore")
            for s in re.findall(rb"[\x20-\x7e]{" + str(min_len).encode() + rb",}", data)]

for dll in ["hsmon.dll", "hlmon.dll"]:
    path = os.path.join(MON_DIR, dll)
    if os.path.exists(path):
        strs = extract_strings(path)
        results[dll + "_strings"] = strs
        print(f"\n=== {dll} strings ({len(strs)} total, showing all) ===")
        for s in strs:
            print(" ", repr(s))

# ── 2. Build command candidate list ──────────────────────────────────────────
# Pull identifiers from the strings: things that look like function/command names
# (all-caps or MixedCase, no spaces, 3-30 chars)
raw_cmds = set()
for dll in ["hsmon.dll", "hlmon.dll"]:
    for s in results.get(dll + "_strings", []):
        # Look for word-like tokens: letters + underscore, possibly digits
        for tok in re.findall(r'[A-Za-z_][A-Za-z0-9_]{2,29}', s):
            raw_cmds.add(tok)

# Also add hardcoded candidates from NetHASP/aksmon knowledge
hard = [
    # NetHASP monitor commands (guesses from protocol analysis)
    "LMINFO", "LMSTAT", "CLIENTS", "SESSIONS", "STATUS", "INFO", "VERSION",
    "GET_CLIENTS", "GET_SESSIONS", "GET_INFO", "GET_STATUS", "GET_VERSION",
    "SERVERINFO", "SERVER_INFO", "SERVER_STATUS", "NHINFO", "NHSTAT",
    "LISTCLIENTS", "LIST_CLIENTS", "ACTIVE_CLIENTS", "ACTIVE",
    "PROGRAMS", "PROG_INFO", "PROGINFO", "PROG", "PROGRAM",
    "USERS", "USER_LIST", "USERLIST", "WHO", "WHOAMI",
    "DUMP", "DUMP_ALL", "ALL",
    # From nhsrvw32.hlp strings
    "LPLMINFO", "CREATE", "INSTALL", "REMOVE",
    # Protocol-level
    "GETINFO", "GET_LMINFO", "GETLMINFO", "GETSTAT", "GETCLIENTS",
    "GETSESSIONS", "GETSTATUS", "GETVERSION", "GETALL", "GETUSERS",
    # HL-Server commands (from hlmon.dll pattern)
    "GET_HL_CLIENTS", "HLSTAT", "HLINFO", "HL_STATUS", "HL_INFO",
    # Numbers and short codes
    "1", "2", "3", "0",
]
candidates = sorted(raw_cmds) + [c for c in hard if c not in raw_cmds]
results["command_candidates"] = candidates
print(f"\n{len(candidates)} command candidates total")

# ── 3. Compile 32-bit C# probe ────────────────────────────────────────────────
# Key fix: try both (string, IntPtr, int) AND (string, IntPtr, IntPtr)
# For hsmon.dll arg3 is dereferenced → need IntPtr pointing to int(8192)

# Embed candidate list as C# array literal (escape quotes, limit to 200)
def cs_str_array(lst):
    escaped = [s.replace("\\", "\\\\").replace('"', '\\"') for s in lst[:200]]
    return "new string[] { " + ", ".join(f'"{s}"' for s in escaped) + " }"

cs_cmds = cs_str_array(candidates)

cs_src = f"""
using System;
using System.Runtime.InteropServices;
using System.Runtime.ExceptionServices;
using System.Security;

class Probe7 {{
    [DllImport("kernel32")] static extern IntPtr LoadLibraryA(string p);
    [DllImport("kernel32")] static extern IntPtr GetProcAddress(IntPtr h, string n);
    [DllImport("kernel32")] static extern bool SetDllDirectory(string p);

    // (string, IntPtr, int) — worked for hlmon.dll
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    delegate int Dspi_C([MarshalAs(UnmanagedType.LPStr)] string cmd, IntPtr buf, int sz);
    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    delegate int Dspi_S([MarshalAs(UnmanagedType.LPStr)] string cmd, IntPtr buf, int sz);

    // (string, IntPtr, IntPtr) — fix for hsmon.dll where arg3 is dereferenced
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    delegate int Dspp_C([MarshalAs(UnmanagedType.LPStr)] string cmd, IntPtr buf, IntPtr pSz);
    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    delegate int Dspp_S([MarshalAs(UnmanagedType.LPStr)] string cmd, IntPtr buf, IntPtr pSz);

    // (IntPtr, IntPtr, IntPtr) — in case cmd is also a pointer to struct
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    delegate int Dppp_C(IntPtr p1, IntPtr buf, IntPtr pSz);
    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    delegate int Dppp_S(IntPtr p1, IntPtr buf, IntPtr pSz);

    // (IntPtr, IntPtr, int) — buf ptr + buf sz
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    delegate int Dpi_C(IntPtr buf, int sz);
    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    delegate int Dpi_S(IntPtr buf, int sz);

    // (IntPtr, IntPtr) — two ptrs, no size
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    delegate int Dpp_C(IntPtr p1, IntPtr p2);
    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    delegate int Dpp_S(IntPtr p1, IntPtr p2);

    static void ShowBuf(string lbl, int ret, IntPtr buf, IntPtr pSz) {{
        int actual = (pSz != IntPtr.Zero) ? Marshal.ReadInt32(pSz) : 0;
        int show = Math.Min(actual > 0 ? actual : 128, 512);
        byte[] b = new byte[show];
        if (show > 0) Marshal.Copy(buf, b, 0, show);
        bool nonzero = false;
        foreach(byte x in b) if(x!=0){{nonzero=true;break;}}
        if(ret != 0 || nonzero) {{
            string h = BitConverter.ToString(b, 0, Math.Min(b.Length,48)).Replace("-","");
            string a = ""; foreach(byte x in b) a += (x>=0x20&&x<0x7f)?(char)x:'.';
            Console.WriteLine(lbl+" ret="+ret+(actual>0?" sz="+actual:"")+" | "+a.Substring(0,Math.Min(a.Length,80)));
        }}
    }}

    static void Clear(IntPtr buf, int n) {{
        byte[] z = new byte[n];
        Marshal.Copy(z, 0, buf, n);
    }}

    [HandleProcessCorruptedStateExceptions][SecurityCritical]
    static void Probe(string dllName, IntPtr pfn, string[] cmds) {{
        IntPtr buf = Marshal.AllocHGlobal(8192);
        IntPtr pSz = Marshal.AllocHGlobal(8);
        IntPtr cmdBuf = Marshal.AllocHGlobal(256);

        foreach(string cmd in cmds) {{
            Clear(buf, 8192);
            Marshal.WriteInt32(pSz, 0, 8192);
            Marshal.WriteInt32(pSz, 4, 0);

            // Write cmd into cmdBuf as ANSI
            byte[] cb = System.Text.Encoding.ASCII.GetBytes(cmd + "\\0");
            Marshal.Copy(cb, 0, cmdBuf, Math.Min(cb.Length, 255));

            string lbl = dllName + " cmd=" + cmd;

            try {{ ShowBuf("Dspi_C "+lbl, ((Dspi_C)Marshal.GetDelegateForFunctionPointer(pfn,typeof(Dspi_C)))(cmd,buf,8192), buf, IntPtr.Zero); }} catch{{}}
            Clear(buf,8192); Marshal.WriteInt32(pSz,0,8192);
            try {{ ShowBuf("Dspi_S "+lbl, ((Dspi_S)Marshal.GetDelegateForFunctionPointer(pfn,typeof(Dspi_S)))(cmd,buf,8192), buf, IntPtr.Zero); }} catch{{}}
            Clear(buf,8192); Marshal.WriteInt32(pSz,0,8192);
            try {{ ShowBuf("Dspp_C "+lbl, ((Dspp_C)Marshal.GetDelegateForFunctionPointer(pfn,typeof(Dspp_C)))(cmd,buf,pSz), buf, pSz); }} catch{{}}
            Clear(buf,8192); Marshal.WriteInt32(pSz,0,8192);
            try {{ ShowBuf("Dspp_S "+lbl, ((Dspp_S)Marshal.GetDelegateForFunctionPointer(pfn,typeof(Dspp_S)))(cmd,buf,pSz), buf, pSz); }} catch{{}}
            Clear(buf,8192); Marshal.WriteInt32(pSz,0,8192);
            try {{ ShowBuf("Dppp_C "+lbl, ((Dppp_C)Marshal.GetDelegateForFunctionPointer(pfn,typeof(Dppp_C)))(cmdBuf,buf,pSz), buf, pSz); }} catch{{}}
            Clear(buf,8192); Marshal.WriteInt32(pSz,0,8192);
            try {{ ShowBuf("Dppp_S "+lbl, ((Dppp_S)Marshal.GetDelegateForFunctionPointer(pfn,typeof(Dppp_S)))(cmdBuf,buf,pSz), buf, pSz); }} catch{{}}
        }}

        // Also try no-command variants
        Clear(buf,8192); Marshal.WriteInt32(pSz,0,8192);
        try {{ ShowBuf("Dpi_C "+dllName, ((Dpi_C)Marshal.GetDelegateForFunctionPointer(pfn,typeof(Dpi_C)))(buf,8192), buf, IntPtr.Zero); }} catch{{}}
        Clear(buf,8192); Marshal.WriteInt32(pSz,0,8192);
        try {{ ShowBuf("Dpi_S "+dllName, ((Dpi_S)Marshal.GetDelegateForFunctionPointer(pfn,typeof(Dpi_S)))(buf,8192), buf, IntPtr.Zero); }} catch{{}}
        Clear(buf,8192); Marshal.WriteInt32(pSz,0,8192);
        try {{ ShowBuf("Dpp_C "+dllName, ((Dpp_C)Marshal.GetDelegateForFunctionPointer(pfn,typeof(Dpp_C)))(buf,pSz), buf, pSz); }} catch{{}}
        Clear(buf,8192); Marshal.WriteInt32(pSz,0,8192);
        try {{ ShowBuf("Dpp_S "+dllName, ((Dpp_S)Marshal.GetDelegateForFunctionPointer(pfn,typeof(Dpp_S)))(buf,pSz), buf, pSz); }} catch{{}}

        Marshal.FreeHGlobal(buf);
        Marshal.FreeHGlobal(pSz);
        Marshal.FreeHGlobal(cmdBuf);
    }}

    static void Main() {{
        string dir = @"C:\\Program Files (x86)\\Aladdin\\Monitor";
        SetDllDirectory(dir);
        string[] cmds = {cs_cmds};

        foreach(string dll in new[]{{ "hsmon.dll", "hlmon.dll" }}) {{
            Console.WriteLine("=== " + dll + " ===");
            IntPtr h = LoadLibraryA(dir + "\\\\" + dll);
            Console.WriteLine("h=" + (long)h + " err=" + Marshal.GetLastWin32Error());
            if(h == IntPtr.Zero) continue;
            IntPtr pfn = GetProcAddress(h, "mightyfunc");
            Console.WriteLine("pfn=" + (long)pfn);
            if(pfn == IntPtr.Zero) continue;
            Probe(dll, pfn, cmds);
        }}
        Console.WriteLine("DONE");
    }}
}}
"""

script_dir = os.path.dirname(os.path.abspath(__file__))
cs_path = os.path.join(script_dir, "probe7.cs")
exe_path = os.path.join(script_dir, "probe7.exe")
with open(cs_path, "w") as f:
    f.write(cs_src)

csc = r"C:\Windows\Microsoft.NET\Framework\v4.0.30319\csc.exe"
r = subprocess.run([csc, "/nologo", "/platform:x86", "/optimize+",
                    f"/out:{exe_path}", cs_path],
                   capture_output=True, text=True, timeout=30)
print(f"\nCompile: rc={r.returncode}")
if r.stderr: print("STDERR:", r.stderr[:400])

if r.returncode == 0:
    r2 = subprocess.run([exe_path], capture_output=True, text=True, timeout=120)
    out = r2.stdout or ""
    err = r2.stderr or ""
    results["probe7_output"] = out[:8000]
    results["probe7_stderr"] = err[:500]
    print("\n=== PROBE OUTPUT ===")
    print(out[:6000] or "(no output)")
    if err: print("ERR:", err[:200])
else:
    results["compile_error"] = r.stderr

out_path = os.path.join(script_dir, "diagnose7_out.json")
with open(out_path, "w", encoding="utf-8") as f:
    json.dump(results, f, indent=2, ensure_ascii=False)
print(f"\nDone → {out_path}")
