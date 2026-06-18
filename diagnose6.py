"""
diagnose6.py — disassemble mightyfunc + compile 32-bit C# probe
Run on example-host: python diagnose6.py
"""
import os, json, struct, re, subprocess, tempfile

results = {}
MON_DIR = r"C:\Program Files (x86)\Aladdin\Monitor"

# ── PE helpers ────────────────────────────────────────────────────────────────
def parse_pe(path):
    data = open(path, "rb").read()
    pe_off = struct.unpack_from("<I", data, 0x3C)[0]
    assert data[pe_off:pe_off+4] == b"PE\x00\x00"
    opt_off = pe_off + 24
    opt_size = struct.unpack_from("<H", data, pe_off + 20)[0]
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

    return data, opt_off, opt_size, sects, r2o

# ── 1. Imports of hsmon.dll and hlmon.dll ─────────────────────────────────────
for dll_name in ["hsmon.dll", "hlmon.dll"]:
    path = os.path.join(MON_DIR, dll_name)
    if not os.path.exists(path):
        continue
    try:
        data, opt_off, opt_size, sects, r2o = parse_pe(path)
        import_rva  = struct.unpack_from("<I", data, opt_off + 104)[0]
        imports = []
        if import_rva:
            off = r2o(import_rva)
            while off and off < len(data):
                orig_thunk = struct.unpack_from("<I", data, off)[0]
                name_rva   = struct.unpack_from("<I", data, off + 12)[0]
                first_thunk= struct.unpack_from("<I", data, off + 16)[0]
                if not name_rva:
                    break
                noff = r2o(name_rva)
                if noff is None:
                    break
                end = data.index(b"\x00", noff)
                dll_dep = data[noff:end].decode("ascii", errors="ignore")
                funcs = []
                lt = r2o(orig_thunk or first_thunk)
                if lt:
                    while lt < len(data):
                        rva = struct.unpack_from("<I", data, lt)[0]
                        if not rva:
                            break
                        if rva & 0x80000000:
                            funcs.append(f"Ordinal#{rva & 0x7fff}")
                        else:
                            fo = r2o(rva)
                            if fo:
                                end2 = data.index(b"\x00", fo + 2)
                                funcs.append(data[fo+2:end2].decode("ascii", errors="ignore"))
                        lt += 4
                imports.append({"dll": dll_dep, "funcs": funcs})
                off += 20
        results[dll_name + "_imports"] = imports
    except Exception as e:
        results[dll_name + "_imports"] = str(e)

# ── 2. Dump raw bytes of mightyfunc ──────────────────────────────────────────
for dll_name, mf_rva in [("hsmon.dll", 0x69fb), ("hlmon.dll", 0xb6bb)]:
    path = os.path.join(MON_DIR, dll_name)
    if not os.path.exists(path):
        continue
    try:
        data, _, _, _, r2o = parse_pe(path)
        off = r2o(mf_rva)
        if off:
            raw = data[off:off+256]
            results[dll_name + "_mightyfunc_bytes"] = raw.hex()
            # Simple disassembly hints
            print(f"\n=== {dll_name} mightyfunc raw bytes (first 96) ===")
            for i in range(0, min(96, len(raw)), 16):
                h = " ".join(f"{b:02x}" for b in raw[i:i+16])
                a = "".join(chr(b) if 0x20<=b<0x7f else "." for b in raw[i:i+16])
                print(f"  +{i:04x}: {h:<48}  {a}")
    except Exception as e:
        results[dll_name + "_mightyfunc_bytes"] = str(e)

# ── 3. Compile 32-bit C# probe ────────────────────────────────────────────────
cs_src = r"""
using System;
using System.Runtime.InteropServices;
using System.Runtime.ExceptionServices;
using System.Security;

class Probe {
    [DllImport("kernel32")] static extern IntPtr LoadLibraryA(string p);
    [DllImport("kernel32")] static extern IntPtr GetProcAddress(IntPtr h, string n);
    [DllImport("kernel32")] static extern bool SetDllDirectory(string p);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]   delegate int D0_C();
    [UnmanagedFunctionPointer(CallingConvention.StdCall)] delegate int D0_S();
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]   delegate int Dpi_C(IntPtr buf, int sz);
    [UnmanagedFunctionPointer(CallingConvention.StdCall)] delegate int Dpi_S(IntPtr buf, int sz);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]   delegate int Dipi_C(int a, IntPtr buf, int sz);
    [UnmanagedFunctionPointer(CallingConvention.StdCall)] delegate int Dipi_S(int a, IntPtr buf, int sz);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]   delegate int Dspi_C([MarshalAs(UnmanagedType.LPStr)]string sv, IntPtr buf, int sz);
    [UnmanagedFunctionPointer(CallingConvention.StdCall)] delegate int Dspi_S([MarshalAs(UnmanagedType.LPStr)]string sv, IntPtr buf, int sz);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]   delegate int Dispi_C(int a, [MarshalAs(UnmanagedType.LPStr)]string sv, IntPtr buf, int sz);
    [UnmanagedFunctionPointer(CallingConvention.StdCall)] delegate int Dispi_S(int a, [MarshalAs(UnmanagedType.LPStr)]string sv, IntPtr buf, int sz);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]   delegate int Dsipi_C([MarshalAs(UnmanagedType.LPStr)]string sv, int a, IntPtr buf, int sz);
    [UnmanagedFunctionPointer(CallingConvention.StdCall)] delegate int Dsipi_S([MarshalAs(UnmanagedType.LPStr)]string sv, int a, IntPtr buf, int sz);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]   delegate int Diipi_C(int a1, int a2, IntPtr buf, int sz);
    [UnmanagedFunctionPointer(CallingConvention.StdCall)] delegate int Diipi_S(int a1, int a2, IntPtr buf, int sz);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]   delegate int Dpiii_C(IntPtr buf, int a1, int a2, int a3);
    [UnmanagedFunctionPointer(CallingConvention.StdCall)] delegate int Dpiii_S(IntPtr buf, int a1, int a2, int a3);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]   delegate int Dpipi_C(IntPtr p1, int a1, IntPtr p2, int a2);
    [UnmanagedFunctionPointer(CallingConvention.StdCall)] delegate int Dpipi_S(IntPtr p1, int a1, IntPtr p2, int a2);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]   delegate int Dsiipi_C([MarshalAs(UnmanagedType.LPStr)]string sv, int a1, int a2, IntPtr buf, int sz);
    [UnmanagedFunctionPointer(CallingConvention.StdCall)] delegate int Dsiipi_S([MarshalAs(UnmanagedType.LPStr)]string sv, int a1, int a2, IntPtr buf, int sz);

    static void ShowBuf(string lbl, int ret, IntPtr buf) {
        byte[] b = new byte[64];
        Marshal.Copy(buf, b, 0, 64);
        string h = BitConverter.ToString(b).Replace("-","");
        string a = ""; foreach(byte x in b) a += (x>=0x20&&x<0x7f)?(char)x:'.';
        // Only print if ret != 0 or buffer is non-zero
        bool nonzero = false;
        foreach(byte x in b) if(x!=0){nonzero=true;break;}
        if(ret != 0 || nonzero)
            Console.WriteLine(lbl + " ret=" + ret + " buf=" + h.Substring(0,80) + " asc=" + a.Substring(0,40));
    }

    [HandleProcessCorruptedStateExceptions][SecurityCritical]
    static void Run(IntPtr pfn, IntPtr buf, string sv, int a1, int a2) {
        for(int i=0;i<8192;i++) Marshal.WriteByte(buf, i, 0);
        string lbl = "sv="+sv+" a1="+a1+" a2="+a2;
        try { ShowBuf("D0_C "+lbl,    ((D0_C)Marshal.GetDelegateForFunctionPointer(pfn,typeof(D0_C)))(),buf); } catch{}
        try { ShowBuf("D0_S "+lbl,    ((D0_S)Marshal.GetDelegateForFunctionPointer(pfn,typeof(D0_S)))(),buf); } catch{}
        try { ShowBuf("Dpi_C "+lbl,   ((Dpi_C)Marshal.GetDelegateForFunctionPointer(pfn,typeof(Dpi_C)))(buf,8192),buf); } catch{}
        try { ShowBuf("Dpi_S "+lbl,   ((Dpi_S)Marshal.GetDelegateForFunctionPointer(pfn,typeof(Dpi_S)))(buf,8192),buf); } catch{}
        try { ShowBuf("Dipi_C "+lbl,  ((Dipi_C)Marshal.GetDelegateForFunctionPointer(pfn,typeof(Dipi_C)))(a1,buf,8192),buf); } catch{}
        try { ShowBuf("Dipi_S "+lbl,  ((Dipi_S)Marshal.GetDelegateForFunctionPointer(pfn,typeof(Dipi_S)))(a1,buf,8192),buf); } catch{}
        try { ShowBuf("Dpiii_C "+lbl, ((Dpiii_C)Marshal.GetDelegateForFunctionPointer(pfn,typeof(Dpiii_C)))(buf,a1,a2,3),buf); } catch{}
        try { ShowBuf("Dpiii_S "+lbl, ((Dpiii_S)Marshal.GetDelegateForFunctionPointer(pfn,typeof(Dpiii_S)))(buf,a1,a2,3),buf); } catch{}
        try { ShowBuf("Diipi_C "+lbl, ((Diipi_C)Marshal.GetDelegateForFunctionPointer(pfn,typeof(Diipi_C)))(a1,a2,buf,8192),buf); } catch{}
        try { ShowBuf("Diipi_S "+lbl, ((Diipi_S)Marshal.GetDelegateForFunctionPointer(pfn,typeof(Diipi_S)))(a1,a2,buf,8192),buf); } catch{}
        if(sv.Length>0) {
            try { ShowBuf("Dspi_C "+lbl,  ((Dspi_C)Marshal.GetDelegateForFunctionPointer(pfn,typeof(Dspi_C)))(sv,buf,8192),buf); } catch{}
            try { ShowBuf("Dspi_S "+lbl,  ((Dspi_S)Marshal.GetDelegateForFunctionPointer(pfn,typeof(Dspi_S)))(sv,buf,8192),buf); } catch{}
            try { ShowBuf("Dispi_C "+lbl, ((Dispi_C)Marshal.GetDelegateForFunctionPointer(pfn,typeof(Dispi_C)))(a1,sv,buf,8192),buf); } catch{}
            try { ShowBuf("Dispi_S "+lbl, ((Dispi_S)Marshal.GetDelegateForFunctionPointer(pfn,typeof(Dispi_S)))(a1,sv,buf,8192),buf); } catch{}
            try { ShowBuf("Dsipi_C "+lbl, ((Dsipi_C)Marshal.GetDelegateForFunctionPointer(pfn,typeof(Dsipi_C)))(sv,a1,buf,8192),buf); } catch{}
            try { ShowBuf("Dsipi_S "+lbl, ((Dsipi_S)Marshal.GetDelegateForFunctionPointer(pfn,typeof(Dsipi_S)))(sv,a1,buf,8192),buf); } catch{}
            try { ShowBuf("Dsiipi_C "+lbl,((Dsiipi_C)Marshal.GetDelegateForFunctionPointer(pfn,typeof(Dsiipi_C)))(sv,a1,a2,buf,8192),buf); } catch{}
            try { ShowBuf("Dsiipi_S "+lbl,((Dsiipi_S)Marshal.GetDelegateForFunctionPointer(pfn,typeof(Dsiipi_S)))(sv,a1,a2,buf,8192),buf); } catch{}
        }
    }

    static void Main() {
        string dir = @"C:\Program Files (x86)\Aladdin\Monitor";
        SetDllDirectory(dir);
        foreach(string dll in new[]{"hsmon.dll","hlmon.dll"}) {
            Console.WriteLine("=== " + dll + " ===");
            IntPtr h = LoadLibraryA(dir + @"\" + dll);
            Console.WriteLine("LoadLibrary=" + (long)h +
                              " err=" + Marshal.GetLastWin32Error());
            if(h == IntPtr.Zero) continue;
            IntPtr pfn = GetProcAddress(h, "mightyfunc");
            Console.WriteLine("mightyfunc=" + (long)pfn);
            if(pfn == IntPtr.Zero) continue;
            IntPtr buf = Marshal.AllocHGlobal(8192);
            foreach(string sv in new[]{"127.0.0.1","example-host",""}) {
                foreach(int a1 in new[]{0,1,2,3,5,10}) {
                    foreach(int a2 in new[]{0,1,2,3}) {
                        Run(pfn, buf, sv, a1, a2);
                    }
                }
            }
            Marshal.FreeHGlobal(buf);
        }
        Console.WriteLine("DONE");
    }
}
"""

# Write .cs file
cs_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "probe_mf.cs")
exe_path = cs_path.replace(".cs", ".exe")
with open(cs_path, "w") as f:
    f.write(cs_src)

# Find 32-bit csc.exe
csc = None
for candidate in [
    r"C:\Windows\Microsoft.NET\Framework\v4.0.30319\csc.exe",
    r"C:\Windows\Microsoft.NET\Framework\v3.5\csc.exe",
    r"C:\Windows\Microsoft.NET\Framework\v2.0.50727\csc.exe",
]:
    if os.path.exists(candidate):
        csc = candidate
        break

results["csc_path"] = csc

if csc:
    # Compile as x86 (AnyCPU would run 64-bit on 64-bit OS and fail to load 32-bit DLLs)
    compile_result = subprocess.run(
        [csc, "/nologo", "/platform:x86", "/optimize+",
         f"/out:{exe_path}", cs_path],
        capture_output=True, text=True, timeout=30)
    results["compile_stdout"] = compile_result.stdout[:500]
    results["compile_stderr"] = compile_result.stderr[:500]
    print("Compile:", compile_result.returncode,
          compile_result.stdout[:200], compile_result.stderr[:200])

    if compile_result.returncode == 0 and os.path.exists(exe_path):
        # Run the compiled 32-bit exe
        run_result = subprocess.run(
            [exe_path], capture_output=True, text=True, timeout=60)
        out = run_result.stdout or ""
        results["probe_output"] = out[:5000]
        results["probe_stderr"] = (run_result.stderr or "")[:500]
        print("\n=== PROBE OUTPUT ===")
        print(out[:3000] or "(no output)")
        if run_result.stderr:
            print("ERR:", run_result.stderr[:200])
    else:
        results["probe_error"] = "compile failed"
else:
    results["probe_error"] = "csc.exe not found"

# ── Output ────────────────────────────────────────────────────────────────────
out_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "diagnose6_out.json")
with open(out_path, "w", encoding="utf-8") as f:
    json.dump(results, f, indent=2, ensure_ascii=False)
print(f"\nDone → {out_path}")

# Print imports summary
for dll in ["hsmon.dll", "hlmon.dll"]:
    imps = results.get(dll+"_imports", [])
    print(f"\n{dll} imports:")
    for imp in imps:
        print(f"  {imp['dll']}: {imp['funcs'][:6]}")
