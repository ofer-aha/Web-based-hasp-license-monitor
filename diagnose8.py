"""
diagnose8.py — call the EXACT hsmon.dll commands to get active HASP logins
Run on example-host: python diagnose8.py
"""
import os, json, re, subprocess

results = {}
MON_DIR = r"C:\Program Files (x86)\Aladdin\Monitor"

# ── Compile 32-bit C# that runs the full query sequence ─────────────────────
cs_src = r"""
using System;
using System.Runtime.InteropServices;
using System.Runtime.ExceptionServices;
using System.Security;
using System.Text;

class Probe8 {
    [DllImport("kernel32")] static extern IntPtr LoadLibraryA(string p);
    [DllImport("kernel32")] static extern IntPtr GetProcAddress(IntPtr h, string n);
    [DllImport("kernel32")] static extern bool SetDllDirectory(string p);

    // The working signature for hsmon.dll mightyfunc:
    //   (const char* command, char* response_buf, int* p_buf_size)  cdecl
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    delegate int MF([MarshalAs(UnmanagedType.LPStr)] string cmd, IntPtr buf, IntPtr pSz);

    static MF mf;
    static IntPtr buf;
    static IntPtr pSz;

    static void Clear() {
        byte[] z = new byte[8192];
        Marshal.Copy(z, 0, buf, 8192);
        Marshal.WriteInt32(pSz, 8192);
    }

    [HandleProcessCorruptedStateExceptions][SecurityCritical]
    static string Call(string cmd) {
        Clear();
        int ret;
        try { ret = mf(cmd, buf, pSz); }
        catch (Exception ex) { return "EXCEPTION: " + ex.GetType().Name + ": " + ex.Message; }
        int sz = Marshal.ReadInt32(pSz);
        if (sz <= 0) sz = 0;
        if (sz > 8192) sz = 8192;
        byte[] b = new byte[sz];
        if (sz > 0) Marshal.Copy(buf, b, 0, sz);
        string text = Encoding.ASCII.GetString(b).TrimEnd('\0', '\r', '\n', ' ');
        Console.WriteLine("CMD: " + cmd);
        Console.WriteLine("RET: " + ret + "  SZ: " + sz);
        Console.WriteLine("RSP: " + text);
        Console.WriteLine();
        return text;
    }

    static void Main() {
        string dir = @"C:\Program Files (x86)\Aladdin\Monitor";
        SetDllDirectory(dir);

        // Load hsmon.dll (NetHASP LM monitor)
        IntPtr h = LoadLibraryA(dir + @"\hsmon.dll");
        Console.WriteLine("hsmon.dll handle=" + (long)h);
        if (h == IntPtr.Zero) { Console.WriteLine("FAILED"); return; }

        IntPtr pfn = GetProcAddress(h, "mightyfunc");
        Console.WriteLine("mightyfunc=" + (long)pfn);
        if (pfn == IntPtr.Zero) { Console.WriteLine("FAILED"); return; }

        mf  = (MF)Marshal.GetDelegateForFunctionPointer(pfn, typeof(MF));
        buf = Marshal.AllocHGlobal(8192);
        pSz = Marshal.AllocHGlobal(8);

        // ── Step 1: Version / Help ──────────────────────────────────────────
        Console.WriteLine("=== HELP / VERSION ===");
        Call("VERSION");
        Call("STATUS");
        Call("HELP");

        // ── Step 2: Scan for servers on network ─────────────────────────────
        Console.WriteLine("=== SCAN SERVERS ===");
        Call("SCAN SERVERS");

        // ── Step 3: List found servers ───────────────────────────────────────
        Console.WriteLine("=== GET SERVERS ===");
        string svr = Call("GET SERVERS");

        // Parse server IDs from response like: HS,ID=123456789,...\r\nHS,ID=...
        // and also try known ID 123456789 directly
        var ids = new System.Collections.Generic.List<int>();
        foreach (System.Text.RegularExpressions.Match m in
            System.Text.RegularExpressions.Regex.Matches(svr, @"ID=(\d+)"))
        {
            int id;
            if (int.TryParse(m.Groups[1].Value, out id) && !ids.Contains(id))
                ids.Add(id);
        }
        // Also try the known HASP HL Net key ID
        if (!ids.Contains(123456789)) ids.Add(123456789);
        // And try 0 / small values in case ID is different
        foreach (int x in new[]{0,1,2,3,4,5}) if(!ids.Contains(x)) ids.Add(x);

        Console.WriteLine("Server IDs to probe: " + string.Join(", ", ids));

        foreach (int id in ids) {
            Console.WriteLine("\n=== SERVER ID=" + id + " ===");

            // Get server info
            Call("GET SERVERINFO,ID=" + id);

            // Get modules
            string mods = Call("GET MODULES,ID=" + id);

            // Parse module addresses (MA)
            var mas = new System.Collections.Generic.List<string>();
            foreach (System.Text.RegularExpressions.Match m in
                System.Text.RegularExpressions.Regex.Matches(mods, "MA=\"([^\"]+)\""))
            {
                if (!mas.Contains(m.Groups[1].Value)) mas.Add(m.Groups[1].Value);
            }
            // Also probe MA=0..9 and MA="3" (known program number)
            foreach (string x in new[]{"0","1","2","3","4","5","6","7","8","9","a","b"})
                if (!mas.Contains(x)) mas.Add(x);

            foreach (string ma in mas) {
                string slots_rsp = Call("GET SLOTS,ID=" + id + ",MA=\"" + ma + "\"");
                if (slots_rsp.Contains("ERROR") || slots_rsp.Contains("EMPTY") ||
                    slots_rsp.Length == 0) continue;

                // Parse slot numbers
                var slotNums = new System.Collections.Generic.List<int>();
                foreach (System.Text.RegularExpressions.Match m in
                    System.Text.RegularExpressions.Regex.Matches(slots_rsp, @"SLOT=(\d+)"))
                {
                    int sl;
                    if (int.TryParse(m.Groups[1].Value, out sl) && !slotNums.Contains(sl))
                        slotNums.Add(sl);
                }
                if (slotNums.Count == 0) slotNums.Add(0);

                foreach (int slot in slotNums) {
                    Console.WriteLine("--- MA=" + ma + " SLOT=" + slot + " ---");
                    // Get slot info (curr/max)
                    Call("GET SLOTINFO,ID=" + id + ",MA=\"" + ma + "\",SLOT=" + slot);
                    // GET LOGINS — THE MAIN QUERY
                    Call("GET LOGINS,ID=" + id + ",MA=\"" + ma + "\",SLOT=" + slot);
                    // GET LOGININFO for each index
                    for (int idx = 0; idx < 20; idx++) {
                        string li = Call("GET LOGININFO,ID=" + id + ",MA=\"" + ma +
                                         "\",SLOT=" + slot + ",INDEX=" + idx);
                        if (li.Contains("EMPTY") || li.Contains("ERROR")) break;
                    }
                }
            }
        }

        Console.WriteLine("\n=== DONE ===");
        Marshal.FreeHGlobal(buf);
        Marshal.FreeHGlobal(pSz);
    }
}
"""

script_dir = os.path.dirname(os.path.abspath(__file__))
cs_path  = os.path.join(script_dir, "probe8.cs")
exe_path = os.path.join(script_dir, "probe8.exe")
with open(cs_path, "w", encoding="utf-8") as f:
    f.write(cs_src)

csc = r"C:\Windows\Microsoft.NET\Framework\v4.0.30319\csc.exe"
r = subprocess.run([csc, "/nologo", "/platform:x86", "/optimize+",
                    f"/out:{exe_path}", cs_path],
                   capture_output=True, text=True, timeout=30)
print(f"Compile: rc={r.returncode}")
if r.stderr:
    print("ERR:", r.stderr[:400])

if r.returncode == 0:
    r2 = subprocess.run([exe_path], capture_output=True, text=True, timeout=120)
    out  = r2.stdout or ""
    err  = r2.stderr or ""
    results["probe_output"] = out
    results["probe_stderr"] = err[:500]
    print(out)
    if err:
        print("STDERR:", err[:200])
else:
    results["compile_error"] = r.stderr

out_path = os.path.join(script_dir, "diagnose8_out.json")
with open(out_path, "w", encoding="utf-8") as f:
    json.dump(results, f, indent=2, ensure_ascii=False)
print(f"\nDone → {out_path}")
