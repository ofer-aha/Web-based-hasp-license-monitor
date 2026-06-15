"""
diagnose9.py — same as diagnose8 but waits for SCAN SERVERS to finish
Run on SWCOMP99: python diagnose9.py
"""
import os, json, subprocess

results = {}

cs_src = r"""
using System;
using System.Runtime.InteropServices;
using System.Runtime.ExceptionServices;
using System.Security;
using System.Text;
using System.Threading;

class Probe9 {
    [DllImport("kernel32")] static extern IntPtr LoadLibraryA(string p);
    [DllImport("kernel32")] static extern IntPtr GetProcAddress(IntPtr h, string n);
    [DllImport("kernel32")] static extern bool SetDllDirectory(string p);

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
        return text;
    }

    static void Log(string label, string rsp) {
        Console.WriteLine("CMD: " + label);
        Console.WriteLine("RSP: " + rsp);
        Console.WriteLine();
    }

    static void Main() {
        string dir = @"C:\Program Files (x86)\Aladdin\Monitor";
        SetDllDirectory(dir);

        IntPtr h = LoadLibraryA(dir + @"\hsmon.dll");
        Console.WriteLine("hsmon.dll handle=" + (long)h);
        if (h == IntPtr.Zero) { Console.WriteLine("FAILED to load"); return; }

        IntPtr pfn = GetProcAddress(h, "mightyfunc");
        Console.WriteLine("mightyfunc=" + (long)pfn);
        if (pfn == IntPtr.Zero) { Console.WriteLine("FAILED to get proc"); return; }

        mf  = (MF)Marshal.GetDelegateForFunctionPointer(pfn, typeof(MF));
        buf = Marshal.AllocHGlobal(8192);
        pSz = Marshal.AllocHGlobal(8);

        // Step 1: SCAN SERVERS then poll until not SCANNING
        Console.WriteLine("=== SCAN SERVERS (polling until ready) ===");
        string r = Call("SCAN SERVERS");
        Log("SCAN SERVERS", r);

        string svr = "";
        for (int attempt = 0; attempt < 20; attempt++) {
            Thread.Sleep(500);  // wait 500ms between polls
            svr = Call("GET SERVERS");
            Console.WriteLine("  poll " + attempt + ": " + svr);
            if (!svr.Contains("SCANNING") && svr.Length > 0) break;
        }
        Console.WriteLine();
        Log("GET SERVERS (final)", svr);

        // Parse server IDs
        var ids = new System.Collections.Generic.List<long>();
        foreach (System.Text.RegularExpressions.Match m in
            System.Text.RegularExpressions.Regex.Matches(svr, @"ID=(\d+)"))
        {
            long id;
            if (long.TryParse(m.Groups[1].Value, out id) && !ids.Contains(id))
                ids.Add(id);
        }
        if (!ids.Contains(147558057L)) ids.Add(147558057L);

        Console.WriteLine("Server IDs: " + string.Join(", ", ids));
        Console.WriteLine();

        foreach (long id in ids) {
            Console.WriteLine("=== SERVER ID=" + id + " ===");

            string si = Call("GET SERVERINFO,ID=" + id);
            Log("GET SERVERINFO,ID=" + id, si);
            if (si.Contains("SCANNING") || si.Contains("ERROR")) continue;

            string mods = Call("GET MODULES,ID=" + id);
            Log("GET MODULES,ID=" + id, mods);

            // Collect MA values from response + brute-force 0..9 + "3"
            var mas = new System.Collections.Generic.List<string>();
            foreach (System.Text.RegularExpressions.Match m in
                System.Text.RegularExpressions.Regex.Matches(mods, "MA=\"([^\"]+)\""))
            {
                if (!mas.Contains(m.Groups[1].Value)) mas.Add(m.Groups[1].Value);
            }
            foreach (string x in new[]{"0","1","2","3","4","5","6","7","8","9","a","b"})
                if (!mas.Contains(x)) mas.Add(x);

            foreach (string ma in mas) {
                string slots_rsp = Call("GET SLOTS,ID=" + id + ",MA=\"" + ma + "\"");
                if (slots_rsp.Contains("ERROR") || slots_rsp.Contains("SCANNING") ||
                    slots_rsp.Contains("EMPTY") || slots_rsp.Length == 0) continue;
                Log("GET SLOTS,ID=" + id + ",MA=" + ma, slots_rsp);

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
                    string si2 = Call("GET SLOTINFO,ID=" + id + ",MA=\"" + ma + "\",SLOT=" + slot);
                    Log("GET SLOTINFO MA=" + ma + " SLOT=" + slot, si2);

                    string logins = Call("GET LOGINS,ID=" + id + ",MA=\"" + ma + "\",SLOT=" + slot);
                    Log("GET LOGINS MA=" + ma + " SLOT=" + slot, logins);

                    for (int idx = 0; idx < 20; idx++) {
                        string li = Call("GET LOGININFO,ID=" + id + ",MA=\"" + ma +
                                         "\",SLOT=" + slot + ",INDEX=" + idx);
                        Console.WriteLine("  LOGININFO[" + idx + "]: " + li);
                        if (li.Contains("EMPTY") || li.Contains("ERROR")) break;
                    }
                    Console.WriteLine();
                }
            }
        }

        Console.WriteLine("=== DONE ===");
        Marshal.FreeHGlobal(buf);
        Marshal.FreeHGlobal(pSz);
    }
}
"""

script_dir = os.path.dirname(os.path.abspath(__file__))
cs_path  = os.path.join(script_dir, "probe9.cs")
exe_path = os.path.join(script_dir, "probe9.exe")

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
    print("Running probe9.exe (may take up to 10s for scan)...")
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

out_path = os.path.join(script_dir, "diagnose9_out.json")
with open(out_path, "w", encoding="utf-8") as f:
    json.dump(results, f, indent=2, ensure_ascii=False)
print(f"\nDone → {out_path}")
