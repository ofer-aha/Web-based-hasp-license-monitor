"""
Aladdin License Monitor — web interface for HASP license usage.
Runs on SWCOMP99 (the machine hosting the HASP key).

Queries:
  1. HASP Admin Control Center (localhost:1947) for current sessions
  2. Each client workstation via WMI for the logged-on user
  3. Active Directory for the user's display name

Usage:
  pip install flask requests beautifulsoup4
  python server.py
Then open http://localhost:5000 in any browser on the network.
"""

import subprocess
import re
import json
import logging
from flask import Flask, jsonify, render_template_string
import requests
from bs4 import BeautifulSoup

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
HASP_URL   = "http://127.0.0.1:1947"
LISTEN_HOST = "0.0.0.0"   # accept connections from the network
LISTEN_PORT = 5000
LOG_LEVEL   = logging.INFO

# ---------------------------------------------------------------------------
logging.basicConfig(level=LOG_LEVEL, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger(__name__)
app = Flask(__name__)

# ---------------------------------------------------------------------------
# HASP session scraping
# ---------------------------------------------------------------------------

# Persistent HTTP session so the ACC gets consistent cookies across calls
_acc_session = requests.Session()
_acc_session.headers.update({"Referer": HASP_URL + "/_int_/sessions.html"})


def _acc_get(path: str, params: dict = None) -> str | None:
    """GET a path from the HASP ACC using the persistent session."""
    url = HASP_URL + path
    try:
        r = _acc_session.get(url, params=params, timeout=5)
        if r.status_code == 200:
            return r.text
        log.debug("HASP %s → HTTP %s", url, r.status_code)
    except requests.RequestException as e:
        log.debug("HASP fetch %s: %s", url, e)
    return None


# Keep a public alias for the debug route
_fetch_acc = _acc_get


def _parse_acc_json(text: str):
    """
    Sentinel ACC responses look like:
      /*JSON:tag*/\\n\\n{obj1},\\n{obj2}\\n/*admin_status*/

    The body after stripping comments may be ONE object or MULTIPLE objects
    separated by commas (invalid JSON as-is).  Wrap in [] to handle both.
    Returns a list (possibly of one item) or None.
    """
    if not text:
        return None
    body = re.sub(r'/\*.*?\*/', '', text, flags=re.DOTALL).strip().rstrip(',')
    if not body:
        return None
    # Try as single object first
    try:
        obj = json.loads(body)
        return obj if isinstance(obj, list) else [obj]
    except json.JSONDecodeError:
        pass
    # Try wrapping multiple comma-separated objects in an array
    try:
        return json.loads('[' + body + ']')
    except json.JSONDecodeError:
        pass
    return None


def _extract_sessions_from_json(objects: list) -> list[dict]:
    """Pull session rows out of the parsed ACC JSON list."""
    sessions = []
    for obj in objects:
        if not isinstance(obj, dict):
            continue
        # The filter-state object has fhaspid/fprod/ffea — skip it
        if "fhaspid" in obj or "ffea" in obj:
            continue
        # A session row has a client hostname or IP
        host = (obj.get("clienthost") or obj.get("hostname")
                or obj.get("machine")  or obj.get("clientname") or "")
        ip   = (obj.get("clientaddr") or obj.get("ip")
                or obj.get("loginid")  or obj.get("login_id")   or "")
        no   = obj.get("ndx") or obj.get("no") or ""
        if host or ip:
            sessions.append({"no": str(no), "host_name": host, "login_id": ip})
    return sessions


# ---------------------------------------------------------------------------
# Source 0-A: Call aksmon_ge.dll by ordinal from 32-bit PowerShell
# Works from Session 0 because the DLL queries the HASP LM *service*, not GUI.
# The DLL exports functions by ordinal only; we probe ordinals 1-10.
#
# Expected AksProgramInfo struct (32-bit layout):
#   program  : WORD  (2)
#   current  : WORD  (2)
#   maximum  : WORD  (2)
#   logins[50]: AksLoginInfo[50]
#     hostname : char[256]
#     loginid  : char[16]
#     timeout  : DWORD(4)
#     protocol : WORD (2)
#     ndx      : WORD (2)
# ---------------------------------------------------------------------------

_AKS_DLL = r"C:\Program Files (x86)\Aladdin\Monitor\aksmon_ge.dll"

_ORDINAL_PS = r"""
try {
Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
using System.Collections.Generic;
using System.Text;

public class HaspQuery {
  const string NHL = @"C:\Program Files (x86)\Aladdin\Monitor\NHLMINST.dll";

  [DllImport("kernel32")] static extern bool SetDllDirectory(string p);

  // HaspLMInfo(server, buffer, program) — cdecl, string server
  [DllImport(NHL, EntryPoint="HaspLMInfo", CallingConvention=CallingConvention.Cdecl)]
  static extern int LMI_CS([MarshalAs(UnmanagedType.LPStr)] string sv, IntPtr buf, ushort pr);

  // HaspLMInfo(server, buffer, program) — cdecl, null pointer server
  [DllImport(NHL, EntryPoint="HaspLMInfo", CallingConvention=CallingConvention.Cdecl)]
  static extern int LMI_CN(IntPtr sv, IntPtr buf, ushort pr);

  // HaspLMInfo(server, buffer, program) — stdcall, string server
  [DllImport(NHL, EntryPoint="HaspLMInfo", CallingConvention=CallingConvention.StdCall)]
  static extern int LMI_SS([MarshalAs(UnmanagedType.LPStr)] string sv, IntPtr buf, ushort pr);

  // HaspLMInfo(server, buffer, program) — stdcall, null pointer server
  [DllImport(NHL, EntryPoint="HaspLMInfo", CallingConvention=CallingConvention.StdCall)]
  static extern int LMI_SN(IntPtr sv, IntPtr buf, ushort pr);

  // HaspLMInfo(server, program, buffer) — alternate param order, cdecl
  [DllImport(NHL, EntryPoint="HaspLMInfo", CallingConvention=CallingConvention.Cdecl)]
  static extern int LMI_CSP([MarshalAs(UnmanagedType.LPStr)] string sv, ushort pr, IntPtr buf);

  // HaspLMInfo(server, program, buffer) — alternate param order, stdcall
  [DllImport(NHL, EntryPoint="HaspLMInfo", CallingConvention=CallingConvention.StdCall)]
  static extern int LMI_SSP([MarshalAs(UnmanagedType.LPStr)] string sv, ushort pr, IntPtr buf);

  [System.Runtime.ExceptionServices.HandleProcessCorruptedStateExceptions]
  [System.Security.SecurityCritical]
  static string SafeCall(int v, string sv, IntPtr buf, ushort pr) {
    try {
      int r = 0;
      switch (v) {
        case 0: r = LMI_CS(sv, buf, pr); break;
        case 1: r = LMI_CN(IntPtr.Zero, buf, pr); break;
        case 2: r = LMI_SS(sv, buf, pr); break;
        case 3: r = LMI_SN(IntPtr.Zero, buf, pr); break;
        case 4: r = LMI_CSP(sv, pr, buf); break;
        case 5: r = LMI_SSP(sv, pr, buf); break;
        default: return "bad_v";
      }
      ushort cur = (ushort)(Marshal.ReadByte(buf, 2) | (Marshal.ReadByte(buf, 3) << 8));
      ushort max = (ushort)(Marshal.ReadByte(buf, 4) | (Marshal.ReadByte(buf, 5) << 8));
      byte[] hdr = new byte[32];
      for (int i = 0; i < 32; i++) hdr[i] = Marshal.ReadByte(buf, i);
      return "ret=" + r.ToString() + " cur=" + cur.ToString() + " max=" + max.ToString() + " hdr=" + BitConverter.ToString(hdr).Replace("-", "");
    } catch (Exception ex) { return "ex:" + ex.GetType().Name + ":" + ex.Message.Replace('\n', ' ').Replace('\r', ' '); }
  }

  static List<string> ParseSessions(IntPtr buf, int cur) {
    var s = new List<string>();
    for (int i = 0; i < cur && i < 50; i++) {
      int off = 6 + i * 280;
      byte[] hb = new byte[256]; byte[] lb = new byte[16];
      for (int j = 0; j < 256; j++) hb[j] = Marshal.ReadByte(buf, off + j);
      for (int j = 0; j < 16;  j++) lb[j] = Marshal.ReadByte(buf, off + 256 + j);
      string host  = Encoding.ASCII.GetString(hb).Split('\0')[0];
      string login = Encoding.ASCII.GetString(lb).Split('\0')[0];
      s.Add("SESSION:" + (i + 1).ToString() + "|" + login + "|" + host);
    }
    return s;
  }

  [System.Runtime.ExceptionServices.HandleProcessCorruptedStateExceptions]
  [System.Security.SecurityCritical]
  public static string[] Run(ushort pr) {
    SetDllDirectory(@"C:\Program Files (x86)\Aladdin\Monitor");
    var res = new List<string>();
    res.Add("NHL:" + NHL);
    int bsz = 16384;
    IntPtr buf = Marshal.AllocHGlobal(bsz);
    try {
      string[] servers = new string[] { "127.0.0.1", "", "SWCOMP99", null };
      string[] vnames  = new string[] { "cdecl_str", "cdecl_null", "std_str", "std_null", "cdecl_str_swapped", "std_str_swapped" };
      foreach (string sv in servers) {
        string svk = sv == null ? "null" : (sv == "" ? "empty" : sv);
        for (int v = 0; v <= 5; v++) {
          for (int i = 0; i < bsz; i++) Marshal.WriteByte(buf, i, 0);
          string r = SafeCall(v, sv, buf, pr);
          res.Add(svk + ":" + vnames[v] + ":" + r);

          if (r.StartsWith("ex:") || r.StartsWith("bad_v")) continue;
          ushort cur = (ushort)(Marshal.ReadByte(buf, 2) | (Marshal.ReadByte(buf, 3) << 8));
          ushort max = (ushort)(Marshal.ReadByte(buf, 4) | (Marshal.ReadByte(buf, 5) << 8));
          if (cur > 0 && cur <= max && max <= 100) {
            res.Add("VALID:sv=" + svk + " v=" + v.ToString() + " cur=" + cur.ToString() + " max=" + max.ToString());
            res.AddRange(ParseSessions(buf, cur));
          }
        }
      }
    } finally { Marshal.FreeHGlobal(buf); }
    return res.Count > 0 ? res.ToArray() : new string[] { "no_data" };
  }
}
'@ -ErrorAction Stop
[HaspQuery]::Run(3)
} catch {
  "COMPILE_OR_RUNTIME_ERROR: " + $_.ToString()
}
"""


def _sessions_via_ordinal() -> list[dict]:
    """Call NHLMINST.dll::HaspLMInfo via 32-bit PowerShell P/Invoke. Session-0 safe."""
    out = _run_ps32(_ORDINAL_PS, timeout=25)
    if not out:
        log.debug("Ordinal probe: no output from 32-bit PS")
        return []
    log.info("Ordinal probe output:\n%s", out[:600])
    sessions = []
    import re as _re
    ip_or_host = _re.compile(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|[A-Z][A-Z0-9\-]{2,}', _re.I)
    for line in out.splitlines():
        if not line.startswith("SESSION:"):
            continue
        parts = line[8:].split("|")
        if len(parts) >= 3:
            sessions.append({
                "no":        parts[0].strip(),
                "login_id":  parts[1].strip(),
                "host_name": parts[2].strip(),
            })
    return sessions


# ---------------------------------------------------------------------------
# Source MIGHTYFUNC: hsmon.dll::mightyfunc — confirmed working via diagnose9.py
#
# Protocol (text-based RPC over UDP to nhsrvice.exe on port 475):
#   SCAN SERVERS  → async broadcast; poll GET SERVERS until not "SCANNING"
#   GET SERVERS   → HS,ID=<n>,NAME=...,PROT="UDP(ip)",...
#   GET MODULES,ID=<n>  → HS,ID=<n>,MA="<ma>",CURR=<c>,MAX=<m>,...
#   GET SLOTS,ID=<n>,MA="<ma>"  → HS,...,SLOT=<s>,CURR=<c>,MAX=<m>,...
#   GET LOGINS,ID=<n>,MA="<ma>",SLOT=<s>
#     → one line per active session:
#       HS,ID=<n>,MA="<ma>",SLOT=<s>,INDEX=<i>,PROT="UDP(ip)",TIMEOUT=<t>,NAME="host"
#
# Confirmed: server ID=46046, MA="1", SLOT=3, users appear as NAME="SWCOMP117.sw.local"
# ---------------------------------------------------------------------------

_MIGHTYFUNC_CS = r"""
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Runtime.ExceptionServices;
using System.Security;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;

class MfQuery {
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
        try { mf(cmd, buf, pSz); }
        catch { return ""; }
        int sz = Marshal.ReadInt32(pSz);
        if (sz <= 0 || sz > 8192) sz = 8192;
        byte[] b = new byte[sz];
        Marshal.Copy(buf, b, 0, sz);
        return Encoding.ASCII.GetString(b).TrimEnd('\0', '\r', '\n', ' ');
    }

    static void Main() {
        string dir = @"C:\Program Files (x86)\Aladdin\Monitor";
        SetDllDirectory(dir);
        IntPtr h = LoadLibraryA(dir + @"\hsmon.dll");
        if (h == IntPtr.Zero) { Console.WriteLine("ERROR:LoadLibrary"); return; }
        IntPtr pfn = GetProcAddress(h, "mightyfunc");
        if (pfn == IntPtr.Zero) { Console.WriteLine("ERROR:GetProcAddress"); return; }
        mf  = (MF)Marshal.GetDelegateForFunctionPointer(pfn, typeof(MF));
        buf = Marshal.AllocHGlobal(8192);
        pSz = Marshal.AllocHGlobal(8);

        // Scan and wait for results (up to 10s)
        Call("SCAN SERVERS");
        string svr = "";
        for (int i = 0; i < 20; i++) {
            Thread.Sleep(500);
            svr = Call("GET SERVERS");
            if (!svr.Contains("SCANNING") && svr.Length > 0) break;
        }
        if (svr.Length == 0 || svr.Contains("SCANNING")) {
            Console.WriteLine("ERROR:NoServers"); return;
        }

        // Parse server IDs
        var ids = new List<long>();
        foreach (Match m in Regex.Matches(svr, @"ID=(\d+)"))
        { long id; if (long.TryParse(m.Groups[1].Value, out id) && !ids.Contains(id)) ids.Add(id); }

        foreach (long id in ids) {
            string si = Call("GET SERVERINFO,ID=" + id);
            if (si.Contains("ERROR") || si.Contains("SCANNING")) continue;

            string mods = Call("GET MODULES,ID=" + id);
            if (mods.Contains("ERROR") || mods.Contains("SCANNING")) continue;

            var mas = new List<string>();
            foreach (Match m in Regex.Matches(mods, "MA=\"([^\"]+)\""))
                if (!mas.Contains(m.Groups[1].Value)) mas.Add(m.Groups[1].Value);
            // Also brute-force common MA values in case parsing missed some
            foreach (string x in new[]{"1","0","2","3"})
                if (!mas.Contains(x)) mas.Add(x);

            foreach (string ma in mas) {
                string slots_rsp = Call("GET SLOTS,ID=" + id + ",MA=\"" + ma + "\"");
                if (slots_rsp.Contains("ERROR") || slots_rsp.Contains("SCANNING") ||
                    slots_rsp.Contains("EMPTY") || slots_rsp.Length == 0) continue;

                var slotNums = new List<int>();
                foreach (Match m in Regex.Matches(slots_rsp, @"SLOT=(\d+)"))
                { int sl; if (int.TryParse(m.Groups[1].Value, out sl) && !slotNums.Contains(sl)) slotNums.Add(sl); }
                if (slotNums.Count == 0) slotNums.Add(0);

                foreach (int slot in slotNums) {
                    string logins = Call("GET LOGINS,ID=" + id + ",MA=\"" + ma + "\",SLOT=" + slot);
                    if (logins.Contains("ERROR") || logins.Contains("SCANNING") ||
                        logins.Contains("EMPTY") || logins.Length == 0) continue;

                    // Each line: HS,...,INDEX=n,PROT="UDP(ip)",TIMEOUT=t,NAME="host"
                    foreach (string line in logins.Split(new[]{'\r','\n'}, StringSplitOptions.RemoveEmptyEntries)) {
                        Match nm = Regex.Match(line, "NAME=\"([^\"]+)\"");
                        Match pm = Regex.Match(line, "PROT=\"[A-Z]+\\(([^)]+)\\)\"");
                        if (nm.Success || pm.Success) {
                            string host = nm.Success ? nm.Groups[1].Value : "";
                            string ip   = pm.Success ? pm.Groups[1].Value : "";
                            Console.WriteLine("SESSION|" + ip + "|" + host);
                        }
                    }
                }
            }
        }

        Console.WriteLine("DONE");
        Marshal.FreeHGlobal(buf);
        Marshal.FreeHGlobal(pSz);
    }
}
"""

import os as _os
import subprocess as _subprocess
import tempfile as _tempfile

_MF_EXE_PATH: str | None = None  # cached compiled exe path


def _ensure_mf_exe() -> str | None:
    """Compile MfQuery.exe once; return exe path or None on failure."""
    global _MF_EXE_PATH
    if _MF_EXE_PATH and _os.path.exists(_MF_EXE_PATH):
        return _MF_EXE_PATH

    script_dir = _os.path.dirname(_os.path.abspath(__file__))
    cs_path  = _os.path.join(script_dir, "_mfquery.cs")
    exe_path = _os.path.join(script_dir, "_mfquery.exe")

    with open(cs_path, "w", encoding="utf-8") as f:
        f.write(_MIGHTYFUNC_CS)

    csc = r"C:\Windows\Microsoft.NET\Framework\v4.0.30319\csc.exe"
    try:
        r = _subprocess.run(
            [csc, "/nologo", "/platform:x86", "/optimize+",
             f"/out:{exe_path}", cs_path],
            capture_output=True, text=True, timeout=30
        )
        if r.returncode == 0:
            _MF_EXE_PATH = exe_path
            log.info("mfquery.exe compiled OK")
            return exe_path
        log.warning("mfquery.exe compile failed: %s", r.stderr[:300])
    except Exception as e:
        log.warning("mfquery.exe compile exception: %s", e)
    return None


def _sessions_via_mightyfunc() -> list[dict]:
    """
    Query NetHASP sessions via hsmon.dll::mightyfunc.
    Compiles a small 32-bit C# exe on first call, then runs it each time.
    Returns list of dicts with host_name, login_id (IP), no.
    """
    exe = _ensure_mf_exe()
    if not exe:
        return []

    try:
        r = _subprocess.run([exe], capture_output=True, text=True, timeout=20)
        out = r.stdout or ""
    except Exception as e:
        log.warning("mfquery.exe run error: %s", e)
        return []

    if "ERROR:" in out:
        log.warning("mfquery.exe: %s", out.strip()[:200])
        return []

    sessions = []
    seen_ips = set()
    for line in out.splitlines():
        if not line.startswith("SESSION|"):
            continue
        parts = line.split("|")
        if len(parts) < 3:
            continue
        ip   = parts[1].strip()
        host = parts[2].strip()
        if ip in seen_ips:
            continue
        seen_ips.add(ip)
        # Shorten FQDN to short hostname if it contains a dot
        short_host = host.split(".")[0] if host else ip
        sessions.append({
            "no":        str(len(sessions) + 1),
            "host_name": short_host,
            "login_id":  ip,
        })

    log.info("mightyfunc: found %d session(s): %s",
             len(sessions), [s["host_name"] for s in sessions])
    return sessions


def get_hasp_sessions() -> list[dict]:
    """
    Get active HASP license sessions.  Tries sources in order:
      1. hsmon.dll::mightyfunc  — confirmed working; Session-0 safe
      2. NHLMINST.dll::HaspLMInfo — 32-bit PS P/Invoke; works from Session 0
      2. ListView reader           — reads Aladdin Monitor window; only works in interactive session
      3. UDP / UIA / ctypes fallbacks
    """
    sessions = _sessions_via_mightyfunc()
    if sessions:
        log.info("Got %d sessions via mightyfunc", len(sessions))
        return sessions

    sessions = _sessions_via_ordinal()
    if sessions:
        log.info("Got %d sessions via ordinal DLL", len(sessions))
        return sessions

    sessions = _sessions_via_listview()
    if sessions:
        log.info("Got %d sessions via ListView", len(sessions))
        return sessions

    sessions = _sessions_via_udp()
    if sessions:
        log.info("Got %d sessions via UDP", len(sessions))
        return sessions

    sessions = _sessions_via_ui_automation()
    if sessions:
        log.info("Got %d sessions via UI Automation", len(sessions))
        return sessions

    sessions = _sessions_via_aksmon_dll()
    if sessions:
        log.info("Got %d sessions via aksmon DLL", len(sessions))
        return sessions

    sessions = _sessions_via_powershell_tool()
    if sessions:
        log.info("Got %d sessions via PowerShell/aksmon tool", len(sessions))
        return sessions

    log.warning("All session sources returned 0 — check /api/debug")
    return []


# ---------------------------------------------------------------------------
# Source 0: UDP port 475 — old HASP monitoring protocol
# ---------------------------------------------------------------------------

def _sessions_via_udp() -> list[dict]:
    """
    Query the HASP License Manager via UDP port 475 using the old
    Aladdin monitoring protocol.  This is exactly what aksmon.exe does.

    The request packet: 6 bytes
      Byte 0-1: packet type  (0x0003 = NetHasp monitor query)
      Byte 2-3: program no   (0x0000 = query all)
      Byte 4-5: padding

    The response contains one or more login records:
      2 bytes  : number of logins
      Per login: IP (4 bytes) + hostname (max 16 bytes, null-terminated)
    (Exact layout varies by LM version; we extract all plausible IP/host data)
    """
    import socket
    QUERIES = [
        b'\x00\x03\x00\x00\x00\x00',   # standard monitor query, prog 0
        b'\x05\x00\x00\x03\x00\x00',   # alternate format seen in some versions
        b'\x00\x03\x00\x03\x00\x00',   # with program number 3
    ]
    results = []
    for q in QUERIES:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(2)
            s.sendto(q, ('127.0.0.1', 475))
            data, _ = s.recvfrom(4096)
            s.close()
            log.info("UDP port 475 response (%d bytes): %s", len(data), data[:64].hex())
            # Parse: look for IPv4 addresses and hostnames in the raw bytes
            results = _parse_udp_response(data)
            if results:
                return results
        except (OSError, socket.timeout) as e:
            log.debug("UDP 475 query %s failed: %s", q.hex(), e)
    # Also try port 1947
    for q in QUERIES:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(2)
            s.sendto(q, ('127.0.0.1', 1947))
            data, _ = s.recvfrom(4096)
            s.close()
            log.info("UDP port 1947 response (%d bytes): %s", len(data), data[:64].hex())
            results = _parse_udp_response(data)
            if results:
                return results
        except (OSError, socket.timeout):
            pass
    return []


def _parse_udp_response(data: bytes) -> list[dict]:
    """Extract IP addresses and hostnames from a raw HASP UDP response."""
    import re as _re
    # Find IPv4 addresses encoded as 4 raw bytes
    sessions = []
    for i in range(len(data) - 3):
        a, b, c, d = data[i], data[i+1], data[i+2], data[i+3]
        if 10 <= a <= 192 and b > 0 and c >= 0 and 1 <= d <= 254:
            ip = f"{a}.{b}.{c}.{d}"
            # Try to read a hostname starting after the IP bytes
            host_start = i + 4
            host_end   = data.find(b'\x00', host_start)
            if host_end == -1 or host_end - host_start > 64:
                host_end = host_start + 16
            host = data[host_start:host_end].decode('ascii', errors='replace').strip()
            host = _re.sub(r'[^\w.\-]', '', host)
            if ip not in [s['login_id'] for s in sessions]:
                sessions.append({
                    "no":        str(len(sessions) + 1),
                    "host_name": host,
                    "login_id":  ip,
                })
    return sessions


# ---------------------------------------------------------------------------
# Source 1: PowerShell UI Automation — read the live Aladdin Monitor window
# ---------------------------------------------------------------------------

_UI_AUTO_PS = r"""
Add-Type -AssemblyName UIAutomationClient, UIAutomationTypes
$scope = [System.Windows.Automation.TreeScope]
$prop  = [System.Windows.Automation.AutomationElement]
$CT    = [System.Windows.Automation.ControlType]

$root = $prop::RootElement
$winCond = [System.Windows.Automation.PropertyCondition]::new($prop::NameProperty, "Aladdin Monitor")
$win = $root.FindFirst($scope::Children, $winCond)
if (-not $win) { exit }

# Find all List and DataGrid/Table items
$rows = $win.FindAll($scope::Subtree,
    [System.Windows.Automation.PropertyCondition]::new($prop::ControlTypeProperty, $CT::ListItem))

foreach ($r in $rows) {
    $name = $r.GetCurrentPropertyValue($prop::NameProperty)
    if ($name) { Write-Output $name }
}

# Also try DataItem (grid rows)
$rows2 = $win.FindAll($scope::Subtree,
    [System.Windows.Automation.PropertyCondition]::new($prop::ControlTypeProperty, $CT::DataItem))
foreach ($r in $rows2) {
    $cells = $r.FindAll($scope::Children,
        [System.Windows.Automation.Condition]::TrueCondition)
    $line = ($cells | ForEach-Object {
        $_.GetCurrentPropertyValue($prop::NameProperty)
    }) -join "|"
    if ($line.Trim()) { Write-Output $line }
}
"""

def _sessions_via_ui_automation() -> list[dict]:
    """Read the Aladdin Monitor window via Windows UI Automation."""
    out = _run_ps(_UI_AUTO_PS, timeout=12)
    if not out:
        log.debug("UI Automation: no output from Aladdin Monitor window")
        return []
    log.info("UI Automation raw output:\n%s", out[:500])
    return _parse_ui_auto_output(out)


# ---------------------------------------------------------------------------
# Source 2: Win32 cross-process ListView reading via 32-bit PowerShell
# ---------------------------------------------------------------------------
# aksmon.exe is a 32-bit (WOW64) process.  Sending LVM_GETITEMTEXT from a
# 64-bit process causes WOW64 to thunk the message and mangle the pointer.
# Solution: run the P/Invoke code inside 32-bit PowerShell so structs and
# pointers are the same width as the target process.
# ---------------------------------------------------------------------------

_LV_CS = r"""
Add-Type -TypeDefinition @'
using System; using System.Text; using System.Collections.Generic;
using System.Runtime.InteropServices;
public class LVR {
  [DllImport("user32.dll")] public static extern IntPtr FindWindow(string c,string t);
  [DllImport("user32.dll")] public static extern bool EnumChildWindows(IntPtr p,CB cb,IntPtr l);
  [DllImport("user32.dll")] public static extern int GetClassName(IntPtr h,StringBuilder s,int n);
  [DllImport("user32.dll")] public static extern IntPtr SendMessage(IntPtr h,int m,IntPtr w,IntPtr l);
  [DllImport("user32.dll")] public static extern int GetWindowThreadProcessId(IntPtr h,out int p);
  [DllImport("kernel32.dll")] public static extern IntPtr OpenProcess(int a,bool i,int p);
  [DllImport("kernel32.dll")] public static extern IntPtr VirtualAllocEx(IntPtr p,IntPtr a,int s,int f,int pr);
  [DllImport("kernel32.dll")] public static extern bool VirtualFreeEx(IntPtr p,IntPtr a,int s,int f);
  [DllImport("kernel32.dll")] public static extern bool WriteProcessMemory(IntPtr p,IntPtr a,byte[] b,int s,out int w);
  [DllImport("kernel32.dll")] public static extern bool ReadProcessMemory(IntPtr p,IntPtr a,byte[] b,int s,out int r);
  [DllImport("kernel32.dll")] public static extern bool CloseHandle(IntPtr h);
  public delegate bool CB(IntPtr h,IntPtr l);
  [StructLayout(LayoutKind.Sequential)]
  public struct LVITEMA { public uint mask; public int iItem; public int iSubItem; public uint state; public uint stateMask; public IntPtr pszText; public int cchTextMax; public int iImage; }
  const int LVM_GETITEMCOUNT=0x1004, LVM_GETITEMTEXTA=0x102D, PROCESS_ALL=0x1F0FFF, MEM_COMMIT=0x1000, MEM_RELEASE=0x8000, PAGE_RW=4;
  public static string[] GetRows() {
    IntPtr win=FindWindow(null,"Aladdin Monitor");
    if(win==IntPtr.Zero) return new string[]{"ERR:no_window"};
    var lvs=new List<IntPtr>();
    EnumChildWindows(win,(h,l)=>{var sb=new StringBuilder(128);GetClassName(h,sb,128);if(sb.ToString().IndexOf("SysListView",StringComparison.OrdinalIgnoreCase)>=0)lvs.Add(h);return true;},IntPtr.Zero);
    if(lvs.Count==0) return new string[]{"ERR:no_listview"};
    var res=new List<string>(); res.Add("LVC:"+lvs.Count);
    foreach(var lv in lvs){
      int pid; GetWindowThreadProcessId(lv,out pid);
      IntPtr proc=OpenProcess(PROCESS_ALL,false,pid);
      if(proc==IntPtr.Zero){res.Add("ERR:open_proc");continue;}
      int cnt=(int)SendMessage(lv,LVM_GETITEMCOUNT,IntPtr.Zero,IntPtr.Zero);
      res.Add("CNT:"+cnt);
      int lsz=Marshal.SizeOf(typeof(LVITEMA)),bsz=512;
      IntPtr mem=VirtualAllocEx(proc,IntPtr.Zero,lsz+bsz,MEM_COMMIT,PAGE_RW);
      if(mem==IntPtr.Zero){CloseHandle(proc);res.Add("ERR:alloc");continue;}
      try{
        for(int row=0;row<cnt;row++){
          var cols=new List<string>();
          for(int col=0;col<5;col++){
            IntPtr ta=new IntPtr(mem.ToInt32()+lsz);
            var lvi=new LVITEMA{mask=1,iItem=row,iSubItem=col,pszText=ta,cchTextMax=bsz-1};
            byte[] lb=new byte[lsz];IntPtr t=Marshal.AllocHGlobal(lsz);
            Marshal.StructureToPtr(lvi,t,false);Marshal.Copy(t,lb,0,lsz);Marshal.FreeHGlobal(t);
            int w,r;WriteProcessMemory(proc,mem,lb,lsz,out w);
            SendMessage(lv,LVM_GETITEMTEXTA,new IntPtr(row),mem);
            byte[] tb=new byte[bsz];ReadProcessMemory(proc,ta,tb,bsz,out r);
            int n=Array.IndexOf(tb,(byte)0);
            cols.Add(Encoding.ASCII.GetString(tb,0,n>=0?n:r));
          }
          res.Add("ROW:"+string.Join("|",cols));
        }
      }finally{VirtualFreeEx(proc,mem,0,MEM_RELEASE);CloseHandle(proc);}
    }
    return res.ToArray();
  }
}
'@
[LVR]::GetRows()
"""

_PS32 = r"C:\Windows\SysWOW64\WindowsPowerShell\v1.0\powershell.exe"


def _run_ps32(command: str, timeout: int = 15) -> str:
    """Run a PowerShell command in 32-bit PowerShell (matches aksmon.exe bitness)."""
    preamble = (
        "$env:PSModulePath = ($env:PSModulePath -split ';' "
        "| Where-Object { $_ -notmatch '^\\\\\\\\' }) -join ';'; "
    )
    try:
        result = subprocess.run(
            [_PS32, "-NonInteractive", "-NoProfile", "-Command", preamble + command],
            capture_output=True, text=True, timeout=timeout
        )
        return result.stdout.strip()
    except (subprocess.TimeoutExpired, FileNotFoundError) as e:
        log.warning("32-bit PowerShell error: %s", e)
        return ""


def _sessions_via_listview() -> list[dict]:
    """
    Read the Aladdin Monitor's Login-table ListView via 32-bit PowerShell
    P/Invoke + cross-process VirtualAllocEx / SendMessage.
    """
    out = _run_ps32(_LV_CS, timeout=20)
    if not out:
        log.debug("LV reader: no output from 32-bit PS")
        return []
    log.info("LV reader raw:\n%s", out[:800])
    return _parse_lv_output(out)


def _parse_lv_output(text: str) -> list[dict]:
    """Parse ROW:col0|col1|col2|col3|col4 lines from the ListView reader."""
    import re as _re
    ip_pat = _re.compile(r'^\d{1,3}(?:\.\d{1,3}){3}$')
    sessions = []
    for line in text.splitlines():
        if not line.startswith("ROW:"):
            continue
        cols = line[4:].split("|")
        # Login table columns: No | Login ID (IP) | Host Name | Protocol | Timeout
        if len(cols) >= 3 and ip_pat.match(cols[1].strip()):
            sessions.append({
                "no":        cols[0].strip(),
                "login_id":  cols[1].strip(),
                "host_name": cols[2].strip(),
            })
    return sessions


def _parse_ui_auto_output(text: str) -> list[dict]:
    """Parse IP addresses / hostnames from UI Automation text output."""
    import re as _re
    sessions = []
    ip_pat = _re.compile(r'\b(\d{1,3}(?:\.\d{1,3}){3})\b')
    host_pat = _re.compile(r'\b([A-Z][A-Z0-9\-]{2,}(?:\.[\w\-]+)*)\b', _re.IGNORECASE)
    for line in text.splitlines():
        ips   = ip_pat.findall(line)
        hosts = host_pat.findall(line)
        ip   = ips[0]   if ips   else ""
        host = hosts[0] if hosts else ""
        if ip or (host and len(host) > 3):
            if ip not in [s['login_id'] for s in sessions]:
                sessions.append({
                    "no":        str(len(sessions) + 1),
                    "host_name": host,
                    "login_id":  ip,
                })
    return sessions


# ---------------------------------------------------------------------------
# Source 1: aksmon DLL via ctypes
# ---------------------------------------------------------------------------
import ctypes
import os

# Structure layout from Aladdin aksmon.h:
#
#   typedef struct {
#       char  hostname[256];
#       char  loginid[16];    // IP address string
#       DWORD timeout;
#       WORD  protocol;       // 1=TCP 2=UDP
#       WORD  ndx;
#   } AKS_LOGIN_INFO;
#
#   typedef struct {
#       WORD           program;
#       WORD           current;
#       WORD           maximum;
#       AKS_LOGIN_INFO logins[50];
#   } AKS_PROGRAM_INFO;
#
#   int AKSMONAPI AksNetGetProgramInfo(
#       const char *server, WORD port, AKS_PROGRAM_INFO *pi);
#   Returns 0 on success.

MAX_LOGINS = 50

class _AksLoginInfo(ctypes.Structure):
    _fields_ = [
        ("hostname", ctypes.c_char * 256),
        ("loginid",  ctypes.c_char * 16),
        ("timeout",  ctypes.c_ulong),
        ("protocol", ctypes.c_ushort),
        ("ndx",      ctypes.c_ushort),
    ]

class _AksProgramInfo(ctypes.Structure):
    _fields_ = [
        ("program", ctypes.c_ushort),
        ("current", ctypes.c_ushort),
        ("maximum", ctypes.c_ushort),
        ("logins",  _AksLoginInfo * MAX_LOGINS),
    ]

_AKSMON_STATIC_PATHS = [
    r"C:\Windows\System32\aksmon64.dll",
    r"C:\Windows\System32\aksmon32.dll",
    r"C:\Windows\SysWOW64\aksmon32.dll",
    # Found in C:\Program Files (x86)\Aladdin\Monitor\
    r"C:\Program Files (x86)\Aladdin\Monitor\aksmon_ge.dll",
    r"C:\Program Files (x86)\Aladdin\Monitor\aksmon64.dll",
    r"C:\Program Files (x86)\Aladdin\Monitor\aksmon32.dll",
    r"C:\Program Files (x86)\Aladdin\Monitor\aksmon.dll",
    r"C:\Program Files\Aladdin\Monitor\aksmon_ge.dll",
    r"C:\Program Files\Aladdin\Monitor\aksmon64.dll",
    r"C:\Program Files\Aladdin\Monitor\aksmon32.dll",
]

# Function names to try — the _ge variant may use a different export name
_AKSMON_FUNC_NAMES = [
    "AksNetGetProgramInfo",
    "AksMonGetProgramInfo",
    "AksGetProgramInfo",
    "GetProgramInfo",
]

_aksmon_lib   = None   # loaded once
_aksmon_fn    = None

def _find_aksmon_paths() -> list[str]:
    """Find aksmon*.dll anywhere on the system, including app directories."""
    paths = list(_AKSMON_STATIC_PATHS)

    # 1. Check which DLLs the running Aladdin Monitor process has loaded
    ps_proc = (
        "Get-Process | Where-Object {$_.Name -like '*aksmon*' -or $_.Name -like '*AksMon*'} "
        "| ForEach-Object { $_.Modules | Where-Object {$_.ModuleName -like 'aksmon*'} "
        "| Select-Object -ExpandProperty FileName }"
    )
    proc_dlls = _run_ps(ps_proc, timeout=8).splitlines()
    paths.extend(p.strip() for p in proc_dlls if p.strip())

    # 2. Search common local install locations (no UNC paths to avoid timeouts)
    ps_search = (
        r'$dirs = @('
        r'"C:\Program Files (x86)\Aladdin",'
        r'"C:\Program Files\Aladdin",'
        r'"C:\Program Files (x86)\SafeNet Sentinel",'
        r'"C:\Program Files\SafeNet Sentinel",'
        r'"C:\Apps",'
        r'"C:\MasterPlan"'
        r'); '
        r'foreach ($d in $dirs) { '
        r'  if (Test-Path $d) { '
        r'    Get-ChildItem $d -Recurse -Filter "aksmon*.dll" -ErrorAction SilentlyContinue '
        r'    | Select-Object -ExpandProperty FullName } }'
    )
    found = _run_ps(ps_search, timeout=15).splitlines()
    paths.extend(p.strip() for p in found if p.strip())

    # Deduplicate, keep order
    seen = set()
    result = []
    for p in paths:
        if p and p not in seen:
            seen.add(p)
            result.append(p)
    return result


def _pe_helpers(data: bytearray):
    """Return (u16, u32, rva2off, is64, nsec, opt_off) helpers for a PE file."""
    import struct
    def u16(o): return struct.unpack_from('<H', data, o)[0]
    def u32(o): return struct.unpack_from('<I', data, o)[0]
    pe       = u32(0x3C)
    machine  = u16(pe + 4)
    is64     = (machine == 0x8664)
    nsec     = u16(pe + 6)
    opt_size = u16(pe + 20)
    opt_off  = pe + 24
    sec_off  = opt_off + opt_size
    def rva2off(rva):
        for i in range(nsec):
            s = sec_off + i * 40
            va = u32(s+12); vs = u32(s+16); ro = u32(s+20)
            if va <= rva < va + max(vs, 1):
                return ro + (rva - va)
        return None
    return u16, u32, rva2off, is64, nsec, opt_off


def _read_pe_exports(path: str) -> list[str]:
    """Parse a PE DLL file and return exported names or ordinals."""
    import struct
    try:
        with open(path, 'rb') as f:
            data = bytearray(f.read())
        if data[:2] != b'MZ': return ['ERROR: not MZ']
        u16, u32, rva2off, is64, nsec, opt_off = _pe_helpers(data)
        pe = u32(0x3C)
        if data[pe:pe+4] != b'PE\x00\x00': return ['ERROR: not PE']
        exp_rva = u32(opt_off + (112 if is64 else 96))
        if not exp_rva: return ['(no exports)']
        eoff = rva2off(exp_rva)
        if eoff is None: return ['ERROR: cannot map export RVA']
        base       = u32(eoff + 16)   # ordinal base
        num_funcs  = u32(eoff + 20)   # total ordinal slots
        num_names  = u32(eoff + 24)
        funcs_rva  = u32(eoff + 28)
        names_rva  = u32(eoff + 32)
        nameord_rva= u32(eoff + 36)
        foff  = rva2off(funcs_rva)
        # Build ordinal→name map from named exports
        ord2name: dict[int, str] = {}
        if num_names and names_rva and nameord_rva:
            noff  = rva2off(names_rva)
            nooff = rva2off(nameord_rva)
            if noff and nooff:
                for i in range(num_names):
                    idx = u16(nooff + i * 2)
                    nrva = u32(noff + i * 4)
                    no = rva2off(nrva)
                    if no:
                        end = data.index(0, no)
                        ord2name[idx] = data[no:end].decode('ascii', errors='replace')
        result = []
        for i in range(num_funcs):
            fn_rva = u32(foff + i * 4) if foff else 0
            if fn_rva == 0:
                continue
            ordinal = base + i
            name = ord2name.get(i, f'ord:{ordinal}')
            result.append(name)
        return result or ['(no exports)']
    except Exception as e:
        return [f'ERROR: {e}']


def _read_pe_imports(path: str) -> dict:
    """Parse PE import table → {dll_name: ['name' or 'ord:N', ...]}"""
    import struct
    try:
        with open(path, 'rb') as f:
            data = bytearray(f.read())
        if data[:2] != b'MZ': return {'error': 'not MZ'}
        u16, u32, rva2off, is64, nsec, opt_off = _pe_helpers(data)
        pe = u32(0x3C)
        if data[pe:pe+4] != b'PE\x00\x00': return {'error': 'not PE'}
        # Import directory RVA: offset 104 (32-bit) or 120 (64-bit) in optional header
        imp_rva = u32(opt_off + (120 if is64 else 104))
        if not imp_rva: return {}
        ioff = rva2off(imp_rva)
        imports: dict[str, list] = {}
        while ioff:
            orig_thunk = u32(ioff)      # OriginalFirstThunk
            name_rva   = u32(ioff + 12)
            first_thunk= u32(ioff + 16)
            if not name_rva and not first_thunk:
                break
            # DLL name
            noff = rva2off(name_rva) if name_rva else None
            dll  = data[noff:data.index(0, noff)].decode('ascii', errors='replace') if noff else '?'
            # Walk INT
            toff = rva2off(orig_thunk or first_thunk)
            funcs = []
            if toff:
                while True:
                    if is64:
                        thunk = struct.unpack_from('<Q', data, toff)[0]; toff += 8
                        if not thunk: break
                        if thunk >> 63:
                            funcs.append(f'ord:{thunk & 0xFFFF}')
                        else:
                            ho = rva2off(thunk & 0x7FFFFFFFFFFFFFFF)
                            funcs.append(data[ho+2:data.index(0, ho+2)].decode('ascii', errors='replace') if ho else '?')
                    else:
                        thunk = u32(toff); toff += 4
                        if not thunk: break
                        if thunk >> 31:
                            funcs.append(f'ord:{thunk & 0xFFFF}')
                        else:
                            ho = rva2off(thunk & 0x7FFFFFFF)
                            funcs.append(data[ho+2:data.index(0, ho+2)].decode('ascii', errors='replace') if ho else '?')
            imports[dll] = funcs
            ioff += 20
        return imports
    except Exception as e:
        return {'error': str(e)}
    except Exception as e:
        return [f'ERROR: {e}']


def _probe_dll_exports(path: str) -> list[str]:
    """Return which of our candidate function names exist in the DLL."""
    all_exports = _read_pe_exports(path)
    # Also return ALL exports so debug shows them
    return all_exports


def _load_aksmon() -> bool:
    global _aksmon_lib, _aksmon_fn
    for path in _find_aksmon_paths():
        if not os.path.exists(path) or not path.lower().endswith(".dll"):
            continue
        exports = _probe_dll_exports(path)
        log.info("aksmon candidate %s — exports found: %s", path, exports)
        for fname in exports:
            try:
                lib = ctypes.WinDLL(path)
                fn  = getattr(lib, fname)
                fn.restype  = ctypes.c_int
                fn.argtypes = [ctypes.c_char_p, ctypes.c_ushort,
                               ctypes.POINTER(_AksProgramInfo)]
                _aksmon_lib = lib
                _aksmon_fn  = fn
                log.info("Loaded %s from %s", fname, path)
                return True
            except (OSError, AttributeError) as e:
                log.debug("Cannot bind %s in %s: %s", fname, path, e)
    log.warning("aksmon DLL load failed — no matching export found")
    return False


def _sessions_via_aksmon_dll() -> list[dict]:
    global _aksmon_fn
    if _aksmon_fn is None and not _load_aksmon():
        return []

    sessions = []
    server = b"localhost"
    port   = 475    # original HASP monitoring port
    for prog in range(0, 16):
        pi = _AksProgramInfo()
        pi.program = prog
        try:
            rc = _aksmon_fn(server, port, ctypes.byref(pi))
        except OSError as e:
            log.debug("aksmon call failed: %s", e)
            break
        if rc != 0:
            log.debug("AksNetGetProgramInfo prog=%d rc=%d — stopping", prog, rc)
            break
        log.info("aksmon prog=%d current=%d max=%d", prog, pi.current, pi.maximum)
        for i in range(pi.current):
            lo   = pi.logins[i]
            host = lo.hostname.decode("ascii", errors="replace").rstrip("\x00")
            ip   = lo.loginid.decode("ascii",  errors="replace").rstrip("\x00")
            if host or ip:
                sessions.append({
                    "no":        str(len(sessions) + 1),
                    "host_name": host,
                    "login_id":  ip,
                })
        if pi.current == 0 and prog > 0:
            break   # no more programs

    return sessions


# ---------------------------------------------------------------------------
# Source 2: PowerShell / aksmon tool
# ---------------------------------------------------------------------------

def _sessions_via_powershell_tool() -> list[dict]:
    """Try to find aksmon.exe or similar tools and parse their output."""
    find_cmd = (
        r'$paths = @('
        r'"C:\Program Files\SafeNet Sentinel\Sentinel LDK",'
        r'"C:\Program Files (x86)\SafeNet Sentinel\Sentinel LDK",'
        r'"C:\Program Files\Common Files\SafeNet Sentinel\Sentinel LDK"'
        r'); '
        r'foreach ($p in $paths) { '
        r'  Get-ChildItem $p -Filter "aksmon*.exe" -ErrorAction SilentlyContinue'
        r'  | Select-Object -First 1 -ExpandProperty FullName }'
    )
    tool = _run_ps(find_cmd).strip().splitlines()
    tool = tool[0] if tool else ""

    sessions = []
    if tool and os.path.exists(tool):
        for flag in ["/list", "-list", "/query", "-query"]:
            try:
                r = subprocess.run([tool, flag], capture_output=True,
                                   text=True, timeout=10)
                out = r.stdout.strip()
                if not out:
                    continue
                for line in out.splitlines():
                    parts = line.split()
                    ip   = next((p for p in parts
                                 if re.match(r'\d+\.\d+\.\d+\.\d+$', p)), "")
                    host = next((p for p in parts
                                 if "." in p and not re.match(r'[\d.]+$', p)), "")
                    if ip or host:
                        sessions.append({
                            "no": str(len(sessions)+1),
                            "host_name": host,
                            "login_id":  ip,
                        })
                if sessions:
                    break
            except Exception as e:
                log.debug("aksmon tool %s: %s", flag, e)

    return sessions


# ---------------------------------------------------------------------------
# WMI / PowerShell helpers
# ---------------------------------------------------------------------------

def _run_ps(command: str, timeout: int = 10) -> str:
    """
    Run a PowerShell command and return stdout as a UTF-8 string.
    Forces PowerShell's output encoding to UTF-8 so Hebrew display names
    survive the trip back to Python.
    """
    # Force UTF-8 output + strip UNC paths from PSModulePath to avoid DC timeouts
    preamble = (
        "[Console]::OutputEncoding = [System.Text.Encoding]::UTF8; "
        "$OutputEncoding = [System.Text.Encoding]::UTF8; "
        "$env:PSModulePath = ($env:PSModulePath -split ';' "
        "| Where-Object { $_ -notmatch '^\\\\\\\\' }) -join ';'; "
    )
    full_cmd = preamble + command
    try:
        result = subprocess.run(
            ["powershell", "-NonInteractive", "-NoProfile", "-Command", full_cmd],
            capture_output=True, timeout=timeout
        )
        # Decode as UTF-8; fall back gracefully on any bad bytes
        stdout = (result.stdout or b"").decode("utf-8", errors="replace")
        return stdout.strip()
    except (subprocess.TimeoutExpired, FileNotFoundError) as e:
        log.warning("PowerShell error: %s", e)
        return ""


def get_logged_on_user(hostname: str, ip: str = "") -> str | None:
    """
    Returns 'DOMAIN\\username' of the currently logged-on user.
    Tries three methods in order, each against IP-first then hostname:
      1. Win32_ComputerSystem.UserName  (fast, interactive console only)
      2. quser /server:<target>         (catches all active sessions)
      3. Win32_LoggedOnUser             (interactive + RemoteInteractive)
    """
    # Build target list: IP first (avoids DNS issues), then short name, then FQDN
    seen, targets = set(), []
    for c in [ip, hostname.split(".")[0] if hostname else "", hostname]:
        if c and c not in seen:
            seen.add(c)
            targets.append(c)

    # --- Method 1: Win32_ComputerSystem.UserName ---
    for target in targets:
        cmd = (
            f"$cs = Get-WmiObject Win32_ComputerSystem -ComputerName '{target}' "
            f"-ErrorAction SilentlyContinue; if ($cs) {{ $cs.UserName }}"
        )
        out = _run_ps(cmd)
        if out:
            log.info("WMI CS.UserName via '%s': %s", target, out)
            return out

    # --- Method 2: quser (Terminal Services session list) ---
    for target in targets:
        cmd = (
            f"$r = (quser /server:{target} 2>&1); "
            f"$r | Select-Object -Skip 1 | ForEach-Object {{ "
            f"  if ($_ -match '^[>\\s]*([\\w\\.\\-]+)\\s') {{ $Matches[1] }} "
            f"}}"
        )
        out = _run_ps(cmd, timeout=8)
        if out:
            user = out.strip().splitlines()[0].strip().lstrip(">")
            if user:
                # quser returns just the SAMAccountName; prepend domain
                domain_user = f"SW\\{user}" if "\\" not in user else user
                log.info("quser via '%s': %s", target, domain_user)
                return domain_user

    # --- Method 3: Win32_LoggedOnUser (interactive + remote sessions) ---
    for target in targets:
        cmd = (
            f"Get-WmiObject Win32_LoggedOnUser -ComputerName '{target}' "
            f"-ErrorAction SilentlyContinue | ForEach-Object {{ "
            f"  $a = $_.Antecedent; "
            f"  if ($a -match 'Domain=\"([^\"]+)\",Name=\"([^\"]+)\"') {{ "
            f"    $d = $Matches[1]; $u = $Matches[2]; "
            f"    if ($d -notmatch '^(NT AUTHORITY|WINDOW MANAGER|Font Driver|DWM)' -and $u -ne 'SYSTEM') {{ "
            f"      \"$d\\$u\" "
            f"    }} "
            f"  }} "
            f"}} | Select-Object -First 1"
        )
        out = _run_ps(cmd, timeout=10)
        if out:
            log.info("Win32_LoggedOnUser via '%s': %s", target, out)
            return out.strip().splitlines()[0].strip()

    log.debug("All user-lookup methods failed for host='%s' ip='%s'", hostname, ip)
    return None


def get_display_name(domain_user: str) -> str | None:
    """
    Given 'DOMAIN\\username' (or bare username), returns the AD DisplayName
    by querying DC01 directly.  Strips the company suffix if present.
    Falls back to the SAM account name if the AD lookup fails.
    """
    if not domain_user:
        return None
    username = domain_user.split("\\")[-1].strip()
    if not username:
        return None

    COMPANY_SUFFIX = " -סלימאן וישאחי מהנדסים ויועצים בעמ"

    # Query DC01 explicitly so the lookup works even when the AD PS module
    # isn't imported on the local machine's default session path.
    cmd = (
        "$dn = $null; "
        "try { "
        "  Import-Module ActiveDirectory -ErrorAction SilentlyContinue; "
        f"  $dn = (Get-ADUser '{username}' -Server DC01 "
        "    -Properties DisplayName -ErrorAction SilentlyContinue).DisplayName "
        "} catch {}; "
        "if (-not $dn) { "
        # Fallback: ADSI DirectorySearcher — works without AD module
        f"  $s = New-Object DirectoryServices.DirectorySearcher([ADSI]'LDAP://DC01'); "
        f"  $s.Filter = '(sAMAccountName={username})'; "
        "  $s.PropertiesToLoad.Add('displayName') | Out-Null; "
        "  $r = $s.FindOne(); "
        "  if ($r) { $dn = $r.Properties['displayName'][0] } "
        "}; "
        "$dn"
    )
    out = _run_ps(cmd, timeout=10).strip()

    name = out if out else username
    if name.endswith(COMPANY_SUFFIX):
        name = name[: -len(COMPANY_SUFFIX)].strip()
    log.debug("get_display_name('%s') -> '%s'", domain_user, name)
    return name or username


# ---------------------------------------------------------------------------
# Main data aggregation
# ---------------------------------------------------------------------------

def build_station_list() -> list[dict]:
    """
    Returns a list of dicts describing each occupied license slot:
      {slot, host_name, ip, domain_user, display_name, status}
    """
    sessions = get_hasp_sessions()
    result = []
    for s in sessions:
        host = s["host_name"]
        ip   = s.get("login_id", "")

        domain_user  = get_logged_on_user(host, ip)
        display_name = get_display_name(domain_user) if domain_user else None

        result.append({
            "slot":         s.get("no", ""),
            "host_name":    host,
            "ip":           ip,
            "domain_user":  domain_user  or "",
            "display_name": display_name or domain_user or "(unknown)",
            "status":       "active",
        })
    return result


# ---------------------------------------------------------------------------
# Flask routes
# ---------------------------------------------------------------------------

HTML = r"""
<!DOCTYPE html>
<html lang="he" dir="rtl">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>מי משתמש בבנארית?</title>
  <style>
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

    body {
      font-family: 'Segoe UI', Arial, 'David', sans-serif;
      background: #f0f2f5;
      color: #222;
      min-height: 100vh;
      display: flex;
      flex-direction: column;
      align-items: center;
      padding: 2rem 1rem;
      direction: rtl;
    }

    header {
      width: 100%;
      max-width: 800px;
      display: flex;
      align-items: center;
      justify-content: space-between;
      margin-bottom: 1.5rem;
    }

    header h1 {
      font-size: 1.4rem;
      font-weight: 600;
      color: #1a1a2e;
      display: flex;
      align-items: center;
      gap: 0.5rem;
    }

    header h1 svg { flex-shrink: 0; }

    #status-bar {
      font-size: 0.78rem;
      color: #666;
      text-align: left;
    }

    #status-bar .dot {
      display: inline-block;
      width: 8px; height: 8px;
      border-radius: 50%;
      background: #4caf50;
      margin-left: 4px;
      vertical-align: middle;
      transition: background 0.3s;
    }
    #status-bar .dot.stale { background: #f0a500; }
    #status-bar .dot.error { background: #e53935; }

    .card {
      width: 100%;
      max-width: 800px;
      background: #fff;
      border-radius: 10px;
      box-shadow: 0 2px 12px rgba(0,0,0,.08);
      overflow: hidden;
    }

    .card-header {
      padding: 1rem 1.5rem;
      border-bottom: 1px solid #eee;
      display: flex;
      align-items: center;
      justify-content: space-between;
    }

    .card-header .title { font-weight: 600; font-size: 0.95rem; }

    .badge {
      display: inline-flex;
      align-items: center;
      gap: 4px;
      padding: 2px 10px;
      border-radius: 999px;
      font-size: 0.78rem;
      font-weight: 600;
    }
    .badge-blue  { background: #e3f2fd; color: #1565c0; }
    .badge-green { background: #e8f5e9; color: #2e7d32; }
    .badge-gray  { background: #f5f5f5; color: #666; }

    table {
      width: 100%;
      border-collapse: collapse;
    }

    thead th {
      padding: 0.7rem 1.5rem;
      text-align: right;
      font-size: 0.75rem;
      font-weight: 600;
      color: #888;
      text-transform: uppercase;
      letter-spacing: 0.05em;
      background: #fafafa;
      border-bottom: 1px solid #eee;
    }

    tbody tr {
      border-bottom: 1px solid #f3f3f3;
      transition: background 0.15s;
    }
    tbody tr:last-child { border-bottom: none; }
    tbody tr:hover { background: #f9f9ff; }

    tbody td {
      padding: 0.85rem 1.5rem;
      font-size: 0.88rem;
      vertical-align: middle;
    }

    .display-name {
      font-weight: 600;
      color: #1a1a2e;
    }

    .sub {
      font-size: 0.76rem;
      color: #888;
      margin-top: 1px;
    }

    .slot-badge {
      display: inline-flex;
      align-items: center;
      justify-content: center;
      width: 28px; height: 28px;
      border-radius: 50%;
      background: #e3f2fd;
      color: #1565c0;
      font-weight: 700;
      font-size: 0.82rem;
    }

    #empty-state {
      display: none;
      flex-direction: column;
      align-items: center;
      justify-content: center;
      padding: 3rem;
      color: #aaa;
      font-size: 0.9rem;
      gap: 0.6rem;
    }
    #empty-state svg { opacity: 0.35; }

    #loading {
      display: flex;
      align-items: center;
      justify-content: center;
      padding: 3rem;
      color: #999;
      font-size: 0.9rem;
      gap: 0.5rem;
    }
    .spinner {
      width: 18px; height: 18px;
      border: 2px solid #ddd;
      border-top-color: #1565c0;
      border-radius: 50%;
      animation: spin 0.8s linear infinite;
    }
    @keyframes spin { to { transform: rotate(360deg); } }
  </style>
</head>
<body>

<header>
  <h1>
    <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="#1565c0" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
      <rect x="2" y="3" width="20" height="14" rx="2"/><path d="M8 21h8M12 17v4"/>
    </svg>
    מי משתמש בבנארית?
  </h1>
  <div id="status-bar">
    <span class="dot" id="dot"></span>
    <span id="status-text">טוען…</span>
  </div>
</header>

<div class="card">
  <div class="card-header">
    <span class="title">משתמשים פעילים</span>
    <span class="badge badge-blue" id="slot-count">— / —</span>
  </div>

  <div id="loading"><div class="spinner"></div> מאחזר נתונים…</div>

  <div id="empty-state">
    <svg width="40" height="40" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
      <circle cx="12" cy="12" r="10"/><path d="M8 12h8M12 8v8"/>
    </svg>
    אין משתמשים פעילים כרגע
  </div>

  <table id="table" style="display:none">
    <thead>
      <tr>
        <th>#</th>
        <th>משתמש</th>
        <th>תחנת עבודה</th>
        <th>כתובת IP</th>
      </tr>
    </thead>
    <tbody id="tbody"></tbody>
  </table>
</div>

<script>
  const REFRESH_MS = 30000;
  let lastOk = null;

  function setStatus(state, text) {
    document.getElementById('status-text').textContent = text;
    const dot = document.getElementById('dot');
    dot.className = 'dot' + (state === 'ok' ? '' : state === 'stale' ? ' stale' : ' error');
  }

  async function refresh() {
    try {
      const resp = await fetch('/api/sessions');
      if (!resp.ok) throw new Error('HTTP ' + resp.status);
      const data = await resp.json();
      render(data);
      lastOk = new Date();
      setStatus('ok', 'עודכן ' + lastOk.toLocaleTimeString());
    } catch (e) {
      const ago = lastOk ? `עדכון אחרון ${lastOk.toLocaleTimeString()}` : 'שגיאת חיבור';
      setStatus('error', ago);
    }
  }

  function render(stations) {
    const loading   = document.getElementById('loading');
    const emptyEl   = document.getElementById('empty-state');
    const table     = document.getElementById('table');
    const tbody     = document.getElementById('tbody');
    const slotCount = document.getElementById('slot-count');

    loading.style.display = 'none';

    if (!stations.length) {
      emptyEl.style.display = 'flex';
      table.style.display   = 'none';
      slotCount.textContent = '0 פעילים';
      slotCount.className   = 'badge badge-gray';
      return;
    }

    emptyEl.style.display = 'none';
    table.style.display   = '';
    slotCount.textContent = stations.length + ' פעילים';
    slotCount.className   = 'badge badge-green';

    tbody.innerHTML = stations.map((s, i) => `
      <tr>
        <td><span class="slot-badge">${s.slot || (i+1)}</span></td>
        <td>
          <div class="display-name">${esc(s.display_name)}</div>
          ${s.domain_user ? '<div class="sub">' + esc(s.domain_user) + '</div>' : ''}
        </td>
        <td><div>${esc(s.host_name)}</div></td>
        <td><div>${esc(s.ip)}</div></td>
      </tr>`
    ).join('');
  }

  function esc(s) {
    return String(s ?? '').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
  }

  refresh();
  setInterval(refresh, REFRESH_MS);
</script>
<footer style="
  margin-top: 2rem;
  padding: 0.75rem 1rem;
  text-align: center;
  font-size: 0.78rem;
  color: #888;
  direction: rtl;
">
  תכנון וביצוע: עופר אהרון &copy; 2026 &nbsp;|&nbsp;
  <a href="mailto:ofer@sw-eng.co.il" style="color:#888; text-decoration:none;">ofer@sw-eng.co.il</a>
</footer>
</body>
</html>
"""


@app.route("/")
def index():
    return render_template_string(HTML)


@app.route("/api/debug")
def api_debug():
    """
    Diagnostic endpoint.  Open http://localhost:5000/api/debug to troubleshoot.
    """
    # Seed session cookies first
    _acc_get("/_int_/sessions.html")

    # Extract real HASP ID
    raw_feat = _acc_get("/_int_/tab_feat.html", {"haspid": "0"})
    feat_objs = _parse_acc_json(raw_feat) or []
    real_haspid = "0"
    for obj in feat_objs:
        if isinstance(obj, dict) and "fhaspid" not in obj:
            h = obj.get("haspid", "0")
            if h and h != "0":
                real_haspid = h
                break

    probes = [
        # Try every plausible login/session endpoint
        ("/_int_/tab_login.html",    {"haspid": real_haspid, "prod": "0", "fea": "0"}),
        ("/_int_/tab_login.html",    {"haspid": "0", "prod": "0", "fea": "0"}),
        ("/_int_/tab_detach.html",   {"haspid": real_haspid}),
        ("/_int_/tab_clients.html",  {"haspid": real_haspid}),
        ("/_int_/tab_clients.html",  {}),
        ("/_int_/tab_sessions.html", {"haspid": real_haspid, "prod": "0", "fea": "0"}),
    ]

    results = {"real_haspid_found": real_haspid}

    # HTTP ACC probes
    for path, params in probes:
        key = path + (("?" + "&".join(f"{k}={v}" for k, v in params.items())) if params else "")
        raw = _acc_get(path, params or None)
        if raw is None:
            results[key] = {"status": "no response"}
        else:
            results[key] = {
                "status": "ok",
                "bytes": len(raw),
                "raw": raw[:2000],
                "parsed": _parse_acc_json(raw),
            }

    # aksmon DLL probe — search dynamically
    found_paths  = _find_aksmon_paths()
    existing     = [p for p in found_paths if os.path.exists(p)]
    dll_exports  = {p: _probe_dll_exports(p)
                    for p in existing if p.lower().endswith(".dll")}
    dll_loaded   = (_aksmon_fn is not None) or _load_aksmon()
    dll_sessions = _sessions_via_aksmon_dll() if dll_loaded else []
    aksmon_proc_modules = _run_ps(
        "Get-Process -Name AksMon,aksmon,AksMon32,AksMon64 -ErrorAction SilentlyContinue "
        "| ForEach-Object { $_.Modules | Select-Object -ExpandProperty FileName }",
        timeout=8
    ).splitlines()

    results["aksmon_dll"] = {
        "paths_existing":       existing,
        "exports_found":        dll_exports,
        "aksmon_process_dlls":  [m.strip() for m in aksmon_proc_modules if m.strip()],
        "dll_loaded":           dll_loaded,
        "sessions":             dll_sessions,
    }

    # ---- PE import table of aksmon.exe -- find what it imports from each DLL --
    aksmon_exe = r"C:\Program Files (x86)\Aladdin\Monitor\aksmon.exe"
    if os.path.exists(aksmon_exe):
        imports = _read_pe_imports(aksmon_exe)
        ge_imports  = {k: v for k, v in imports.items() if "aksmon" in k.lower() or "aks" in k.lower()}
        nhl_imports = imports.get("NHLMINST.dll", imports.get("NHLMINST.DLL", []))
        results["aksmon_exe_imports"] = {
            "aksmon_ge_imports": ge_imports,
            "nhlminst_imports":  nhl_imports,
            "all_dlls":         list(imports.keys()),
            "all_imports":      {k: v for k, v in imports.items()
                                 if k.upper() not in (
                                     "KERNEL32.DLL", "USER32.DLL", "GDI32.DLL",
                                     "ADVAPI32.DLL", "SHELL32.DLL", "SHLWAPI.DLL",
                                     "COMCTL32.DLL", "OLE32.DLL", "OLEAUT32.DLL",
                                     "OLEDLG.DLL", "COMDLG32.DLL", "WINSPOOL.DRV")},
        }
    else:
        results["aksmon_exe_imports"] = {"error": "aksmon.exe not found"}

    # ---- Find NHLMINST.dll and inspect its exports --------------------------
    nhl_search_dirs = [
        r"C:\Program Files (x86)\Aladdin\Monitor",
        r"C:\Windows\SysWOW64",
        r"C:\Windows\System32",
        r"C:\Program Files (x86)\Aladdin",
        r"C:\Program Files\Aladdin\Monitor",
    ]
    nhl_found = []
    for d in nhl_search_dirs:
        p = os.path.join(d, "NHLMINST.dll")
        if os.path.exists(p):
            nhl_found.append({"path": p, "exports": _read_pe_exports(p)})
    nhl_where = _run_ps("(Get-Command NHLMINST.dll -ErrorAction SilentlyContinue).Source", timeout=5)
    if nhl_where and os.path.exists(nhl_where):
        nhl_found.append({"path": nhl_where, "exports": _read_pe_exports(nhl_where)})
    results["nhlminst_dll"] = nhl_found or "not_found"

    # ---- NHLMINST.dll HaspLMInfo probe (Session-0 safe) ---------------------
    _ord_preamble = (
        "$env:PSModulePath = ($env:PSModulePath -split \';\' "
        "| Where-Object { $_ -notmatch \'^\\\\\\\\\' }) -join \';\'; "
    )
    try:
        _ord_result = subprocess.run(
            [_PS32, "-NonInteractive", "-NoProfile", "-Command", _ord_preamble + _ORDINAL_PS],
            capture_output=True, text=True, timeout=60
        )
        ordinal_raw    = _ord_result.stdout.strip()
        ordinal_stderr = _ord_result.stderr.strip()
    except subprocess.TimeoutExpired:
        ordinal_raw, ordinal_stderr = "", "TIMEOUT"
    except Exception as _e:
        ordinal_raw, ordinal_stderr = "", str(_e)
    ordinal_sessions = _sessions_via_ordinal()
    results["ordinal_probe"] = {
        "raw_output":  ordinal_raw,
        "stderr":      ordinal_stderr,
        "sessions":    ordinal_sessions,
    }

    # ---- HASP LM process + port check -------------------------------------
    hasp_procs = _run_ps(
        "Get-Process -ErrorAction SilentlyContinue "
        "| Where-Object { $_.Name -match 'hasp|sentinel|nhsrv|aksmon|aladdin' } "
        "| Select-Object Name,Id,SessionId | Format-Table -HideTableHeaders | Out-String",
        timeout=8
    )
    port475 = _run_ps(
        "netstat -ano | Select-String ':475\\s'",
        timeout=5
    )
    port1947 = _run_ps(
        "netstat -ano | Select-String ':1947\\s'",
        timeout=5
    )
    results["hasp_system"] = {
        "hasp_processes": [l.strip() for l in hasp_procs.splitlines() if l.strip()],
        "port_475_bindings":  [l.strip() for l in port475.splitlines() if l.strip()],
        "port_1947_bindings": [l.strip() for l in port1947.splitlines() if l.strip()],
    }

    # ---- Named pipe scan --------------------------------------------------
    named_pipes = _run_ps(
        r"try { [System.IO.Directory]::GetFiles('\\\\.\\pipe\\') "
        r"| Where-Object { $_ -match 'hasp|aladdin|sentinel|aks|nhl' -i } } catch {}",
        timeout=8
    )
    results["hasp_named_pipes"] = [p.strip() for p in named_pipes.splitlines() if p.strip()]

    # ---- Sentinel ACC exhaustive prod/fea sweep ---------------------------
    # Also try full raw HTTP probe for tab_clients (capture actual status code)
    acc_sweep = {}
    try:
        for prod in range(10):
            raw = _acc_get("/_int_/tab_sessions.html",
                           {"haspid": real_haspid, "prod": str(prod), "fea": "0"})
            parsed = _parse_acc_json(raw) if raw else []
            cnt_val = int(parsed[0].get("cnt", "0")) if parsed else -1
            acc_sweep["prod" + str(prod) + "_fea0"] = cnt_val
            if cnt_val > 0:
                cli = _acc_get("/_int_/tab_clients.html",
                               {"haspid": real_haspid, "prod": str(prod), "fea": "0"})
                acc_sweep["SESSIONS_prod" + str(prod) + "_fea0"] = {
                    "sessions_raw": raw[:800] if raw else None,
                    "clients_raw":  cli[:800] if cli else None,
                }
        try:
            cli_r = _acc_session.get(
                HASP_URL + "/_int_/tab_clients.html",
                params={"haspid": real_haspid, "prod": "0", "fea": "0"},
                timeout=5, allow_redirects=False
            )
            acc_sweep["tab_clients_status"] = cli_r.status_code
            acc_sweep["tab_clients_body"]   = cli_r.text[:300]
        except Exception as _ce:
            acc_sweep["tab_clients_status"] = str(_ce)
        for extra_path in ["/_int_/hasp.html", "/_int_/tab_feat.html"]:
            raw_ex = _acc_get(extra_path, {"haspid": real_haspid})
            acc_sweep[extra_path] = (raw_ex[:400] if raw_ex else "no_response")
    except Exception as _e2:
        acc_sweep["error"] = str(_e2)
    results["acc_sweep"] = acc_sweep

    # ---- UDP port 475 probe (127.0.0.1 + local NIC + broadcast) -----------
    import socket as _sock
    local_ip = "127.0.0.1"
    try:
        _ls = _sock.socket(_sock.AF_INET, _sock.SOCK_DGRAM)
        _ls.connect(("8.8.8.8", 80))
        local_ip = _ls.getsockname()[0]
        _ls.close()
    except Exception:
        pass
    subnet_bcast = ".".join(local_ip.split(".")[:3]) + ".255"
    udp_debug = {"local_ip": local_ip}
    for target in list(dict.fromkeys(["127.0.0.1", local_ip, subnet_bcast])):
        for q_hex in ["000300000000", "050000030000", "4800000000000000"]:
            key = "udp475_" + target + "_" + q_hex[:8]
            try:
                s = _sock.socket(_sock.AF_INET, _sock.SOCK_DGRAM)
                s.setsockopt(_sock.SOL_SOCKET, _sock.SO_BROADCAST, 1)
                s.settimeout(1)
                s.sendto(bytes.fromhex(q_hex), (target, 475))
                d2, addr = s.recvfrom(4096)
                s.close()
                udp_debug[key] = {"bytes": len(d2), "from": str(addr), "hex": d2.hex()}
            except Exception as eu:
                udp_debug[key] = {"error": str(eu)}
    results["udp_probes"] = udp_debug

    # ---- TCP port 475 probe (nhsrvice.exe) ---------------------------------
    tcp475 = {}
    try:
        import socket as _tsock
        ts = _tsock.socket(_tsock.AF_INET, _tsock.SOCK_STREAM)
        ts.settimeout(3)
        ts.connect(("127.0.0.1", 475))
        tcp475["connected"] = True
        ts.settimeout(1)
        try:
            banner = ts.recv(256)
            tcp475["banner_hex"] = banner.hex()
            tcp475["banner_ascii"] = banner.decode("ascii", errors="replace")
        except Exception:
            tcp475["banner"] = "none"
        # Try various probe packets and record responses
        probes475 = [
            ("nh_getinfo",  "000300000000"),
            ("nh_broad",    "050000030000"),
            ("hasp_h",      "4800030000000000"),
            ("hasp_hm",     "480000000000"),
            ("tcp_hello",   "48454c4c4f00"),
            ("nul6",        "000000000000"),
            ("ff6",         "ffffffffffff"),
        ]
        for pname, phex in probes475:
            try:
                ts.send(bytes.fromhex(phex))
                ts.settimeout(1)
                resp = ts.recv(1024)
                tcp475["resp_" + pname] = resp.hex()
            except Exception as pe:
                tcp475["resp_" + pname] = str(pe)
        ts.close()
    except Exception as te:
        tcp475["error"] = str(te)
    results["tcp_475_probe"] = tcp475

    # ---- TCP command scan: try L=3 payloads cmd 0x00..0x1F ------------------
    import socket as _s475
    tcp_scan = {}
    interesting = {}
    cmds_to_try = list(range(0x20)) + [0x30, 0x40, 0x50, 0x80, 0xFE, 0xFF]
    for cmd in cmds_to_try:
        for plen in [1, 3, 5]:
            try:
                payload = bytes([cmd] + [0] * (plen - 1))
                packet  = bytes([0x00, plen]) + payload
                sc = _s475.socket(_s475.AF_INET, _s475.SOCK_STREAM)
                sc.settimeout(2)
                sc.connect(("127.0.0.1", 475))
                sc.send(packet)
                sc.settimeout(1)
                try:
                    resp = sc.recv(1024)
                    not_ff = resp and not all(b >= 0xFE for b in resp[:8])
                    key = "L" + str(plen) + "_x" + format(cmd, "02x")
                    tcp_scan[key] = resp.hex()[:80]
                    if not_ff:
                        interesting[key] = resp.hex()
                except Exception as re2:
                    pass
                sc.close()
            except Exception:
                pass
    results["tcp_cmd_scan"] = {
        "interesting_cmds": interesting,
        "all_results_sample": {k: v for k, v in list(tcp_scan.items())[:20]},
    }

    # ---- Find nhsrvice.exe and read its strings ----------------------------
    nhsrv_svc_path = _run_ps(
        "(Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\nhsrvice' "
        "-ErrorAction SilentlyContinue).ImagePath",
        timeout=5
    ).strip().strip('"')
    results["nhsrvice_reg_path"] = nhsrv_svc_path

    # Also search common locations
    nhsrv_candidates = [
        nhsrv_svc_path,
        r"C:\Windows\System32\nhsrvice.exe",
        r"C:\Windows\SysWOW64\nhsrvice.exe",
        r"C:\Program Files (x86)\Aladdin\nhsrvice.exe",
        r"C:\Program Files\Aladdin\nhsrvice.exe",
    ]
    nhsrv_found = next((p for p in nhsrv_candidates if p and os.path.exists(p)), None)
    results["nhsrvice_exe_path"] = nhsrv_found
    if nhsrv_found:
        try:
            raw_bin = open(nhsrv_found, "rb").read()
            all_strs = re.findall(rb"[ -~]{5,}", raw_bin)
            keywords = [b"pipe", b"session", b"login", b"monitor", b"hasp",
                        b"socket", b"shared", b"mutex", b"semaphor", b"event",
                        b"memory", b"server", b"port", b"listen"]
            matched = [s.decode("ascii", errors="ignore") for s in all_strs
                       if any(k in s.lower() for k in keywords)]
            results["nhsrvice_strings"] = matched[:80]
        except Exception as be:
            results["nhsrvice_strings"] = str(be)

    # ---- Full named pipe list (unfiltered) ---------------------------------
    all_pipes_raw = _run_ps(
        r"try { [System.IO.Directory]::GetFiles('\\.\pipe\') | Select-Object -First 200 } catch {}",
        timeout=6
    )
    results["all_named_pipes"] = [p.strip() for p in all_pipes_raw.splitlines() if p.strip()]

    # ---- Aladdin registry tree --------------------------------------------
    ald_reg = _run_ps(
        "Get-ChildItem 'HKLM:\\SOFTWARE\\Wow6432Node\\Aladdin' -Recurse -ErrorAction SilentlyContinue "
        "| Select-Object -ExpandProperty Name",
        timeout=8
    )
    results["aladdin_registry"] = [l.strip() for l in ald_reg.splitlines() if l.strip()]

    # ---- COM / registry scan for HASP objects ------------------------------
    com_scan = _run_ps(
        r"$out=@(); "
        r"'HKLM:\SOFTWARE\Classes','HKLM:\SOFTWARE\Wow6432Node\Classes' | ForEach-Object { "
        r"  $root=$_; "
        r"  if (Test-Path $root) { "
        r"    Get-ChildItem $root -ErrorAction SilentlyContinue | "
        r"    Where-Object { $_.Name -match 'hasp|aladdin|nhsrv|aksmon|nhl|sentinel' } | "
        r"    ForEach-Object { $out += $_.Name } "
        r"  } "
        r"}; "
        r"$out | Select-Object -Unique",
        timeout=12
    )
    com_clsids = _run_ps(
        r"$out=@(); "
        r"'HKLM:\SOFTWARE\Classes\CLSID','HKLM:\SOFTWARE\Wow6432Node\Classes\CLSID' | ForEach-Object { "
        r"  $root=$_; "
        r"  if (Test-Path $root) { "
        r"    Get-ChildItem $root -ErrorAction SilentlyContinue | ForEach-Object { "
        r"      $def=$_.GetValue(''); "
        r"      if ($def -match 'hasp|aladdin|nhsrv|aksmon|nhl|sentinel') { $out += ($_.Name + ' = ' + $def) } "
        r"    } "
        r"  } "
        r"}; "
        r"$out | Select-Object -Unique",
        timeout=12
    )
    results["com_scan"] = {
        "progids": [l.strip() for l in com_scan.splitlines() if l.strip()],
        "clsids":  [l.strip() for l in com_clsids.splitlines() if l.strip()],
    }

    # ---- nhsrvice.exe binary scan for embedded strings ---------------------
    nhsrv_strings = _run_ps(
        r"$path = (Get-Process -Name nhsrvice -ErrorAction SilentlyContinue | "
        r"  Select-Object -First 1 -ExpandProperty Path); "
        r"if ($path) { "
        r"  $bytes = [System.IO.File]::ReadAllBytes($path); "
        r"  $txt = [System.Text.Encoding]::ASCII.GetString($bytes); "
        r"  $matches_ = [regex]::Matches($txt, '[\x20-\x7e]{6,}'); "
        r"  $matches_ | Select-Object -ExpandProperty Value | "
        r"  Where-Object { $_ -match 'pipe|session|login|monitor|hasp|aks|nhl|port|socket|shared' -i } | "
        r"  Select-Object -Unique -First 60 "
        r"} else { 'nhsrvice not found' }",
        timeout=15
    )
    results["nhsrvice_strings"] = [l.strip() for l in nhsrv_strings.splitlines() if l.strip()]

    # ---- UI Automation probe -----------------------------------------------
    ui_raw = _run_ps(_UI_AUTO_PS, timeout=15)
    results["ui_automation"] = {
        "raw_output": ui_raw,
        "sessions":   _parse_ui_auto_output(ui_raw) if ui_raw else [],
    }

    # ---- Win32 ListView reader (32-bit PS) ---------------------------------
    lv_raw = _run_ps32(_LV_CS, timeout=25)
    results["listview_reader"] = {
        "raw_output": lv_raw,
        "sessions":   _parse_lv_output(lv_raw) if lv_raw else [],
    }

    return jsonify(results)


@app.route("/api/sessions")
def api_sessions():
    try:
        data = build_station_list()
        return jsonify(data)
    except Exception as e:
        log.exception("Error building station list")
        return jsonify({"error": str(e)}), 500


if __name__ == "__main__":
    log.info("Starting Aladdin License Monitor on %s:%d", LISTEN_HOST, LISTEN_PORT)
    app.run(host=LISTEN_HOST, port=LISTEN_PORT, debug=False)
