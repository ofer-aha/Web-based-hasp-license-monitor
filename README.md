# hasp-license-monitor

Aladdin License Monitor is a Windows-hosted Flask web application that shows, in real time, who is currently consuming one of the 10 available Bentley BenARIT license seats from an Aladdin HASP HL USB dongle.

It runs on `SWCOMP99`, the server that hosts the physical dongle, and exposes a Hebrew RTL web UI at `http://swcomp99:5000` for users on the local network.

## Features

- Real-time visibility into active BenARIT license consumers
- Resolves workstation login to employee display name via Active Directory
- Shows user name, workstation name, IP address, and slot information
- Hebrew right-to-left web interface
- Auto-refresh every 30 seconds
- Startup watchdog with automatic restart on crash
- Runs as a Windows Scheduled Task

## Purpose and Overview

The application is designed to answer a simple operational question: **who is currently using BenARIT?**

The monitor queries the legacy NetHASP license manager actually serving BenARIT seats, enriches the raw session data with Windows and Active Directory identity information, and serves the results through a lightweight web interface.

## System Environment

| Component | Details |
|---|---|
| License server host | `SWCOMP99` (Windows, domain `sw.local`) |
| Domain controller | `DC01` |
| HASP dongle | Aladdin HASP HL, Key ID `147558057` |
| License type | NetHASP, 10 seats, Program 3 |
| Protected software | Bentley BenARIT |
| Web server port | `5000` |
| Python version | 3.13 |
| Run-as account | `SW\swadmin` |

## How It Works

Two license manager layers exist on the host:

1. **Sentinel HASP LM** (`hasplms.exe`, port `1947`)  
   Exposes the Sentinel Admin Control Center, but does not report the active BenARIT NetHASP sessions on this installation.

2. **NetHASP License Manager** (`nhsrvice.exe`, port `475`)  
   This is the service that actually manages the BenARIT license seats.

Because `nhsrvice.exe` has no documented public API for this use case, the application queries sessions through `hsmon.dll`, using its exported native function `mightyfunc`.

## Session Discovery

Active sessions are retrieved through `hsmon.dll::mightyfunc` using a generated 32-bit helper executable.

### Command flow

1. `SCAN SERVERS`
2. Poll `GET SERVERS` until scan completes
3. `GET MODULES,ID=<server-id>`
4. `GET SLOTS,ID=<server-id>,MA="1"`
5. `GET LOGINS,ID=<server-id>,MA="1",SLOT=<slot>`

Each login record returns the client workstation and IP information, which is then enriched by the Python app.

## 32-bit Helper Executable

`hsmon.dll` is 32-bit, so it cannot be called directly from a 64-bit Python process. To bridge that gap:

- `server.py` embeds C# source for `_mfquery.cs`
- On first use, the app compiles it with:
  - `C:\Windows\Microsoft.NET\Framework\v4.0.30319\csc.exe /platform:x86`
- The compiled `_mfquery.exe` is reused on subsequent runs
- `_mfquery.exe` loads `hsmon.dll`, calls `mightyfunc`, and emits parsed session lines to stdout
- Python reads and transforms those lines into session objects

## User Identification

A raw HASP session contains only hostname and IP. The app resolves the user in two stages:

1. **Logged-on Windows user**  
   Queried from the client workstation using WMI / `quser` fallback logic.

2. **Employee display name**  
   Looked up in Active Directory on `DC01` using either:
   - `Get-ADUser`
   - `.NET DirectorySearcher` via LDAP

This produces display values such as a full Hebrew employee name alongside the domain username.

## Request Flow

Each `GET /api/sessions` call performs the following:

1. Run `_mfquery.exe`
2. Parse active HASP sessions
3. Resolve workstation login to `SW\\username`
4. Resolve `DisplayName` from Active Directory
5. Build the response objects
6. Return JSON to the browser

Example response:

```json name=api-response.json
[
  {
    "slot": "1",
    "host_name": "SWCOMP117",
    "ip": "10.0.0.203",
    "domain_user": "SW\\meirav",
    "display_name": "Meirav Cohen",
    "status": "active"
  }
]
```

## Web Interface

The frontend is embedded directly in `server.py` as an HTML string.

### UI characteristics

- Hebrew UI
- `dir="rtl"`
- Title: **Who is using BenARIT?**
- Live status indicator
- Active-user count badge
- Table columns:
  - Slot number
  - Display name + domain username
  - Workstation name
  - IP address

### Refresh behavior

- Fetches `/api/sessions` every 30 seconds
- First fetch runs immediately on page load
- Status indicator becomes stale if the last successful refresh is older than 60 seconds

## Startup and Service

The application is intended to run automatically at machine startup.

### `install_service.bat`

Creates a Windows Scheduled Task named `AladdinLicenseMonitor` using `schtasks`.

| Parameter | Value |
|---|---|
| Trigger | On system startup |
| Program | `python start_server.py` |
| Run-as | `SW\swadmin` |
| Privilege | Highest |
| Log file | `logs\service.log` |

### `start_server.py`

Acts as a watchdog:

- Starts `server.py`
- If it crashes, waits 10 seconds
- Restarts automatically
- Appends stdout/stderr to `logs\service.log`

### Management commands

```bat name=service-commands.bat
schtasks /run   /tn AladdinLicenseMonitor
schtasks /end   /tn AladdinLicenseMonitor
schtasks /query /tn AladdinLicenseMonitor
uninstall_service.bat
```

## Project Structure

| File | Purpose | Notes |
|---|---|---|
| `server.py` | Main Flask application | Contains app logic, HTML, and embedded C# source |
| `start_server.py` | Watchdog launcher | Restart loop and task entry point |
| `install_service.bat` | Service installer | Creates scheduled task |
| `uninstall_service.bat` | Service remover | Deletes scheduled task |
| `requirements.txt` | Python dependencies | Includes `flask`, `requests`, `beautifulsoup4` |
| `_mfquery.cs` | Generated C# source | Written at runtime |
| `_mfquery.exe` | Compiled helper | 32-bit executable for `hsmon.dll` access |
| `logs/service.log` | Runtime log | Combined stdout/stderr |
| `diagnose1-9.py` | Investigation scripts | Used during protocol discovery |

## Dependencies

- Flask
- requests
- beautifulsoup4
- .NET Framework 4.0 x86
- `hsmon.dll`
- `nhsrvice.exe`
- Active Directory PowerShell module or ADSI / DirectorySearcher
- WMI access to client workstations

Install Python dependencies with:

```bash name=install-deps.sh
pip install -r requirements.txt
```

## Known Limitations

- Session refresh can take **5-8 seconds** because `SCAN SERVERS` is asynchronous and requires polling
- If no interactive user is logged on to a workstation, the display name may fall back to `(unknown)`
- WMI access requires the service account to have sufficient rights on client workstations
- If workstation WMI is blocked by firewall or policy, user resolution may fail
- The NetHASP server ID is dynamic and discovered at runtime
- If .NET Framework 4 x86 is unavailable, `_mfquery.exe` cannot be compiled and session discovery fails

## Notes

- The Sentinel Admin Control Center may appear healthy while still showing zero BenARIT sessions; this is expected in this environment because BenARIT uses the legacy NetHASP path.
- The runtime session discovery path depends on the Aladdin Monitor installation that provides `hsmon.dll`.

---

Ofer Aharon  
`ofer@sw-eng.co.il`  
2026
