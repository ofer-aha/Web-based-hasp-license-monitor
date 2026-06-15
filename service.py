"""
Windows Service wrapper for Aladdin License Monitor.
Install/manage with install_service.bat, or directly:
  python service.py install
  python service.py start
  python service.py stop
  python service.py remove
"""
import sys
import os
import subprocess

import win32serviceutil
import win32service
import win32event
import servicemanager


class AladdinMonitorService(win32serviceutil.ServiceFramework):
    _svc_name_        = "AladdinLicenseMonitor"
    _svc_display_name_= "Aladdin License Monitor"
    _svc_description_ = "משתמשים פעילים ברישיון HASP – http://localhost:5000"

    def __init__(self, args):
        win32serviceutil.ServiceFramework.__init__(self, args)
        self._stop = win32event.CreateEvent(None, 0, 0, None)
        self._proc = None

    def SvcStop(self):
        self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
        win32event.SetEvent(self._stop)
        if self._proc:
            self._proc.terminate()

    def SvcDoRun(self):
        servicemanager.LogMsg(
            servicemanager.EVENTLOG_INFORMATION_TYPE,
            servicemanager.PYS_SERVICE_STARTED,
            (self._svc_name_, ""),
        )
        app_dir = os.path.dirname(os.path.abspath(__file__))
        log_dir = os.path.join(app_dir, "logs")
        os.makedirs(log_dir, exist_ok=True)
        log_path = os.path.join(log_dir, "service.log")

        with open(log_path, "a", encoding="utf-8") as log:
            self._proc = subprocess.Popen(
                [sys.executable, os.path.join(app_dir, "server.py")],
                cwd=app_dir,
                stdout=log,
                stderr=log,
            )

        # Wait until stop is requested
        win32event.WaitForSingleObject(self._stop, win32event.INFINITE)


if __name__ == "__main__":
    if len(sys.argv) == 1:
        # Called by the SCM directly (not from command line)
        servicemanager.Initialize()
        servicemanager.PrepareToHostSingle(AladdinMonitorService)
        servicemanager.StartServiceCtrlDispatcher()
    else:
        win32serviceutil.HandleCommandLine(AladdinMonitorService)
