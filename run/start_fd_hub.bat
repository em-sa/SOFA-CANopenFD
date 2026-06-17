@echo off
rem ---------------------------------------------------------------------------
rem  Start the SOFA CANopen FD bus simulator on 127.0.0.1.
rem  Usage:  start_fd_hub.bat            (default port 5810)
rem          start_fd_hub.bat 5811       (override port)
rem
rem  Default port 5810. See
rem  doc/fieldbus_sim_canopen_fd_spec.txt section 2.
rem ---------------------------------------------------------------------------
setlocal
cd /d "%~dp0"

set "PORT=%~1"
if "%PORT%"=="" set "PORT=5810"

echo CANopen FD bus simulator listening on port %PORT%.  Press Ctrl+C to stop.
echo.
..\build\variants\canopen_fd\bus\Release\fbsec_co_fd_bus.exe --port %PORT%

echo.
echo Bus simulator exited.
pause
endlocal
