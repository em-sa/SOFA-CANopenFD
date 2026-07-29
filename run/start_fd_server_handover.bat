@echo off
rem ---------------------------------------------------------------------------
rem  Start a SOFA CANopen FD server as NEW-FROM-MANUFACTURER for the RPK
rem  handover / commissioning-lifecycle demo.
rem
rem  Unlike start_fd_server.bat, this boots the device UNCOMMISSIONED: no
rem  session keys are installed (no --demo-keys, no --key-file), so C001h:01h
rem  reports uncommissioned and the key store is empty. The device still holds
rem  its factory RPK identity (IDevID + manufacturer anchor) and advertises the
rem  voucher gate at C000h:06h.
rem
rem  Drive the handover from the client (start_fd_client_handover.bat): the L)
rem  lifecycle submenu claims ownership with the voucher and installs the
rem  Provisioning key, moving the device to Owned / Operational.
rem
rem  Usage:  start_fd_server_handover.bat            (interactive, port 5810)
rem          start_fd_server_handover.bat 0x07       (skip the node prompt)
rem          start_fd_server_handover.bat 0x07 5811  (also override bus port)
rem ---------------------------------------------------------------------------
setlocal
cd /d "%~dp0"

set "NODE=%~1"
set "PORT=%~2"
if "%PORT%"=="" set "PORT=5810"

if "%NODE%"=="" (
  set /p "NODE=Server CANopen node id [default 0x05]: "
)
if "%NODE%"=="" set "NODE=0x05"

echo.
echo Starting UNCOMMISSIONED CANopen FD server  node=%NODE%  bus=127.0.0.1:%PORT%
echo (new-from-manufacturer; commission it from the client L) submenu)
echo (Press Ctrl+C to stop.)
echo.
..\build\variants\canopen_fd\server\Release\fbsec_co_fd_server.exe --bus 127.0.0.1:%PORT% --node %NODE% --od-file "%~dp0sofa-od-demo.txt"

echo.
echo Server exited.
pause
endlocal
