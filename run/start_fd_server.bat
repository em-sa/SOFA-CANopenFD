@echo off
rem ---------------------------------------------------------------------------
rem  Start a SOFA CANopen FD server attached to the local bus simulator.
rem  Prompts for a CANopen node id (1..127), defaults to 0x05.
rem  Usage:  start_fd_server.bat                  (interactive, port 5810)
rem          start_fd_server.bat 0x07             (skip the prompt)
rem          start_fd_server.bat 0x07 5811        (also override bus port)
rem
rem  Node id maps both to the USDO BUF[0] destination byte and to the
rem  SOFA device_id AAD field; see doc/fieldbus_sim_canopen_fd_spec.txt
rem  Sections 4.4 and 5.2.
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
echo Starting CANopen FD server  node=%NODE%  bus=127.0.0.1:%PORT%
echo (Press Ctrl+C to stop.)
echo.
rem ---------------------------------------------------------------------------
rem  --demo-keys fills the session-key slots with the built-in demo keys, so
rem  the device boots Operational and the secure read/write menu works out of
rem  the box. Demo-key install is now opt-in: with no --demo-keys and no
rem  --key-file the device boots Uncommissioned (new-from-manufacturer), and
rem  the client's L) lifecycle submenu shows the commissioning state. To try
rem  that, drop --demo-keys from the line below.
rem ---------------------------------------------------------------------------
..\build\variants\canopen_fd\server\Release\fbsec_co_fd_server.exe --bus 127.0.0.1:%PORT% --node %NODE% --demo-keys --od-file "%~dp0sofa-od-demo.txt"

echo.
echo Server exited.
pause
endlocal
