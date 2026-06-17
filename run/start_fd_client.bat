@echo off
rem ---------------------------------------------------------------------------
rem  Launch fbsec_co_fd_client.exe in interactive --menu mode against the
rem  local CANopen FD bus simulator. Verb taxonomy: rd / wr / srd / swr /
rem  srdpoll / swrpoll, carried over USDO expedited frames.
rem
rem  Usage:  start_fd_client.bat            (default bus port 5810,
rem                                          target node 0x05)
rem          start_fd_client.bat 5811       (override bus port)
rem          start_fd_client.bat 5811 0x07  (also override target node)
rem
rem  Make sure start_fd_hub.bat and at least one start_fd_server.bat
rem  are running before launching this script.
rem ---------------------------------------------------------------------------
setlocal
cd /d "%~dp0"

set "PORT=%~1"
set "NODE=%~2"
if "%PORT%"=="" set "PORT=5810"
if "%NODE%"=="" set "NODE=0x05"

..\build\variants\canopen_fd\client\Release\fbsec_co_fd_client.exe --menu --bus 127.0.0.1:%PORT% --target-node %NODE% --timeout 1500 --key-file "%~dp0keys-demo.txt"

echo.
pause
endlocal
