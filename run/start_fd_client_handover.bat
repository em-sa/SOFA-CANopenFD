@echo off
rem ---------------------------------------------------------------------------
rem  Launch the SOFA CANopen FD client for the RPK handover /
rem  commissioning-lifecycle demo, against an UNCOMMISSIONED server
rem  (start_fd_server_handover.bat).
rem
rem  It relays the demo ownership voucher from run\voucher-demo.txt (the offline
rem  manufacturer/MASA artifact) rather than self-signing one. In the menu:
rem
rem    L )  open the lifecycle submenu; it shows the server as Uncommissioned
rem         and offers "Claim ownership by voucher, then install the
rem         Provisioning key". Run it: the device becomes Owned / Operational.
rem    3 )  a secure 4-byte read then works with the freshly installed key.
rem
rem  To regenerate the voucher file after changing demo identities:
rem    fbsec_co_fd_client.exe --emit-voucher run\voucher-demo.txt
rem
rem  Usage:  start_fd_client_handover.bat            (bus port 5810, node 0x05)
rem          start_fd_client_handover.bat 5811       (override bus port)
rem          start_fd_client_handover.bat 5811 0x07  (also override target node)
rem ---------------------------------------------------------------------------
setlocal
cd /d "%~dp0"

set "PORT=%~1"
set "NODE=%~2"
if "%PORT%"=="" set "PORT=5810"
if "%NODE%"=="" set "NODE=0x05"

..\build\variants\canopen_fd\client\Release\fbsec_co_fd_client.exe --menu --bus 127.0.0.1:%PORT% --target-node %NODE% --timeout 1500 --key-file "%~dp0keys-demo.txt" --voucher "%~dp0voucher-demo.txt"

echo.
pause
endlocal
