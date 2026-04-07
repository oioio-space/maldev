@echo off
REM vm-test.bat — Run Go tests from VirtualBox shared folder
REM Usage: Copy this script to VM, run as admin for risky tests

if exist C:\maldev rmdir /s /q C:\maldev
xcopy Z:\ C:\maldev\ /E /I /Q /EXCLUDE:Z:\scripts\vm-exclude.txt
cd /d C:\maldev
go test %* 2>&1
echo VM_TEST_EXIT_CODE=%ERRORLEVEL%
