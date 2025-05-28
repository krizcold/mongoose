@echo off
REM Adjust the path to your balcon.exe
REM This script now passes ALL arguments it receives directly to balcon.exe

C:\balcon\balcon.exe %*

REM %* passes all command line arguments received by the batch script
REM to balcon.exe exactly as they were given.

exit /b %errorlevel%