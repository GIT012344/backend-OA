@echo off
echo Installing SSL Certificate to Windows Certificate Store...
echo.
echo This will add the backend SSL certificate to trusted certificates
echo so browsers will accept the HTTPS connection without warnings.
echo.
pause

REM Import certificate to Trusted Root Certification Authorities
certlm.msc /s /r localMachine root cert.pem

echo.
echo Certificate imported successfully!
echo Please restart your browser for changes to take effect.
echo.
pause
