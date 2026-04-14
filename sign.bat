PATH=%PATH%;%WSDK81%\bin\x86;C:\dev\Progs\NSIS;C:\Program Files (x86)\Windows Kits\10\bin\10.0.19041.0\x86;

rem sign using SHA-256
signtool sign /v /sha1 86E1D426731E79117452F090188A828426B29B5F /ac GlobalSign_SHA256_EV_CodeSigning_CA.cer /fd sha256 /tr http://timestamp.digicert.com /td SHA256 "Bin\Win32\Release\HashCheck.dll" "Bin\x64\Release\HashCheck.dll" 

makensis.exe installer\HashCheck.nsi

signtool sign /v /sha1 86E1D426731E79117452F090188A828426B29B5F /ac GlobalSign_SHA256_EV_CodeSigning_CA.cer /fd sha256 /tr http://timestamp.digicert.com /td SHA256  "installer\HashCheckSetup-v2.6.0.0.exe"

pause
