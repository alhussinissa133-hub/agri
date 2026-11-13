@echo off
cd /d "%~dp0"
echo ===== Building Android APK =====
echo Requirements: Node.js, JDK 17, Android Studio (Android SDK), ANDROID_HOME set
where node >nul 2>nul
if errorlevel 1 (
  echo Install Node.js first from nodejs.org
  pause
  exit /b 1
)
if not exist "%USERPROFILE%\.android" mkdir "%USERPROFILE%\.android"
if exist "%USERPROFILE%\.android\debug.keystore" copy /y "%USERPROFILE%\.android\debug.keystore" "%USERPROFILE%\.android\debug.keystore.bak" >nul
copy /y build\debug.keystore "%USERPROFILE%\.android\debug.keystore" >nul
call npm install
if errorlevel 1 goto fail
call node scripts\prepare-www.js
if errorlevel 1 goto fail
if not exist android (
  call npx cap add android
  if errorlevel 1 goto fail
)
call node scripts\patch-android.js
if errorlevel 1 goto fail
call npx cap sync android
if errorlevel 1 goto fail
cd android
call gradlew.bat assembleDebug
if errorlevel 1 goto fail
cd ..
if not exist dist mkdir dist
copy /y android\app\build\outputs\apk\debug\app-debug.apk dist\AgriPharmacy.apk >nul
echo.
echo DONE. File: dist\AgriPharmacy.apk
explorer dist
pause
exit /b 0
:fail
echo.
echo FAILED. Read the error above.
pause
exit /b 1
