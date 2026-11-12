@echo off
chcp 65001 >nul
cd /d "%~dp0"
echo ===== بناء تطبيق الاندرويد ^(APK^) =====
echo المتطلبات: Node.js + JDK 17 + Android Studio ^(Android SDK^) وضبط ANDROID_HOME
where node >nul 2>nul || (echo ثبّت Node.js اولا & pause & exit /b 1)
if not exist "%USERPROFILE%\.android" mkdir "%USERPROFILE%\.android"
if exist "%USERPROFILE%\.android\debug.keystore" copy /y "%USERPROFILE%\.android\debug.keystore" "%USERPROFILE%\.android\debug.keystore.bak" >nul
copy /y build\debug.keystore "%USERPROFILE%\.android\debug.keystore" >nul
call npm install || (echo فشل npm install & pause & exit /b 1)
call node scripts\prepare-www.js || (pause & exit /b 1)
if not exist android (call npx cap add android || (echo فشل cap add & pause & exit /b 1))
call node scripts\patch-android.js || (pause & exit /b 1)
call npx cap sync android || (echo فشل cap sync & pause & exit /b 1)
cd android
call gradlew.bat assembleDebug || (echo فشل البناء & pause & exit /b 1)
cd ..
if not exist dist mkdir dist
copy /y android\app\build\outputs\apk\debug\app-debug.apk dist\AgriPharmacy.apk >nul
echo.
echo تم! الملف: dist\AgriPharmacy.apk
explorer dist
pause
