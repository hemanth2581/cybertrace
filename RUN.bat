@echo off
title CyberTrace - AI Digital Forensics Platform
color 0b
echo ============================================================
echo   CYBERTRACE - AI DIGITAL FORENSICS PLATFORM
echo ============================================================
echo.
echo Checking Java installation...
java -version >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] Java 17+ or Java 21 is required to run CyberTrace.
    echo Please download and install OpenJDK / Eclipse Temurin from:
    echo https://adoptium.net/
    echo.
    pause
    exit /b 1
)

echo.
echo [1/2] Opening browser at http://localhost:8080 ...
timeout /t 2 >nul
start "" http://localhost:8080

echo [2/2] Launching CyberTrace Spring Boot Application...
echo.

if exist "target\cybertrace-1.0.0.jar" (
    java -jar target\cybertrace-1.0.0.jar
) else if exist "cybertrace-1.0.0.jar" (
    java -jar cybertrace-1.0.0.jar
) else (
    echo Building and starting with Maven wrapper...
    call mvnw.cmd spring-boot:run
)

pause
