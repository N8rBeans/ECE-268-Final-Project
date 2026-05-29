@echo off

if exist build rmdir /S /Q build
mkdir build

if exist output rmdir /S /Q output
mkdir output

echo.

echo Compiling Lamport...
gcc src\lamport.c src\sha256.c -o build\lamport.exe

echo Compiling XMSS...
gcc src\xmss.c src\sha256.c -o build\xmss.exe

echo Compiling LMS...
gcc src\lms.c src\sha256.c -o build\lms.exe

echo.
echo =======================================================
echo RUNNING LAMPORT
echo =======================================================

build\lamport.exe data\the_odyssey.txt

echo.
echo =======================================================
echo RUNNING XMSS
echo =======================================================

build\xmss.exe data\the_odyssey.txt

echo.
echo =======================================================
echo RUNNING LMS
echo =======================================================

build\lms.exe data\the_odyssey.txt

echo.