@echo off

if exist build rmdir /S /Q build
mkdir build

if exist output rmdir /S /Q output
mkdir output

echo.

echo Compiling Lamport...
nvcc -rdc=true src\lamport.cu src\sha256.cu -o build\lamport.exe -Xlinker /NOEXP -Xlinker /NOIMPLIB -Wno-deprecated-gpu-targets -diag-suppress 177

echo Compiling XMSS...
nvcc -rdc=true src\xmss.cu src\sha256.cu -o build\xmss.exe -Xlinker /NOEXP -Xlinker /NOIMPLIB -Wno-deprecated-gpu-targets -diag-suppress 177

echo Compiling LMS...
nvcc -rdc=true src\lms.cu src\sha256.cu -o build\lms.exe -Xlinker /NOEXP -Xlinker /NOIMPLIB -Wno-deprecated-gpu-targets -diag-suppress 177

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
echo RUNNING XMSS
echo =======================================================

build\lms.exe data\the_odyssey.txt

echo.