@echo off

call :main
exit /B %ERRORLEVEL% 

:main
  setlocal

  call :installCMake
  if %ERRORLEVEL% neq 0 (
    endlocal
    exit /B 1
  )

  call :installLLVM
  if %ERRORLEVEL% neq 0 (
    endlocal
    exit /B 1
  )

  call :installLLVMIntegration
  if %ERRORLEVEL% neq 0 (
    endlocal
    exit /B 1
  )

  call :installPython
  if %ERRORLEVEL% neq 0 (
    endlocal
    exit /B 1
  )

  call :installCxxcommon
  if %ERRORLEVEL% neq 0 (
    endlocal
    exit /B 1
  )

  call :initializeVisualStudioEnvironment
  if %ERRORLEVEL% neq 0 (
    echo Failed to find a suitable Visual Studio installation

    endlocal
    exit /B 1
  )

  call :configureProject
  if %ERRORLEVEL% neq 0 (
    echo Failed to find a suitable Visual Studio installation

    endlocal
    exit /B 1
  )

  call :buildProject
  if %ERRORLEVEL% neq 0 (
    echo Build has failed

    endlocal
    exit /B 1
  )

  endlocal
  exit /B 0

:configureProject
  setlocal

  mkdir build
  cd build

  pushd ..\tob_libraries
  set tob_libraries=%CD%
  popd

  for %%v in ("16 2019" "15 2017") do (
    echo Attempting configuration with Visual Studio %%v

    cmake -G "Visual Studio %%v" -T llvm -A x64 -DCMAKE_BUILD_TYPE=Release -DLIBRARY_REPOSITORY_ROOT=%tob_libraries% -DCMAKE_INSTALL_PREFIX=C:\ ..
    if %ERRORLEVEL% equ 0 (
      endlocal
      exit /B 0
    )
  )

  endlocal
  exit /B 1

:buildProject
  setlocal

  cd build

  echo Building
  cmake --build . --config Release -- /maxcpucount:%NUMBER_OF_PROCESSORS%
  if %ERRORLEVEL% neq 0 (
    endlocal
    exit /B 1
  )

  endlocal
  exit /B 0

:installCMake
  setlocal

  where cmake > NUL 2>&1
  if %ERRORLEVEL% equ 0 (
    echo Found existing CMake installation

    endlocal
    exit /B 0
  )

  echo Attempting to install CMake with choco
  choco install cmake
  if %ERRORLEVEL% neq 0 (
    echo Failed to install CMake with choco

    endlocal
    exit /B 1
  )

  where cmake > NUL 2>&1
  if %ERRORLEVEL% neq 0 (
    echo Failed to call CMake with choco

    endlocal
    exit /B 1
  )

  endlocal
  exit /B 0

:initializeVisualStudioEnvironment
  for %%v in (2019 2017) do (
    if exist "%ProgramFiles(x86)%\Microsoft Visual Studio\%%v\BuildTools\VC\Auxiliary\Build\vcvars64.bat" (
      echo Using Visual Studio %%v
      call "%ProgramFiles(x86)%\Microsoft Visual Studio\%%v\BuildTools\VC\Auxiliary\Build\vcvars64.bat" > NUL

      exit /B 0
    )
  )

  exit /B 1

:installLLVM
  setlocal

  if exist "%ProgramFiles%\LLVM\bin\clang.exe" (
    echo Found existing LLVM installation

    endlocal
    exit /B 0
  )

  echo Downloading the LLVM installer
  call :downloadFile http://releases.llvm.org/9.0.0/LLVM-9.0.0-win64.exe, llvm-installer.exe
  if %ERRORLEVEL% neq 0 (
    endlocal
    exit /B 1
  )

  echo Installing LLVM
  llvm-installer.exe /S /D
  if %ERRORLEVEL% neq 0 (
    endlocal
    exit /B 1
  )

  endlocal
  exit /B 0

:installLLVMIntegration
  setlocal

  for %%v in (2019 2017) do (
    if exist "%ProgramFiles(x86)%\Microsoft Visual Studio\%%v\BuildTools\MSBuild\Microsoft\VC\v160\LLVM.Cpp.Common.targets" (
      echo LLVM has already been integrated in Visual Studio %%v
      exit /B 0
    )
  )

  echo Downloading the Visual Studio LLVM integration
  call :downloadFile https://llvmextensions.gallerycdn.vsassets.io/extensions/llvmextensions/llvm-toolchain/1.0.363769/1560930595399/llvm.vsix, llvm_vsix.zip
  if %ERRORLEVEL% neq 0 (
    endlocal
    exit /B 1
  )

  echo Installing the Visual Studio LLVM integration
  call :extractArchive llvm_vsix.zip, llvm_integration
  if %ERRORLEVEL% neq 0 (
    endlocal
    exit /B 1
  )

  for %%v in (2019 2017) do (
    if exist "%ProgramFiles(x86)%\Microsoft Visual Studio\%%v\BuildTools\MSBuild\Microsoft\VC\v160" (
      echo Integrating LLVM with Visual Studio %%v

      xcopy llvm_integration\$VCTargets\* "%ProgramFiles(x86)%\Microsoft Visual Studio\%%v\BuildTools\MSBuild\Microsoft\VC\v160" /e /y /h /r > NUL
      if %ERRORLEVEL% neq 0 (
        endlocal
        exit /B 1
      )
    )
  )

  endlocal
  exit /B 0

:extractArchive
  setlocal

  powershell -Command "Expand-Archive %~1 -DestinationPath %~2 -Force"
  if %ERRORLEVEL% neq 0 (
    echo Failed to download the file

    endlocal
    exit /B 1
  )

  endlocal
  exit /B 0


:installPython
  setlocal

  if exist "%SystemDrive%\Python27\python.exe" (
    echo Found existing Python installation

    endlocal
    exit /B 0
  )

  echo Downloading the Python installer
  call :downloadFile https://www.python.org/ftp/python/2.7.17/python-2.7.17.amd64.msi, python-installer.msi
  if %ERRORLEVEL% neq 0 (
    endlocal
    exit /B 1
  )

  echo Installing Python
  msiexec /i python-installer.msi /quiet /qn /norestart
  if %ERRORLEVEL% neq 0 (
    endlocal
    exit /B 1
  )

  endlocal
  exit /B 0

:installCxxcommon
  setlocal

  if not exist cxxcommon.7z (
    echo Downloading the cxxcommon archive
    call :downloadFile https://s3.amazonaws.com/cxx-common/libraries-llvm50-windows10-amd64.7z, cxxcommon.7z
    if %ERRORLEVEL% neq 0 (
      endlocal
      exit /B 1
    )
  )

  if not exist tob_libraries (
    echo Extracting the cxxcommon archive
    7z.exe x cxxcommon.7z
    if %ERRORLEVEL% neq 0 (
      endlocal
      exit /B 1
    )
  )

  endlocal
  exit /B 0

:downloadFile
  setlocal

  powershell -Command "Invoke-WebRequest %~1 -OutFile %~2"
  if %ERRORLEVEL% neq 0 (
    echo Failed to download the file

    endlocal
    exit /B 1
  )

  endlocal
  exit /B 0
