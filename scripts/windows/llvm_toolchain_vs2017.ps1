# Copyright (C) Trail of Bits, 2019
#
# This is a simple script to extract the LLVM Toolset Visual Studio plugin
# and make it work with VS Build Tools, which is not a supported configuration by default
#
# Currently this script has only been tested with VS 2017 Build Tools.
#
# The LLVM Toolset Plugin (llvm.zip) is obtained from https://marketplace.visualstudio.com/items?itemName=LLVMExtensions.llvm-toolchain
# and is subject to the LLVM license (See LICENSE.llvm).

# Run this script as: 
#  powershell -nologo -executionpolicy bypass -File llvm_toolchain_vs2017.ps1
#
#

function ExtractFile {
     Param(
      [parameter(Mandatory=$true)]
      [String] $sourceFile,
      [parameter(Mandatory=$true)]
      [String] $destinationDir
    )


    $shellApp = New-Object -ComObject Shell.Application
    $sourcePath = [System.IO.Path]::GetFullPath([IO.Path]::Combine($sourceFile, '$VCTargets'))
    $destPath = [System.IO.Path]::GetFullPath($destinationDir)
    $source = $shellApp.NameSpace($sourcePath)
    $dest = $shellApp.NameSpace($destPath)
    # The 0x14 constant means to silently overwrite
    # from here: https://stackoverflow.com/questions/2359372/how-do-i-overwrite-existing-items-with-folder-copyhere-in-powershell
    Write-Host "Extracting files from $sourcePath to $destPath"
    $dest.copyHere($source.Items(), 0x14)
}

if (! (Test-Path "${ENV:VS150COMNTOOLS}") ) {
  Write-Error "Could not find the VS 2017 Common Tools path in your environment"
  Write-Error "Are you running this from the VS2017 Command Prompt?"
  return
}

$vsDirectory = [IO.Path]::Combine("${env:VS150COMNTOOLS}", "..", 'IDE', 'VC', 'VCTargets')
if( !(Test-Path $vsDirectory) ) { 
  Write-Error "Could not find the VS 2017 Common Tools in: $vsDirectory"
  return
}

$sourceZip = [IO.Path]::Combine("$PSScriptRoot", "llvm.zip")

if( !(Test-Path $sourceZIp) ) { 
  Write-Error "Could not find llvm.zip in: $sourceZip"
  return
}

ExtractFile $sourceZip $vsDirectory