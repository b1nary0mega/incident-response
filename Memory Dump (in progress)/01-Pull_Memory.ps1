#global variables
$modulePath = (Split-Path $MyInvocation.MyCommand.Path)
$scriptLocation = $modulePath + "Memory-Tools.psm1"
$datetimeString = (Get-Date -format o | ForEach-Object { $_ -replace ":", "." })
$dumpFileName = $modulePath + $datetimeString + "--" + $env:COMPUTERNAME

#import our module and suppress any warnings
Import-Module -Name $scriptLocation 3>$null

#$dumpFileName = $modulePath + $env:COMPUTERNAME

### Disable reg-key for bitlocker

### dump the entire memory image of powershell.exe to disk 
# in binary format, execution of the dumped memory image 
# requires fixing up PE header.

#$proc = [System.Diagnostics.Process]::GetCurrentProcess()
$proc = ps cmd
$module = $proc.MainModule
$size = $module.ModuleMemorySize
$base = $module.BaseAddress

#only dump the first 0x248 bytes of main module (powershell)
Dump-Memory $base 0x768 | Out-File -FilePath ($dumpFileName + ".txt")


### !!!WARNING!!!
# THESE WILL CRASH PS... DO NOT USE UNTIL FIXED
#  --going up to 1024 bytes causes crash (7/31 - JRA)
# uncommenting below pipes ALL MEMORY for main module (powershell) out to a txt
#Dump-Memory $base $size | Out-File -FilePath $dumpFileName + ".txt"
# uncommenting below dumps all memory in binary format; requires fixing up PE header
#Dump-Memory $base $size -DumpToFile ($dumpFileName + ".exe")

### Re-Enable reg-key for bitlocker