<#
NAME: IRDumper.psm1
VERSION: v1.0
AUTHOR: Jimmi Aylesworth
DATE: 20190731

DESCRIPTION:
This script will attempt to pull as much data as possible from a computer and store it
into a local (same directory as script) text file.

Data Gathering:
[ ] Memory Dump
[ ] System Services
[ ] Scheduled Tasks
[x] General Computer Information (Name, Domain, Make, Model, etc.)
[X] BIOS
[X] CPU Make
[X] OS Information (Version, Build, Serial)
[X] ALL Administrator Accounts (even when names have been changed)
[X] LAPS password
[X] Hotfixes
[X] Active Directory data (CN, LastLogon, LastBadPasswd, Lockout, LAPS, etc.)
[X] Network Information
[X] Network Connections (TCP)
 
#>

#global variables
$modulePath = (Split-Path $MyInvocation.MyCommand.Path)
$datetimeString = (Get-Date -format o | ForEach-Object { $_ -replace ":", "." })
$dumpFileName = $modulePath + $datetimeString + "--" + $env:COMPUTERNAME

function Get-StartOutput {
    Write-Output "///BEGINING OF OUTPUT///`n`n"| out-file -Append -encoding ASCII -filepath ($dumpFileName + ".txt")
}

function Get-EndOutput {
    Write-Output "///END OF OUTPUT///"| out-file -Append -encoding ASCII -filepath ($dumpFileName + ".txt")

    Write-Output "...data pull complete.`n"

    Write-Output "file located at: " ($dumpFileName + ".txt")
}

function Get-MemoryDump {
    Write-Output "pulling memory dump..."
    Write-Output ("----------------------------------------------------------") | out-file -Append -encoding ASCII -filepath ($dumpFileName + ".txt")
    Write-Output ("   Memory Dump") | out-file -Append -encoding ASCII -filepath ($dumpFileName + ".txt")
    Write-Output ("----------------------------------------------------------") | out-file -Append -encoding ASCII -filepath ($dumpFileName + ".txt")
    Write-Output "TODO: implement this code" | out-file -Append -encoding ASCII -filepath ($dumpFileName + ".txt")
}

function Get-SystemServices {
    Write-Output "pulling system services..."
    Write-Output ("----------------------------------------------------------") | out-file -Append -encoding ASCII -filepath ($dumpFileName + ".txt")
    Write-Output ("   System Services") | out-file -Append -encoding ASCII -filepath ($dumpFileName + ".txt")
    Write-Output ("----------------------------------------------------------") | out-file -Append -encoding ASCII -filepath ($dumpFileName + ".txt")
    Write-Output "TODO: implement this code" | out-file -Append -encoding ASCII -filepath ($dumpFileName + ".txt")
}

function Get-ScheduledTasks {
    Write-Output "pulling scheduled tasks..."
    Write-Output ("----------------------------------------------------------") | out-file -Append -encoding ASCII -filepath ($dumpFileName + ".txt")
    Write-Output ("   Scheduled Tasks") | out-file -Append -encoding ASCII -filepath ($dumpFileName + ".txt")
    Write-Output ("----------------------------------------------------------") | out-file -Append -encoding ASCII -filepath ($dumpFileName + ".txt")
    Write-Output "TODO: implement this code" | out-file -Append -encoding ASCII -filepath ($dumpFileName + ".txt")
}

function Get-ComputerInfo {
    Write-Output "pulling computer info..."
    Write-Output ("----------------------------------------------------------") | out-file -Append -encoding ASCII -filepath ($dumpFileName + ".txt")
    Write-Output ("   Computer Information") | out-file -Append -encoding ASCII -filepath ($dumpFileName + ".txt")
    Write-Output ("----------------------------------------------------------") | out-file -Append -encoding ASCII -filepath ($dumpFileName + ".txt")
    Write-Output (get-wmiobject -query "SELECT * FROM Win32_ComputerSystem" |
    select-object Name,Domain,Description,Manufacturer,Model,NumberOfProcessors,`
    TotalPhysicalMemory,SystemType,PrimaryOwnerName,UserName) | out-file -Append -encoding ASCII -filepath ($dumpFileName + ".txt")
}

function Get-BIOSinfo {
    Write-Output "pulling bios info..."
    Write-Output ("----------------------------------------------------------") | out-file -Append -encoding ASCII -filepath ($dumpFileName + ".txt")
    Write-Output ("   BIOS Information") | out-file -Append -encoding ASCII -filepath ($dumpFileName + ".txt")
    Write-Output ("----------------------------------------------------------") | out-file -Append -encoding ASCII -filepath ($dumpFileName + ".txt")
    Write-Output (get-wmiobject -query "SELECT * FROM Win32_BIOS" |
    select-object Name,Version,SMBIOSBIOSVersion) | out-file -Append -encoding ASCII -filepath ($dumpFileName + ".txt")
}

function Get-CPUinfo {
    Write-Output "pulling CPU info..."
    Write-Output ("----------------------------------------------------------") | out-file -Append -encoding ASCII -filepath ($dumpFileName + ".txt")
    Write-Output ("   CPU Information") | out-file -Append -encoding ASCII -filepath ($dumpFileName + ".txt")
    Write-Output ("----------------------------------------------------------") | out-file -Append -encoding ASCII -filepath ($dumpFileName + ".txt")
    Write-Output (get-wmiobject -query "SELECT * FROM Win32_Processor" |
    select-object Manufacturer,Name,CurrentClockSpeed,L2CacheSize) | out-file -Append -encoding ASCII -filepath ($dumpFileName + ".txt")
}

function Get-OSinfo {
    Write-Output "pulling OS info..."
    Write-Output ("----------------------------------------------------------") | out-file -Append -encoding ASCII -filepath ($dumpFileName + ".txt")
    Write-Output ("   Operating System Information") | out-file -Append -encoding ASCII -filepath ($dumpFileName + ".txt")
    Write-Output ("----------------------------------------------------------") | out-file -Append -encoding ASCII -filepath ($dumpFileName + ".txt")
    Write-Output (get-wmiobject -query "SELECT * FROM Win32_OperatingSystem" |
    select-object Caption,BuildNumber,Version,SerialNumber,ServicePackMajorVersion,InstallDate) | out-file -Append -encoding ASCII -filepath ($dumpFileName + ".txt")
}

function Get-AdminAccounts {
    Write-Output "pulling administrator info..."
    Write-Output ("----------------------------------------------------------") | out-file -Append -encoding ASCII -filepath ($dumpFileName + ".txt")
    Write-Output ("   Name of Built-In Administrator Accounts") | out-file -Append -encoding ASCII -filepath ($dumpFileName + ".txt")
    Write-Output ("----------------------------------------------------------") | out-file -Append -encoding ASCII -filepath ($dumpFileName + ".txt")
    Write-Output (get-wmiobject -query "SELECT * FROM Win32_UserAccount" | where-object {$_.SID -match '-500$'} | 
    select-object Name) | out-file -Append -encoding ASCII -filepath ($dumpFileName + ".txt")
}

function Get-LAPSinfo {
    Write-Output "pulling LAPS info..."
    Write-Output ("----------------------------------------------------------") | out-file -Append -encoding ASCII -filepath ($dumpFileName + ".txt")
    Write-Output ("   LAPS Information (if available, may be able to pair") | out-file -Append -encoding ASCII -filepath ($dumpFileName + ".txt")
    Write-Output ("   with an above account)") | out-file -Append -encoding ASCII -filepath ($dumpFileName + ".txt")
    Write-Output ("----------------------------------------------------------") | out-file -Append -encoding ASCII -filepath ($dumpFileName + ".txt")
    Write-Output (get-adcomputer -Identity $env:COMPUTERNAME -Properties *| select @{Label="Name";Expression={$_.name}},`
    @{Label="OS";Expression={$_.operatingsystem}}, @{Label="Distinguished name";Expression={$_.'distinguishedname'}},`
    @{Label="Password";Expression={$_.'ms-Mcs-AdmPwd'}}) | out-file -Append -encoding ASCII -filepath ($dumpFileName + ".txt")
}

function Get-HotfixInfo {
    Write-Output "pulling hotfix info..."
    Write-Output ("----------------------------------------------------------") | out-file -Append -encoding ASCII -filepath ($dumpFileName + ".txt")
    Write-Output ("   Installed Hotfixes") | out-file -Append -encoding ASCII -filepath ($dumpFileName + ".txt")
    Write-Output ("----------------------------------------------------------") | out-file -Append -encoding ASCII -filepath ($dumpFileName + ".txt")
    Write-Output (get-wmiobject -query "SELECT * FROM Win32_QuickFixEngineering" |
    select-object HotFixID) | out-file -Append -encoding ASCII -filepath ($dumpFileName + ".txt")
}

function Get-ADinfo {
    Write-Output "pulling AD info..."
    Write-Output ("----------------------------------------------------------") | out-file -Append -encoding ASCII -filepath ($dumpFileName + ".txt")
    Write-Output ("   Active Directory Information") | out-file -Append -encoding ASCII -filepath ($dumpFileName + ".txt")
    Write-Output ("----------------------------------------------------------") | out-file -Append -encoding ASCII -filepath ($dumpFileName + ".txt")
    Write-Output (get-adcomputer -Identity $env:COMPUTERNAME -Properties *) | out-file -Append -encoding ASCII -filepath ($dumpFileName + ".txt")
}

function Get-NetworkInfo {
    Write-Output "pulling network info..."
    Write-Output ("----------------------------------------------------------") | out-file -Append -encoding ASCII -filepath ($dumpFileName + ".txt")
    Write-Output ("   Network Information") | out-file -Append -encoding ASCII -filepath ($dumpFileName + ".txt")
    Write-Output ("----------------------------------------------------------") | out-file -Append -encoding ASCII -filepath ($dumpFileName + ".txt")
    Write-Output (Get-NetAdapter) | out-file -Append -encoding ASCII -filepath ($dumpFileName + ".txt")
}

function Get-TCPconnections {
    Write-Output "pulling connection info..."
    Write-Output ("----------------------------------------------------------") | out-file -Append -encoding ASCII -filepath ($dumpFileName + ".txt")
    Write-Output ("   TCP Connection Information") | out-file -Append -encoding ASCII -filepath ($dumpFileName + ".txt")
    Write-Output ("----------------------------------------------------------") | out-file -Append -encoding ASCII -filepath ($dumpFileName + ".txt")
    Write-Output (Get-NetTCPConnection) | out-file -Append -encoding ASCII -filepath ($dumpFileName + ".txt")
}

function Global:GetThemAll {
    Get-StartOutput
    Get-EndOutput
    Get-MemoryDump
    Get-SystemServices
    Get-ScheduledTasks
    Get-ComputerInfo
    Get-BIOSinfo
    Get-CPUinfo
    Get-OSinfo
    Get-AdminAccounts
    Get-LAPSinfo
    Get-HotfixInfo
    Get-ADinfo
    Get-NetworkInfo
    Get-TCPconnections
}

function main {
    Write-Output "This came from the main function...nothing to see here."
}