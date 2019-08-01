<#
NAME: IRDumper.psm1
VERSION: v1.0
AUTHOR: Jimmi Aylesworth
DATE: 20190731
LEGAL: Public domain, no rights reserved.

*** a GREAT deal of this code was taken from below ***
##############################################################################
#  Script: Show-ComputerInfo.ps1
#    Date: 30.May.2007
# Version: 1.0
#  Author: Jason Fossen, Enclave Consulting LLC (http://www.sans.org/sec505)
#    SANS: Course SEC505 - Securing Windows and PowerShell Automation
# Purpose: Demo a sampling of the kinds of information queryable through WMI.
#   Legal: Public domain, no rights reserved.
##############################################################################

DESCRIPTION:
This script will attempt to pull as much data as possible from a computer and store it
into a local (same directory as script) text file.

Data Gathering:
[ ] Memory Dump
[ ] Scheduled Tasks
[ ] System Services
[x] General Computer Information (Name, Domain, Make, Model, etc.)
[X] Process Tree
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

# global variables
$modulePath = (Split-Path $MyInvocation.MyCommand.Path)
# make sure we have a trailing "\"
If ($modulePath[-1] -notmatch "\\") 
{
    $modulePath+="\"
}

$datetimeString = (Get-Date -format o | ForEach-Object { $_ -replace ":", "." })
$dumpFileName = $modulePath + $datetimeString + "--" + $env:COMPUTERNAME


function Get-StartOutput {
    Write-Output "///BEGINING OF OUTPUT///`n`n"| out-file -Append -encoding ASCII -filepath ($dumpFileName + "-aggregate.txt")
}

function Get-MemoryDump {
    Write-host "...pulling memory dump..." -foregroundcolor green 
    Write-Output ("----------------------------------------------------------") | out-file -Append -encoding ASCII -filepath ($dumpFileName + "-aggregate.txt")
    Write-Output ("   Memory Dump") | out-file -Append -encoding ASCII -filepath ($dumpFileName + "-aggregate.txt")
    Write-Output ("----------------------------------------------------------") | out-file -Append -encoding ASCII -filepath ($dumpFileName + "-aggregate.txt")
    Write-Output "TODO: implement this code" | out-file -Append -encoding ASCII -filepath ($dumpFileName + "-aggregate.txt")
}

function Get-SystemServices {
    Write-host "...pulling system services..." -foregroundcolor green 
    Write-Output ("----------------------------------------------------------") | out-file -Append -encoding ASCII -filepath ($dumpFileName + "-aggregate.txt")
    Write-Output ("   System Services") | out-file -Append -encoding ASCII -filepath ($dumpFileName + "-aggregate.txt")
    Write-Output ("----------------------------------------------------------") | out-file -Append -encoding ASCII -filepath ($dumpFileName + "-aggregate.txt")
    Write-Output "TODO: implement this code" | out-file -Append -encoding ASCII -filepath ($dumpFileName + "-aggregate.txt")
}

# SOURCE: Adam Roben @ https://gist.github.com/aroben/5542538
function Get-ProcessTree {
    Write-host "...pulling process tree..." -foregroundcolor green 
    Write-Output ("----------------------------------------------------------") | out-file -Append -encoding ASCII -filepath ($dumpFileName + "-aggregate.txt")
    Write-Output ("   Process Tree") | out-file -Append -encoding ASCII -filepath ($dumpFileName + "-aggregate.txt")
    Write-Output ("----------------------------------------------------------") | out-file -Append -encoding ASCII -filepath ($dumpFileName + "-aggregate.txt")
    if(1) {
        $ProcessesById = @{}

        foreach ($Process in (Get-WMIObject -Class Win32_Process)) {
          $ProcessesById[$Process.ProcessId] = $Process
        }

        $ProcessesWithoutParents = @()
        $ProcessesByParent = @{}
        foreach ($Pair in $ProcessesById.GetEnumerator()) {
          $Process = $Pair.Value

          if (($Process.ParentProcessId -eq 0) -or !$ProcessesById.ContainsKey($Process.ParentProcessId)) {
            $ProcessesWithoutParents += $Process
            continue
          }

          if (!$ProcessesByParent.ContainsKey($Process.ParentProcessId)) {
            $ProcessesByParent[$Process.ParentProcessId] = @()
          }
          $Siblings = $ProcessesByParent[$Process.ParentProcessId]
          $Siblings += $Process
          $ProcessesByParent[$Process.ParentProcessId] = $Siblings
        }

        function Show-ProcessTree([UInt32]$ProcessId, $IndentLevel) {
          $Process = $ProcessesById[$ProcessId]
      
          $Indent = ("." * $IndentLevel)
          if ($IndentLevel -eq 0){
            $Indent =""
          }
          $commandline = $Process.CommandLine
          $Name  = $Indent + $Process.Name
          $ExePath = $Process.Executablepath
          $owner = $Process.getowner()
          $user = $owner.domain + "\"  + $owner.user
          $creationdate_str = $Process.ConvertToDateTime($Process.CreationDate)

          Write-Output ("{0,6} {1,-30} {2,-30} {3} {4} {5}" -f $Process.ProcessId, $Name, $user, $creationdate_str, $ExePath, $commandline)
          foreach ($Child in ($ProcessesByParent[$ProcessId] | Sort-Object CreationDate)) {
            Show-ProcessTree $Child.ProcessId ($IndentLevel + 2)
          }
        }

        Write-Output ("{0,6} {1} {2} {3} {4}" -f "PID", "Name                          ", "User                          ","Creation date      ","Image path") | out-file -Append -encoding ASCII -filepath ($dumpFileName + "-aggregate.txt")
        Write-Output ("{0,6} {1} {2} {3} {4}" -f "---", "----------------------------  ","----------------------------  ","-------------------","-----------") | out-file -Append -encoding ASCII -filepath ($dumpFileName + "-aggregate.txt")

        foreach ($Process in ($ProcessesWithoutParents | Sort-Object CreationDate)) {
          Write-Output (Show-ProcessTree $Process.ProcessId 0) | out-file -Append -encoding ASCII -filepath ($dumpFileName + "-aggregate.txt")
        }
    }
}

function Get-ScheduledTasks {
    Write-host "...pulling scheduled tasks..." -foregroundcolor green 
    Write-Output ("----------------------------------------------------------") | out-file -Append -encoding ASCII -filepath ($dumpFileName + "-aggregate.txt")
    Write-Output ("   Scheduled Tasks") | out-file -Append -encoding ASCII -filepath ($dumpFileName + "-aggregate.txt")
    Write-Output ("----------------------------------------------------------") | out-file -Append -encoding ASCII -filepath ($dumpFileName + "-aggregate.txt")
    Write-Output "TODO: implement this code" | out-file -Append -encoding ASCII -filepath ($dumpFileName + "-aggregate.txt")
}

function Get-ComputerInfo {
    Write-host "...pulling computer info..." -foregroundcolor green 
    Write-Output ("----------------------------------------------------------") | out-file -Append -encoding ASCII -filepath ($dumpFileName + "-aggregate.txt")
    Write-Output ("   Computer Information") | out-file -Append -encoding ASCII -filepath ($dumpFileName + "-aggregate.txt")
    Write-Output ("----------------------------------------------------------") | out-file -Append -encoding ASCII -filepath ($dumpFileName + "-aggregate.txt")
    Write-Output (get-wmiobject -query "SELECT * FROM Win32_ComputerSystem" |
    select-object Name,Domain,Description,Manufacturer,Model,NumberOfProcessors,`
    TotalPhysicalMemory,SystemType,PrimaryOwnerName,UserName) | out-file -Append -encoding ASCII -filepath ($dumpFileName + "-aggregate.txt")
}

function Get-BIOSinfo {
    Write-host "...pulling bios info..." -foregroundcolor green 
    Write-Output ("----------------------------------------------------------") | out-file -Append -encoding ASCII -filepath ($dumpFileName + "-aggregate.txt")
    Write-Output ("   BIOS Information") | out-file -Append -encoding ASCII -filepath ($dumpFileName + "-aggregate.txt")
    Write-Output ("----------------------------------------------------------") | out-file -Append -encoding ASCII -filepath ($dumpFileName + "-aggregate.txt")
    Write-Output (get-wmiobject -query "SELECT * FROM Win32_BIOS" |
    select-object Name,Version,SMBIOSBIOSVersion) | out-file -Append -encoding ASCII -filepath ($dumpFileName + "-aggregate.txt")
}

function Get-CPUinfo {
    Write-host "...pulling CPU info..." -foregroundcolor green 
    Write-Output ("----------------------------------------------------------") | out-file -Append -encoding ASCII -filepath ($dumpFileName + "-aggregate.txt")
    Write-Output ("   CPU Information") | out-file -Append -encoding ASCII -filepath ($dumpFileName + "-aggregate.txt")
    Write-Output ("----------------------------------------------------------") | out-file -Append -encoding ASCII -filepath ($dumpFileName + "-aggregate.txt")
    Write-Output (get-wmiobject -query "SELECT * FROM Win32_Processor" |
    select-object Manufacturer,Name,CurrentClockSpeed,L2CacheSize) | out-file -Append -encoding ASCII -filepath ($dumpFileName + "-aggregate.txt")
}

function Get-OSinfo {
    Write-host "...pulling OS info..." -foregroundcolor green 
    Write-Output ("----------------------------------------------------------") | out-file -Append -encoding ASCII -filepath ($dumpFileName + "-aggregate.txt")
    Write-Output ("   Operating System Information") | out-file -Append -encoding ASCII -filepath ($dumpFileName + "-aggregate.txt")
    Write-Output ("----------------------------------------------------------") | out-file -Append -encoding ASCII -filepath ($dumpFileName + "-aggregate.txt")
    Write-Output (get-wmiobject -query "SELECT * FROM Win32_OperatingSystem" |
    select-object Caption,BuildNumber,Version,SerialNumber,ServicePackMajorVersion,InstallDate) | out-file -Append -encoding ASCII -filepath ($dumpFileName + "-aggregate.txt")
}

function Get-AdminAccounts {
    Write-host "...pulling administrator info..." -foregroundcolor green 
    Write-Output ("----------------------------------------------------------") | out-file -Append -encoding ASCII -filepath ($dumpFileName + "-aggregate.txt")
    Write-Output ("   Name of Built-In Administrator Accounts") | out-file -Append -encoding ASCII -filepath ($dumpFileName + "-aggregate.txt")
    Write-Output ("----------------------------------------------------------") | out-file -Append -encoding ASCII -filepath ($dumpFileName + "-aggregate.txt")
    Write-Output (get-wmiobject -query "SELECT * FROM Win32_UserAccount" | where-object {$_.SID -match '-500$'} | 
    select-object Name) | out-file -Append -encoding ASCII -filepath ($dumpFileName + "-aggregate.txt")
}

function Get-LAPSinfo {
    Write-host "...pulling LAPS info..." -foregroundcolor green 
    Write-Output ("----------------------------------------------------------") | out-file -Append -encoding ASCII -filepath ($dumpFileName + "-aggregate.txt")
    Write-Output ("   LAPS Information (if available, may be able to pair") | out-file -Append -encoding ASCII -filepath ($dumpFileName + "-aggregate.txt")
    Write-Output ("   with an above account)") | out-file -Append -encoding ASCII -filepath ($dumpFileName + "-aggregate.txt")
    Write-Output ("----------------------------------------------------------") | out-file -Append -encoding ASCII -filepath ($dumpFileName + "-aggregate.txt")
    Write-Output (get-adcomputer -Identity $env:COMPUTERNAME -Properties *| select @{Label="Name";Expression={$_.name}},`
    @{Label="OS";Expression={$_.operatingsystem}}, @{Label="Distinguished name";Expression={$_.'distinguishedname'}},`
    @{Label="Password";Expression={$_.'ms-Mcs-AdmPwd'}}) | out-file -Append -encoding ASCII -filepath ($dumpFileName + "-aggregate.txt")
}

function Get-HotfixInfo {
    Write-host "...pulling hotfix info..." -foregroundcolor green 
    Write-Output ("----------------------------------------------------------") | out-file -Append -encoding ASCII -filepath ($dumpFileName + "-aggregate.txt")
    Write-Output ("   Installed Hotfixes") | out-file -Append -encoding ASCII -filepath ($dumpFileName + "-aggregate.txt")
    Write-Output ("----------------------------------------------------------") | out-file -Append -encoding ASCII -filepath ($dumpFileName + "-aggregate.txt")
    Write-Output (get-wmiobject -query "SELECT * FROM Win32_QuickFixEngineering" |
    select-object HotFixID) | out-file -Append -encoding ASCII -filepath ($dumpFileName + "-aggregate.txt")
}

function Get-ADinfo {
    Write-host "...pulling AD info..." -foregroundcolor green 
    Write-Output ("----------------------------------------------------------") | out-file -Append -encoding ASCII -filepath ($dumpFileName + "-aggregate.txt")
    Write-Output ("   Active Directory Information") | out-file -Append -encoding ASCII -filepath ($dumpFileName + "-aggregate.txt")
    Write-Output ("----------------------------------------------------------") | out-file -Append -encoding ASCII -filepath ($dumpFileName + "-aggregate.txt")
    Write-Output (get-adcomputer -Identity $env:COMPUTERNAME -Properties *) | out-file -Append -encoding ASCII -filepath ($dumpFileName + "-aggregate.txt")
}

function Get-NetworkInfo {
    Write-host "...pulling network info..." -foregroundcolor green 
    Write-Output ("----------------------------------------------------------") | out-file -Append -encoding ASCII -filepath ($dumpFileName + "-aggregate.txt")
    Write-Output ("   Network Information") | out-file -Append -encoding ASCII -filepath ($dumpFileName + "-aggregate.txt")
    Write-Output ("----------------------------------------------------------") | out-file -Append -encoding ASCII -filepath ($dumpFileName + "-aggregate.txt")
    Write-Output (Get-NetAdapter) | out-file -Append -encoding ASCII -filepath ($dumpFileName + "-aggregate.txt")
}

function Get-TCPconnections {
    Write-host "...pulling connection info..." -foregroundcolor green 
    Write-Output ("----------------------------------------------------------") | out-file -Append -encoding ASCII -filepath ($dumpFileName + "-aggregate.txt")
    Write-Output ("   TCP Connection Information") | out-file -Append -encoding ASCII -filepath ($dumpFileName + "-aggregate.txt")
    Write-Output ("----------------------------------------------------------") | out-file -Append -encoding ASCII -filepath ($dumpFileName + "-aggregate.txt")
    Write-Output (Get-NetTCPConnection) | out-file -Append -encoding ASCII -filepath ($dumpFileName + "-aggregate.txt")
}

function Get-EndOutput {
    Write-Output "///END OF OUTPUT///"| out-file -Append -encoding ASCII -filepath ($dumpFileName + "-aggregate.txt")
    Write-host "...aggregate data pull complete." -foregroundcolor green
}

function GetThemAll {
    
    Write-host "[+] Starting acquisition process..." -foregroundcolor green
    
    # get output and start file
    Get-StartOutput

    ## not yet implemented items
    #Get-MemoryDump
    #Get-SystemServices
    #Get-ScheduledTasks
    
    ## implemented items
    Get-ComputerInfo
    Get-ProcessTree
    Get-BIOSinfo
    Get-CPUinfo
    Get-OSinfo
    Get-AdminAccounts
    Get-LAPSinfo
    Get-HotfixInfo
    Get-ADinfo
    Get-NetworkInfo
    Get-TCPconnections

    # wrap up output and let user know location
    Get-EndOutput

    #copy journal events
    Write-host "...pulling security event log..." -foregroundcolor green
    wevtutil epl security ($dumpFileName + "-security.evtx")

    #hash all the things
    Write-host "...hashing aggregate and event files..." -foregroundcolor green
    get-filehash ($dumpFileName + "-aggregate.txt") | format-list | out-file -append ($dumpFileName + "--HASHES.txt")
    get-filehash ($dumpFileName + "-security.evtx") | format-list | out-file -append ($dumpFileName + "--HASHES.txt")

    Write-host "...all files located at: `n`t" ($dumpFileName + "*") -foregroundcolor yellow 

    Write-host "[+] Finished acquisition process." -foregroundcolor green 

}

function main {
    Write-Output "This came from the main function...nothing to see here."
}