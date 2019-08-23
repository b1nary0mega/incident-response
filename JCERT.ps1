<#
NAME: Get_Stuff-prototype.ps1
VERSION: v1.0
AUTHOR: Jimmi Aylesworth
DATE: 20190823
LEGAL: Public domain, no rights reserved.

DESCRIPTION:
This script will attempt to pull as much data as possible on a computer, 
storing a copy of it, and then adding its HASH to an output file of all hashes.

Data Gathering:
[X] Computer Information
    - Name, Domain, Manufacturer, Model
    [x] BIOS Information
    [x] CPU Information
    [x] OS Information
        - Name, Version, Build
    [x] Installed Hotfixes
[ ] Memory Dump
    [x] Prefetch files
    [ ] Pagefile
[ ] Scheduled Tasks
[ ] System Services
[ ] Logged On User
[ ] Network Information & Connections

#>

# Get Machine Information (SOURCE: http://www.sans.org/sec505)
function computerInfo {
    Write-Output (.\Show-ComputerInfo.ps1) | out-file -Append -encoding ASCII -filepath ($dumpFileName + "\" + $env:ComputerName +  "-ComputerInfo.txt")
    Write-host "...pulling computer info..." -foregroundcolor green 
    $fileNames.Add($dumpFileName + "\" + $env:ComputerName +  "-ComputerInfo.txt")
}

# Pull Machine Logs
function logCopy {
    $Logs = @{Security = "Security"; Application = "Application"; System = "System"; Powershell = "Microsoft-Windows-PowerShell/Operational"}
    Write-host "...copying log files..." -foregroundcolor green 
    forEach ($log in $Logs.keys) {
        Write-host "... ... " $log "... ..." -foregroundcolor blue 
        wevtutil epl $Logs[$log] ($dumpFileName + "\logs\" + $env:ComputerName + "-" + $log + ".evtx")
        $fileNames.Add($dumpFileName + "\logs\" + $env:ComputerName + "-" + $log + ".evtx") 
    }
}

# Get Prefetch files
function prefetchCopy {
    Write-host "...copying prefetch files..." -foregroundcolor green 
    Copy-Item c:\windows\prefetch\*.pf ($dumpFileName + "\prefetch") -recurse

    <#TODO##
        Hash all items & store output
    #>
}

# Get Machine Autoruns
function autorunsQuery {
    Write-host "...pulling autorun info..." -foregroundcolor green 
    .\autorunsc64.exe -accepteula -a * -c > ($dumpFileName + "\" + $env:ComputerName + "-autoruns.csv")
    $fileNames.Add($dumpFileName + "\" + $env:ComputerName + "-autoruns.csv")
}

# Get Machine Hives (must have run script with elevated privs)
function hiveCopy {
    $Hives = "SYSTEM","SOFTWARE","SAM"
    Write-host "...pulling registry hive(s)..." -foregroundcolor green 
    forEach ($hive in $Hives){
        Write-host "... ... " + $hive " ... ..." -foregroundcolor blue 
        reg save HKLM\SYSTEM ($dumpFileName + "\hives\" + $env:ComputerName + "-" + $hive)
        $fileNames.Add($dumpFileName + "\hives\" + $env:ComputerName + "-" + $hive)
    }
}

# Recreate a PSTREE function for this windows instance
# SOURCE: Adam Roben @ https://gist.github.com/aroben/5542538
function processTreeExport {
    Write-host "...pulling process tree..." -foregroundcolor green
    $fileNames.Add($dumpFileName + "\" + $env:ComputerName + "-ProcessTree.txt")
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

        Write-Output ("{0,6} {1} {2} {3} {4}" -f "PID", "Name                          ", "User                          ","Creation date      ","Image path") | out-file -Append -encoding ASCII -filepath ($dumpFileName + "\" + $env:ComputerName + "-ProcessTree.txt")
        Write-Output ("{0,6} {1} {2} {3} {4}" -f "---", "----------------------------  ","----------------------------  ","-------------------","-----------") | out-file -Append -encoding ASCII -filepath ($dumpFileName + "\" + $env:ComputerName + "-ProcessTree.txt")

        foreach ($Process in ($ProcessesWithoutParents | Sort-Object CreationDate)) {
          Write-Output (Show-ProcessTree $Process.ProcessId 0) | out-file -Append -encoding ASCII -filepath ($dumpFileName + "\" + $env:ComputerName + "-ProcessTree.txt")
        }
    }
}

# Hash all files
function fileHasher {
    Write-host "...hashing all the things..." -foregroundcolor green 
    ForEach ($file in $fileNames) {
        get-filehash ($file) | format-list | out-file -append ($dumpFileName + "--HASHES.txt")
    } 
}

<###########################################################

###########################################################>
Write-host "[+] Beginning Data Acquisition" -foregroundcolor green 
$VICTIM = ${Env:ComputerName}
$fileNames = New-Object System.Collections.Generic.List[string]

$datetimeString = (Get-Date -format o | ForEach-Object { $_ -replace ":", "." })
#$dumpFileName = "\\fileserver1\isad\ISADdata\IS_Staff\CyberSecurity\Incoming\" + $datetimeString + "--" + $VICTIM
$dumpFileName = ".\Incoming\" + $datetimeString + "--" + $VICTIM

#make directories to store files
$destinations = "prefetch","hives","logs"
Write-host "[-] Creating directory structure"
forEach ($dest in $destinations) {
    New-Item -Path ($dumpFileName + "\" + $dest) -ItemType Directory
}

computerInfo
logCopy
prefetchCopy
autorunsQuery
hiveCopy
ProcessTreeExport
fileHasher

Write-host "[+] Completed Data Acquisition" -foregroundcolor green 