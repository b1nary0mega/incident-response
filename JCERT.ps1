<#
NAME: JCERT.ps1
VERSION: refer to GitHub ;)
AUTHOR: Jimmi Aylesworth
DATE: 20190823
LEGAL: Public domain, no rights reserved.

DESCRIPTION:
This script will attempt to pull as much data as possible on a computer, 
storing copies and then hashing all collected files to a file of hashes.

NOTE:
Some additional tools may be required for review:
SysInternals: https://docs.microsoft.com/en-us/sysinternals/
WinPreFetchView: https://www.nirsoft.net/utils/win_prefetch_view.html
Other: https://ericzimmerman.github.io/#!index.md



Data Gathering:
[X] Computer Information
    - Name, Domain, Manufacturer, Model
    [x] BIOS Information
    [x] CPU Information
    [x] OS Information
        - Name, Version, Build
    [x] Installed Hotfixes
[-] Memory Dump
    [x] Prefetch files
    [ ] Pagefile
[X] Scheduled Tasks
[X] System Services
[X] Logged On User
[X] Network Information & Connections

#>
function Get-AutorunsQuery {
    Write-host "...pulling autorun info..." -foregroundcolor green 
    .\autorunsc64.exe -accepteula -a * -c > ($dumpFileName + "\" + $env:ComputerName + "-autoruns.csv")
    $fileNames.Add($dumpFileName + "\" + $env:ComputerName + "-autoruns.csv")
}

function Get-ComputerInfo {
# SOURCE: Jason Fossen @ http://www.sans.org/sec505
  Write-Output (.\Show-ComputerInfo.ps1) | out-file -Append -encoding ASCII -filepath ($dumpFileName + "\" + $env:ComputerName +  "-ComputerInfo.txt")
  Write-host "...pulling computer info..." -foregroundcolor green 
  $fileNames.Add($dumpFileName + "\" + $env:ComputerName +  "-ComputerInfo.txt")
}

function Get-Network_clientDNSCache {
  Write-Output (Get-DnsClientCache) | out-file -Append -encoding ASCII -filepath ($dumpFileName + "\" + $env:ComputerName +  "-DNSCache.txt")
  Write-host "...pulling dns cache info..." -foregroundcolor green
  $fileNames.Add($dumpFileName + "\" + $env:ComputerName +  "-DNSCache.txt")
}

function Get-Network_clientIPConfig {
  Write-Output (Get-NetIPConfiguration) | out-file -Append -encoding ASCII -filepath ($dumpFileName + "\" + $env:ComputerName +  "-IPConfig.txt")
  Write-host "...pulling ip configuration..." -foregroundcolor green
  $fileNames.Add($dumpFileName + "\" + $env:ComputerName +  "-IPConfig.txt")
}

function Get-Network_clientConnections {
  #Get All TCP Connections
  Write-Output (Get-NetTCPConnection) | out-file -Append -encoding ASCII -filepath ($dumpFileName + "\" + $env:ComputerName +  "-TCPConnections.txt")
  Write-host "...pulling tcp connections..." -foregroundcolor green
  $fileNames.Add($dumpFileName + "\" + $env:ComputerName +  "-TCPConnections.txt")

  #Now get all established/listening connections with NetStat
  Write-Output (netstat -naob) | out-file -Append -encoding ASCII -filepath ($dumpFileName + "\" + $env:ComputerName +  "-NetStat.txt")
  Write-host "...pulling netstat info..." -foregroundcolor green
  $fileNames.Add($dumpFileName + "\" + $env:ComputerName +  "-NetStat.txt")
}

function Get-Network_clientARPTable {
  Write-Output (arp -a) | out-file -Append -encoding ASCII -filepath ($dumpFileName + "\" + $env:ComputerName +  "-ARPTable.txt")
  Write-host "...pulling arp table..." -foregroundcolor green
  $fileNames.Add($dumpFileName + "\" + $env:ComputerName +  "-ARPTable.txt")
}

function Get-HostsCopy {
    Write-host "...pulling hosts file..." -foregroundcolor green 
    Copy-Item -path ($env:WinDir + "\System32\drivers\etc\hosts") -destination ($dumpFileName + "\" + $env:ComputerName + "-Hosts.txt")
    $fileNames.Add($dumpFileName + "\" + $env:ComputerName + "-Hosts.txt")
}

function Get-FileHasher {
    Write-host "...hashing all the things..." -foregroundcolor green 
    ForEach ($file in $fileNames) {
        get-filehash ($file) | format-list | out-file -append -encoding ASCII -filepath ($dumpFileName + "\" + $env:ComputerName +  "-Hashes.txt")
    } 
}

Function Get-FirewallData {
  Write-host "...pulling firewall configuration..." -foregroundcolor green 
  $fileNames.Add($dumpFileName + "\" + $env:ComputerName +  "-FirewallConfig.txt")
  netsh advfirewall show allprofiles | out-file -append -encoding ASCII -filepath ($dumpFileName + "\" + $env:ComputerName +  "-FirewallConfig.txt")
  
  Write-host "...pulling firewall rules..." -foregroundcolor green
  $fileNames.Add($dumpFileName + "\" + $env:ComputerName +  "-FirewallRules.txt")
  netsh advfirewall firewall show rule name=all type=dynamic | out-file -append -encoding ASCII -filepath ($dumpFileName + "\" + $env:ComputerName +  "-FirewallRules.txt")

  Write-host "...pulling firewall log..." -foregroundcolor green 
  $fileNames.Add($dumpFileName + "\" + $env:ComputerName +  "-Firewall.log")
  copy-item -path ($env:WinDir + "\System32\LogFiles\Firewall\pfirewall.log") -destination ($dumpFileName + "\" + $env:ComputerName + "-Firewall.log")
}

function Get-GroupQuery {
# SOURCE: Boe Prox @ https://mcpmag.com/articles/2015/06/18/reporting-on-local-groups.aspx
  [Cmdletbinding()] 

  Param (
    [Parameter(ValueFromPipeline=$True, ValueFromPipelineByPropertyName=$True)]
    [String[]]$Computername =  $Env:COMPUTERNAME,
    [parameter()]
    [string[]]$Group
  )

  Begin {

    Function  ConvertTo-SID {
      Param([byte[]]$BinarySID)
      (New-Object  System.Security.Principal.SecurityIdentifier($BinarySID,0)).Value
    }
  
    Function  Get-LocalGroupMember {
      Param  ($Group)
      $group.Invoke('members')  | ForEach {
        $_.GetType().InvokeMember("Name",  'GetProperty',  $null,  $_, $null)
      }
    }
  }

  Process  {

    Write-host "...pulling local groups..." -foregroundcolor green 

    ForEach  ($Computer in  $Computername) {
      Try {
        Write-Verbose  "Connecting to $($Computer)"
        $adsi  = [ADSI]"WinNT://$Computer"

        If  ($PSBoundParameters.ContainsKey('Group')) {
          Write-Verbose  "Scanning for groups: $($Group -join ',')"
          $Groups  = ForEach  ($item in  $group) {
            $adsi.Children.Find($Item, 'Group')
          }
        } Else {
          Write-Verbose  "Scanning all groups"
          $groups  = $adsi.Children | where {$_.SchemaClassName -eq  'group'}
        }

        If  ($groups) {
          $groups  | ForEach {
            Write-Output ("Computer: " + `
                $Computer + "`nName: " + $_.Name[0] + "`nMembers: " + `
                ((Get-LocalGroupMember  -Group $_) -join ', ') + `
                "`nSID: " + (ConvertTo-SID -BinarySID $_.ObjectSID[0])`
                + "`n") | out-file -Append -encoding ASCII -filepath ($dumpFileName + "\" + $env:ComputerName + "-Groups.txt")
          }
          #add the filename to collection
          $fileNames.Add($dumpFileName + "\" + $env:ComputerName + "-Groups.txt")
        } Else {
          Throw  "No groups found!"
        }
      } Catch {
        Write-Warning  "$($Computer): $_"
      }
    }
  }
}

function Get-HiveCopy {
    # !!! will FAIL without elevated privs !!! #
    $Hives = "SYSTEM","SOFTWARE","SAM"
    Write-host "...pulling registry hive(s)..." -foregroundcolor green 
    forEach ($hive in $Hives){
        Write-host ("... ... " + $hive + "... ...") -foregroundcolor blue 
        reg save HKLM\SYSTEM ($dumpFileName + "\hives\" + $env:ComputerName + "-" + $hive)
        $fileNames.Add($dumpFileName + "\hives\" + $env:ComputerName + "-" + $hive)
    }
}

function Get-HiveByUsers {
    # !!! will FAIL without elevated privs !!! #
    Write-host "...querying user registries..." -foregroundcolor green

    #create list of possible user registries
    reg query HKU | out-file -encoding ASCII -filepath ($dumpFileName + "\hives\" + $env:ComputerName + "-HKU-list.txt")
    $fileNames.Add($dumpFileName + "\hives\" + $env:ComputerName + "-HKU-list.txt")
    
    #clean up list
    (Get-Content ($dumpFileName + "\hives\" + $env:ComputerName + "-HKU-list.txt")) -replace "HKEY_USERS\\", "" | out-file -encoding ASCII -filepath ($dumpFileName + "\hives\" + $env:ComputerName + "-HKU-list.txt")
    
    #itterate through list, saving keys
    $RegistryUsers = Get-Content ($dumpFileName + "\hives\" + $env:ComputerName + "-HKU-list.txt")
    forEach ($RegistryUser in $RegistryUsers) {
      if ($RegistryUser -eq "") {continue} #first line is blank; skip it
      reg save ("HKU\" + $RegistryUser) ($dumpFileName + "\hives\" + $env:ComputerName + "-" + $RegistryUser + "-NTHive")
      $fileNames.Add($dumpFileName + "\hives\" + $env:ComputerName + "-" + $RegistryUser + "-NTHive")
    }
}

function Get-ComputerShares {
    Write-host "...pulling computer shares..." -foregroundcolor green 
    Get-WMIObject -class Win32_Share | out-file -append -encoding ASCII -filepath ($dumpFileName + "\" + $env:ComputerName + "-ComputerShares.txt")
    $fileNames.Add($dumpFileName + "\" + $env:ComputerName + "-ComputerShares.txt")
}

function Get-ComputerDrives {
    Write-host "...pulling computer drives..." -foregroundcolor green 
    Get-WMIObject -class Win32_LogicalDisk | out-file -append -encoding ASCII -filepath ($dumpFileName + "\" + $env:ComputerName + "-ComputerDrives.txt")
    $fileNames.Add($dumpFileName + "\" + $env:ComputerName + "-ComputerDrives.txt")
}

function Get-LogCopy {
    $Logs = @{Security = "Security"; Application = "Application"; System = "System"; `
      Powershell = "Microsoft-Windows-PowerShell/Operational"; `
      TaskScheduler = "Microsoft-Windows-TaskScheduler/Operational"
    }
    Write-host "...pulling log files..." -foregroundcolor green 
    forEach ($log in $Logs.keys) {
        Write-host ("... ... " + $log + "... ...") -foregroundcolor blue 
        wevtutil epl $Logs[$log] ($dumpFileName + "\logs\" + $env:ComputerName + "-" + $log + ".evtx")
        $fileNames.Add($dumpFileName + "\logs\" + $env:ComputerName + "-" + $log + ".evtx") 
    }
}

function Get-PrefetchCopy {
    Write-host "...pulling prefetch files..." -foregroundcolor green 
    Copy-Item c:\windows\prefetch\*.pf ($dumpFileName + "\prefetch") -recurse

    <#TODO##
        Hash all items & store output
    #>
}

function Get-Processes_PSTree {
# SOURCE: Adam Roben @ https://gist.github.com/aroben/5542538
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

Function Get-Processes_CPUMemUse {
  Write-host "...pulling process cpu and memory usage..." -foregroundcolor green
  $fileNames.Add($dumpFileName + "\" + $env:ComputerName + "-CPUMemUse.txt")
  Write-Output (get-process|select Name, Description, ID, @{Label="Memory Usage(KB)";Expression={($_.WS / 1KB)}}, @{Label="CPU Time(s)";Expression={($_.CPU)}}) | `
  out-file -Append -encoding ASCII -filepath ($dumpFileName + "\" + $env:ComputerName + "-CPUMemUse.txt")
}

function Get-TaskLists {
  $TasklistSwitches = @{Services = "svc"; Verbose = "v"; Modules = "m"}
  Write-host "...pulling running processes..." -foregroundcolor green
  forEach ($switch in $TasklistSwitches.keys) {
    Write-host ("... ... " + $switch + "... ...") -foregroundcolor blue
    Write-Output (tasklist ("/" + $TasklistSwitches[$switch])) | out-file -Append -encoding ASCII -filepath ($dumpFileName + "\" + $env:ComputerName + "-Tasklist-" + $switch +".txt")
    $fileNames.Add($dumpFileName + "\" + $env:ComputerName + "-Tasklist-" + $switch +".txt")
  }
}

function Get-ScheduledTasks {
  Write-host "...pulling scheduled tasks..." -foregroundcolor green 
  schtasks /query /fo list /v | out-file ($dumpFileName + "\" + $env:ComputerName + "-ScheduledTasks.txt")
  $fileNames.Add($dumpFileName + "\" + $env:ComputerName + "-ScheduledTasks.txt")
}

function Get-SystemServices {
    Write-host "...pulling system services..." -foregroundcolor green
    $ServiceStatus = "Running", "Stopped"
    forEach ($status in $ServiceStatus) {
      Write-host ("... ... " + $status + " ... ...") -foregroundcolor blue 
      Write-Output (Get-Service | Where {$_.Status -eq $status} | Select-Object *) | `
        out-file -Append -encoding ASCII -filepath ($dumpFileName + "\" + $env:ComputerName +  "-SystemServices.txt")
      $fileNames.Add($dumpFileName + "\" + $env:ComputerName +  "-SystemServices.txt")
    }
}

<###########################################################
                  Let's begin...shall we
###########################################################>

Write-host "[+] Beginning Data Acquisition" -foregroundcolor green 
$VICTIM = ${Env:ComputerName} #computername

$fileNames = New-Object System.Collections.Generic.List[string] #collection to store files (full path)

$datetimeString = (Get-Date -format o | ForEach-Object { $_ -replace ":", "." }) #filename friendly DT string for labeling

$dumpFileName = ".\Incoming\" + $datetimeString + "--" + $VICTIM

#make directories to store above mentioned files
$destinations = "prefetch","hives","logs"
Write-host "[-] Creating directory structure"
forEach ($dest in $destinations) {
    New-Item -Path ($dumpFileName + "\" + $dest) -ItemType Directory
}

### Enumerate Files ###
Get-PrefetchCopy
Get-HiveCopy
Get-HiveByUsers

### Collect network caches ###
Get-Network_clientDNSCache
Get-Network_clientARPTable

### Collect User & Administrator Group Members ### 
Get-GroupQuery -Computername  $env:COMPUTERNAME -Group  Administrators,  Users  | Format-List 

### Analyze Startup Items ###
Get-AutorunsQuery

### Analyze Programs Run ###
### Collect Network Shares ###

### Collect System Configuration ###
Get-SystemServices

### Analyze Scheduled tasks ###
Get-ScheduledTasks

### Collect event logs ###
Get-LogCopy

### Collect Processes ###
Get-Processes_PSTree
Get-TaskLists
Get-Processes_CPUMemUse

### Collect Network Connections and Ports ###
Get-Network_clientConnections
Get-Network_clientIPConfig
Get-HostsCopy
Get-FirewallData

### Collect web files ###

#all your datas belong to $dumpFileName ;)
Get-ComputerShares
Get-ComputerDrives
Get-ComputerInfo

### Analyze all files ###



#finish up by providing a hash for all pulled data and files
Get-FileHasher

#let the user know we are finished
Write-host "[+] Completed Data Acquisition" -foregroundcolor green 