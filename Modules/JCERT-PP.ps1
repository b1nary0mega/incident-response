<#
NAME: JCERT-PP.ps1
VERSION: refer to GitHub ;)
AUTHOR: Jimmi Aylesworth
DATE: 20191011
LEGAL: Public domain, no rights reserved.

DESCRIPTION:
Post Processing [PP] of data gathered via the JCERT module.

Data Gathering:
[ ] IP Addresses
[ ] Event Log Queries
[ ] ...more when I think of it...

#>

<###########################################################
                  Let's begin...shall we
###########################################################>

#search "Incoming" folder for case folders to investigate
$IncomingFolder = Get-ChildItem ../Incoming

#output list of available directories with index
try{
  $dirCount = 0
  Write-host "The following directories are available...`n"
  foreach ($dir in $IncomingFolder) {
      Write-host '[' $dirCount ']' $dir
      $dirCount++
  }
}
catch {
  Write-host "No \'Incoming' folder found...please verify it exists at the root."
}

#ask for a directory index
do {
  $FolderIndex = Read-Host -Prompt "`nWhat directory number would you like to investigate? "
}  while ($FolderIndex -lt 0 -or $FolderIndex -gt (($IncomingFolder).Count - 1))


Write-host "`nInvestigating :: " $IncomingFolder[$FolderIndex] 

Write-host  "`n`t...Please stand by...`n"

#begin ingesting folder
$IngestList = Get-ChildItem -recurse ("../Incoming/" + $IncomingFolder[$folderIndex])

#inform the user of the found files, by type
$FileExt = "txt","evtx","pf","aff4"
foreach ($ext in $FileExt) {
  Write-host "`nThe following __" $ext "__ files were found:" -foregroundcolor green
  foreach ($item in $IngestList | where {$_.extension -eq ("." + $ext)}) {Write-host $item.Fullname}
}
