#make a GPO directory
New-Item -Path (".\GPO") -ItemType Directory

#let user know what we are doing (this may take some time)
Write-host "...pulling GPO policy reports..." -foregroundcolor green

#get all GPO policies and their [GU]ID 
$GPOList = Get-GPO -all | Select-Object -Property DisplayName,Id

#loop through all GPO's (by ID) and generate an HTML report for them
# -- below -ReportType can be changed to "XML" if desired
ForEach ($gpo in $GPOList) {
  get-GPOReport -GUID $gpo.Id -ReportType Html -Path ($dumpFileName + "\GPO\" + $gpo.DisplayName + " (" + $gpo.Id + ").html") 2> $null 
}