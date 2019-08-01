<#
NAME: 01-Pull_Machine_Info.ps1
VERSION: v1.0
AUTHOR: Jimmi Aylesworth
DATE: 20190731

DESCRIPTION:
This script calls the IR-Dumper module and will be used to call
any additional modules that are added later on.

All files written out to directory script is called from; if run
from a device that has a bit-locker enforced policy (i.e. USB Drive),
you will need to either disable that or copy the file to a disc
that can be written to.

#>

#global variables
$currentPath = (Split-Path $MyInvocation.MyCommand.Path)

#make sure we have a trailing "\"
If ($currentPath[-1] -notmatch "\\")
{
    $currentPath+="\"
}

$scriptPath = $currentPath + "IRDumper.psm1"

#import module and suppress warnings
Import-Module -Name $scriptPath 3>$null

#list out the available commands
Get-Command -Module IRDumper

GetThemAll
