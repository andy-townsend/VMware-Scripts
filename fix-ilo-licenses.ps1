<#
  .AUTHOR
  Andy Townsend - andy@alphatangoconsultants.com

  .SYNOPSIS
  This script checks and fixes the iLO licenses applied to the blades in an enclosure. 

  .DESCRIPTION
  If the script finds a blade with a Standard iLO license then it will try to fix it by applying the Advanced license

  The script makes use of the HP cmdlets. 

  .NOTES
  Enter the enclosure address without any http:// or https:// in front of it.

  .TO-DO
  Need to add the code to apply the license	

#>

param (
    [Parameter(Mandatory=$true)][String] $enclosure
)

$advancedLicense = "XXXXX-XXXXX-XXXXX-XXXXX-XXXXX"


##################################################
# Check the iLO license as Advanced is required. #
##################################################
Write-Host "Checking the iLO Licenses in $enclosure" -BackgroundColor Yellow -ForegroundColor Blue 

try{
    [xml]$xmlData = Invoke-WebRequest "https://$enclosure/xmldata?item=all"
} catch [System.Net.WebException] {
    Write-host "Could not connect to enclosure : " $enclosure -BackgroundColor DarkRed -ForegroundColor Red
}

foreach ($blade in $xmlData.RIMP.INFRA2.BLADES.BLADE){
    $bladeIP = $blade.MGMTIPADDR
    $webrequest = "https://$bladeIP/xmldata?item=CpqKey"
    # Check blade IP is reachable before grabbing the data
    if (Test-Connection -ComputerName $bladeIP -quiet){
        $bladeXML = Invoke-WebRequest $webrequest

        # Be sure to trim the response as its prepended with white space which invalidates it as XML
        [xml]$bladeVersion = ($bladeXML.Content).Trim()

        # Check if we're running the Advanced version
        if ( $bladeversion.PROLIANTKEY.LNAME -like "*Advanced for BladeSystem"){
            write-host "Host: " $blade.Name "has iLO IP :" $blade.MGMTIPADDR " : " $bladeversion.PROLIANTKEY.LNAME -BackgroundColor DarkGreen -ForegroundColor Green
        } else {
            write-host "Host: " $blade.Name "has iLO IP :" $blade.MGMTIPADDR " : " $bladeversion.PROLIANTKEY.LNAME -BackgroundColor DarkRed -ForegroundColor Red
        }
    } else {
        write-host "Host: " $blade.Name "is unreachable on " $blade.MGMTIPADDR
    }
}
