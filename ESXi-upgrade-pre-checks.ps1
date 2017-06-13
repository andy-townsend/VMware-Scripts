<#
  .AUTHOR
  Andy Townsend - andy@alphatangoconsultants.com

  .SYNOPSIS
  This script performs the pre-checks against a cluster prior to an ESXi upgrade. The script can also be ran post-upgrade to check on status.

  .DESCRIPTION
  This script performs the following checks as well as generating a CSV of VMs running on the cluster. All files are output to a sub-directory that uses the CHG number\clusters name.
  Script output is recorded in a time-stamped log file as well. Console output is highlighted with anything bad in red to allow for easy checks. 

  - Checks ESXi Version
  - Checks iLO license on each blade in enclosure
  - Checks vMotion IPs, Mask and VLANID and records as backup in case of needing to revert
  - Checks if each host has 4 physical uplinks
  - Check if physical NICs are all up
  - Checks for any dead storage paths
  - Exports a list of VMs on the cluster - used to find owners should any host outages occur
  - Checks SSH status on each Host
  - Checks for VMs with Memory Reservations
  - Ping VMs to confirm connectivity
  - Check Cluster Alarm status
  - Check Host Alarm Status
  - Added additional check to make sure vmk0 is enabled for mgmt traffic only and vmk1 is enabled for vMotion only
  - Checks DRS/HA settings and records to an XML file. Verifies current settings against these if the file exists to ensure it is back to normal.

  .NOTES
  This script checks the current version of ESXi installed is equal to $requiredESXi51Version or $requiredESXi55Version. 
  If running the script for a new upgrade (non U3d) then please update these values

  Enter the enclosure address without any http:// or https:// in front of it.

#>

param (
    [Parameter(Mandatory=$true)][String] $vCenter,
    [Parameter(Mandatory=$true)][String] $cluster,
    [Parameter(Mandatory=$true)][String] $changeNum
    #[Parameter(Mandatory=$true)][String] $enclosure
)

# Generate a filename including date/time and cluster name.
$now=Get-Date -Format "yyyyMMdd_HHmmss"
$filename = "$cluster-prechecks-$now"

# Set the required build versions for 5.1 and 5.5
$requiredESXi51Version = "VMware ESXi 5.1.0 build-3070626"
$requiredESXi55Version = "VMware ESXi 5.5.0 build-3568722"

# Make sure transcript isn't running already from a previous failed run of the script.
try{
Stop-Transcript | Out-Null
} catch [System.InvalidOperationException] {}

# Create a directory to contain the output for the cluster.
if (!(Test-Path ".\$changeNum\$cluster")){
    New-Item -ItemType Directory -Path ".\$changeNum\$cluster" | Out-Null

}

# Start transcript to record script output.
Start-Transcript -Path ".\$changeNum\$cluster\$filename.txt"
 

# Run under the current users context. All users should have Read-Only permissions on the VCs which is enough.
# Swap out the line below should you need to run with a different account.
#$userName = Read-Host "Enter your VC Username: "
$userName = "$env:USERDOMAIN\$env:USERNAME"
$passwd = Read-Host ("Enter Password for " + $userName) -AsSecureString:$true
$cred = New-Object System.Management.Automation.PSCredential -ArgumentList $userName,$passwd

#Connect to vCenter
Try {
    Connect-VIServer -Server $vCenter -Credential $cred | Out-Null 
}
Catch {
Throw "Error Connecting to $Vcenter, Please check $Vcenter name AND/OR credentials"
}

# Necessary for environment because of proxy setup
Set-PowerCLIConfiguration -ProxyPolicy NoProxy -scope session -confirm:$false | Out-Null

# Create a cluster object to work with.
$objCluster = get-cluster $cluster

# Get a list of VM hosts in the cluster
$Esxihosts = $objCluster | Get-VMHost |where {$_.State -eq "Connected"}| Sort


############################################
# Get the ESXi Version before the upgrade. #
############################################
Write-Host "Getting the ESXi Version for hosts in $cluster" -BackgroundColor Yellow -ForegroundColor Blue 

foreach ($Esxihost in $Esxihosts) { 
    $version = $esxihost.ExtensionData.config.Product.fullname
    if ($version -eq $requiredESXi51Version  -or $version -eq $requiredESXi55Version ){
        Write-Host $Esxihost ":" $version -BackgroundColor DarkGreen -ForegroundColor Green
    } else {
        Write-Host $Esxihost ":" $version " : UPGRADE REQUIRED" -BackgroundColor DarkRed -ForegroundColor Red
    }
}

# ##################################################
# # Check the iLO license as Advanced is required. #
# ##################################################
# Write-Host "Checking the iLO Licenses in $cluster" -BackgroundColor Yellow -ForegroundColor Blue 

# try{
    # [xml]$xmlData = Invoke-WebRequest "https://$enclosure/xmldata?item=all"
# } catch [System.Net.WebException] {
    # Write-host "Could not connect to enclosure : " $enclosure -BackgroundColor DarkRed -ForegroundColor Red
# }

# foreach ($blade in $xmlData.RIMP.INFRA2.BLADES.BLADE){
    # $bladeIP = $blade.MGMTIPADDR
    # $webrequest = "https://$bladeIP/xmldata?item=CpqKey"
    # # Check blade IP is reachable before grabbing the data
    # if (Test-Connection -ComputerName $bladeIP -quiet){
        # $bladeXML = Invoke-WebRequest $webrequest

        # # Be sure to trim the response as its prepended with white space which invalidates it as XML
        # [xml]$bladeVersion = ($bladeXML.Content).Trim()

        # # Check if we're running the Advanced version
        # if ( $bladeversion.PROLIANTKEY.LNAME -like "*Advanced for BladeSystem"){
            # write-host "Host: " $blade.Name "has iLO IP :" $blade.MGMTIPADDR " : " $bladeversion.PROLIANTKEY.LNAME -BackgroundColor DarkGreen -ForegroundColor Green
        # } else {
            # write-host "Host: " $blade.Name "has iLO IP :" $blade.MGMTIPADDR " : " $bladeversion.PROLIANTKEY.LNAME -BackgroundColor DarkRed -ForegroundColor Red
        # }
    # } else {
        # write-host "Host: " $blade.Name "is unreachable on " $blade.MGMTIPADDR
    # }
# }

###########################################################
# Get the vMotion IPs for the cluster before the upgrade. #
###########################################################
Write-Host "Getting the list of vMotion IPs for $cluster" -BackgroundColor Yellow -ForegroundColor Blue  

foreach ($Esxihost in $Esxihosts) {
    $vMotionDetails =  $Esxihost | get-vmhostnetworkadapter | where {$_.VMotionEnabled}|  select VMHost, Name, IP, SubnetMask, PortgroupName, mtu
    foreach ($vMotionNic in $vMotionDetails) {
        $portgroup = get-vdswitch -name "*$cluster*" | get-vdportgroup -name $vmotionNic.PortGroupName
        $vMotionVlanID = $portgroup.ExtensionData.config.defaultportconfig.vlan.vlanID
        Write-Host $vMotionNic.VMHost ":" $vMotionNic.Name ":" $vMotionNic.IP ":" $vMotionNic.Subnetmask ": VLAN" $vmotionNic.PortgroupName ": VLANID" $vmotionVlanID
    }
}

#######################################################################
# Check vmk0 is enabled for MGMT and vmk1 is enabled for vMotion only #
#######################################################################
Write-Host "Checking MGMT/vMotion interfaces for hosts in $cluster" -BackgroundColor Yellow -ForegroundColor Blue  

foreach ($Esxihost in $Esxihosts) {
    $vmk0 = $esxihost | Get-Vmhostnetworkadapter | select Name, VmotionEnabled, ManagementTrafficEnabled, IP | where {$_.name -like "vmk0"}
    $vmk1 = $esxihost | Get-Vmhostnetworkadapter | select Name, VmotionEnabled, ManagementTrafficEnabled, IP | where {$_.name -like "vmk1"}

    # Check VMK0 is enabled for MGMT only and not vMotion
    if ($vmk0.ManagementTrafficEnabled -AND !($vmk0.VmotionEnabled)){
        Write-Host $Esxihost.Name " : " $vmk0.Name " : " $vmk0.IP " : MGMT traffic only" -BackgroundColor DarkGreen -ForegroundColor Green
    } else {
        Write-Host $Esxihost.name " : Config issue with vmk0. Should be enabled for mgmt traffic only. Please check this" -BackgroundColor DarkRed -ForegroundColor Red
    }

    # Check VMK1 is enabled for vMotion only and not MGMT
    if (!($vmk1.ManagementTrafficEnabled) -AND $vmk1.VmotionEnabled){
        Write-Host $Esxihost.Name " : " $vmk1.Name " : " $vmk1.IP " : vMotion traffic only" -BackgroundColor DarkGreen -ForegroundColor Green
    } else {
        Write-Host $Esxihost.name " : Config issue with vmk1. Should be enabled for vmotion traffic only. Please check this" -BackgroundColor DarkRed -ForegroundColor Red
    }

}



###################################
# Check the cluster has 4 uplinks #
###################################
Write-Host "Checking if $Cluster has supported number of UPLINKS" -BackgroundColor Yellow -ForegroundColor Blue 
    
foreach ($Esxihost in $Esxihosts) {
   $numNics = $Esxihost | get-VMHostNetworkAdapter -Physical
   if ($numNics.count -ne "4"){
       Write-Host $Esxihost "has less than 4 physical NICs. Please check this host" -BackgroundColor DarkRed -ForegroundColor Red 
   } else {
       Write-Host $Esxihost "has 4 physical NICs" -BackgroundColor DarkGreen -ForegroundColor Green
   }
}

#########################
# Check all NICS are up #
#########################
Write-Host "Checking NICS on hosts in $cluster" -BackgroundColor Yellow -ForegroundColor Blue
     
foreach ($Esxihost in $Esxihosts) {  
    $Esxcli = Get-EsxCli -VMHost $Esxihost  
    $Esxihostview = Get-VMHost $EsxiHost | get-view  
    $NetworkSystem = $Esxihostview.Configmanager.Networksystem  
    $Networkview = Get-View $NetworkSystem  
          
    $VMnics = $Esxihost | get-vmhostnetworkadapter -Physical   #$_.NetworkInfo.Pnic
     
    Foreach ($VMnic in $VMnics){  
        $realInfo = $Networkview.QueryNetworkHint($VMnic)  
        $pNics = $esxcli.network.nic.list() | where-object {$vmnic.name -eq $_.name} | Select-Object Description, Link           
        $Description = $esxcli.network.nic.list()  

    if ($pNics.Link -eq "Up") {
        write-host $esxihost.name ":" "$VMnic" ":" ($pNics.Link) ":" ($vmnic.ExtensionData.LinkSpeed.SpeedMB) -BackgroundColor DarkGreen -ForegroundColor Green
    } elseif ($pNics.Link -eq "Down") {
        write-host $esxihost.name ":" "$VMnic" ":" ($pNics.Link) ":" ($vmnic.ExtensionData.LinkSpeed.SpeedMB) -BackgroundColor DarkRed -ForegroundColor Red
    }
   
    }   
 } 

############################################
# Check the cluster has dead storage paths #
############################################
Write-Host "Checking if $Cluster has any dead storage paths" -BackgroundColor Yellow -ForegroundColor Blue 

foreach ($Esxihost in $Esxihosts) {
    $deadPaths = $Esxihost | Get-scsilun | get-scsilunpath | where {$_.State -eq "Dead"}
    if ($deadPaths.count -ne "0"){
        Write-Host $Esxihost "has 1 or more dead storage paths, please investigate" -BackgroundColor DarkRed -ForegroundColor Red 
    } else {
       Write-Host $Esxihost "has no dead storage paths" -BackgroundColor DarkGreen -ForegroundColor Green
   }
}

#######################################
# Export a list of VMs on the cluster #
#######################################
# Write-Host "Exporting list of VMs running on $cluster" -BackgroundColor Yellow -ForegroundColor Blue

$objCluster | Get-VM | select Guest | Export-CSV ".\$changeNum\$cluster\$cluster-VMs.csv" 

if (Test-Path .\$changeNum\$cluster\$cluster-VMs.csv){ 
    Write-Host "Export complete" -BackgroundColor DarkGreen -ForegroundColor Green
}

# ######################################################################
# # Get SSH service status                                             #
# # policy should be on to stop/start with host - do a check for this. #
# ######################################################################
Write-Host "Checking SSH service status on $cluster" -BackgroundColor Yellow -ForegroundColor Blue

foreach ($Esxihost in $Esxihosts) {
    $sshStatus = $EsxiHost | Get-VMHostService | Where-OBject {$_.Key -EQ 'TSM-SSH'} | Select-Object -Property VMhost, Label, Policy, Running

    if ($sshStatus.Running -eq "True") {
        write-host $esxihost.name ":" $sshStatus.Label "is running" -BackgroundColor DarkGreen -ForegroundColor Green
    } elseif ($sshStatus.Running -eq "False") {
        write-host $esxihost.name ":" $sshStatus.Label "is stopped" -BackgroundColor DarkRed -ForegroundColor Red
    }

}

#######################################
# Check for VMs with MEM reservations #
#######################################
Write-Host "Checking for VMs with Memory Reservations on $cluster" -BackgroundColor Yellow -ForegroundColor Blue

$VMs = $objCluster | Get-VM | Where-Object {$_.ExtensionData.ResourceConfig.MemoryAllocation.Reservation -ne "0" }

if ([string]::IsNullOrEmpty($VMs) ){
    Write-Host "No VMs found with memory reservations" -BackgroundColor DarkGreen -ForegroundColor Green
}

ForEach ($VM in $VMs) { 
        Write-host $VM.Name "has a memory reservation of "$VM.ExtensionData.ResourceConfig.MemoryAllocation.Reservation -BackgroundColor DarkRed -ForegroundColor Red 
} 
  
#################################################
# Ping the VMs to check for connectivity issues #
#################################################
Write-Host "Checking VM connectivity on $cluster" -BackgroundColor Yellow -ForegroundColor Blue

$objPing = New-Object system.Net.NetworkInformation.Ping

$VMs = Get-VM -Location (get-cluster -Name $cluster) | Where-Object {$_.Powerstate -eq "PoweredOn"} | Sort -property Name
Foreach ($VM in $VMs) {
    Write-Host $VM.Name.PadRight(20) -nonewline
 
    Get guest's primary IP address
    $ip = (Get-VMGuest -VM $vm).IPAddress[0]
    if (!$ip) {
        Write-Host "NULL - Skipping test" -Background DarkYellow -ForegroundColor Yellow
        Continue
    }
    Write-Host $ip.PadRight(17) -nonewline
    if ($ip -eq '0.0.0.0') {
        Write-Host "Skipping" -Background DarkYellow -ForegroundColor Yellow
        Continue
    }
 
    [string]$res = $objPing.Send($ip).Status
    if ($res.CompareTo("Success")) {                    # Returns 1 if $res doesn't match "Success" !!
        Write-Host $res -BackgroundColor DarkRed -ForegroundColor Red
    } else {
        Write-Host $res -BackgroundColor DarkGreen -ForegroundColor Green
    }
}

##################################
# Check the cluster alarm status #
##################################
Write-Host "Checking Cluster Alarm status" -BackgroundColor Yellow -ForegroundColor Blue


if ($objCluster.ExtensionData.AlarmActionsEnabled){
    Write-Host $cluster alarms are enabled -BackgroundColor DarkGreen -ForegroundColor Green
} else {
    Write-Host $cluster alarms are disabled -BackgroundColor DarkRed -ForegroundColor Red

}

##################################
# Check the host alarm status    #
##################################
Write-Host "Checking Host Alarm status" -BackgroundColor Yellow -ForegroundColor Blue

foreach ($Esxihost in $Esxihosts){
    if ($Esxihost.extensiondata.AlarmActionsEnabled){
        Write-Host $Esxihost alarms are enabled -BackgroundColor DarkGreen -ForegroundColor Green
    } else {
        Write-Host $Esxihost alarms are disabled -BackgroundColor DarkRed -ForegroundColor Red
    }
}


#####################################################################################
# Record the HA/DRS settings and check current settings against saved if they exist #
#####################################################################################

# Populate an object with the DRS settings to work with.
$drsConfig = @()
$drsConfig = $objCluster.extensiondata.configuration.drsconfig

#$drsObject = New-Object PSObject
#$drsObject | Add-Member -MemberType NoteProperty -name Enabled -Value $drsConfig.Enabled
#$drsObject | Add-Member -MemberType NoteProperty -name EnableVmBehaviorOverrides -Value $drsConfig.EnableVmBehaviorOverrides
#$drsObject | Add-Member -MemberType NoteProperty -Name DefaultVmBehavior -Value $drsConfig.DefaultVmBehavior
#$drsObject | Add-Member -MemberType NoteProperty -Name VmotionRate -Value $drsConfig.VmotionRate
#$drsObject | Add-Member -MemberType NoteProperty -Name Option -Value $drsConfig.Option
#$drsObject | Add-Member -MemberType NoteProperty -Name DynamicType -Value $drsConfig.DynamicType
#$drsObject | Add-Member -MemberType NoteProperty -Name DynamicProperty -Value $drsConfig.DynamicProperty

# Populate an object with the HA settings to work with.
$haConfig = @()
$haConfig = $objCluster.extensiondata.configuration.dasconfig

$haObject = new-object PSObject
$haObject | Add-Member -MemberType NoteProperty -name Enabled -Value $haConfig.Enabled
$haObject | Add-Member -MemberType NoteProperty -name VmMonitoring -Value $haConfig.VmMonitoring
$haObject | Add-Member -MemberType NoteProperty -Name HostMonitoring -Value $haConfig.HostMonitoring
$haObject | Add-Member -MemberType NoteProperty -Name FailoverLevel -Value $haConfig.FailoverLevel
$haObject | Add-Member -MemberType NoteProperty -Name AdmissionControlPolicyFailoverHost -Value $haConfig.AdmissionControlPolicy.FailoverHosts.Value
$haObject | Add-Member -MemberType NoteProperty -Name AdmissionControlPolicyCpuFailoverResourcesPercent -Value $haConfig.AdmissionControlPolicy.CpuFailoverResourcesPercent
$haObject | Add-Member -MemberType NoteProperty -Name AdmissionControlPolicyMemoryFailoverResourcesPercent -Value $haConfig.AdmissionControlPolicy.MemoryFailoverResourcesPercent
$haObject | Add-Member -MemberType NoteProperty -Name AdmissionControlEnabled -Value $haConfig.AdmissionControlEnabled
$haObject | Add-Member -MemberType NoteProperty -Name DefaultVmSettingsRestartPriority -Value $haConfig.DefaultVmSettings.RestartPriority
$haObject | Add-Member -MemberType NoteProperty -Name DefaultVmSettingsIsolationResponse -Value $haConfig.DefaultVmSettings.IsolationResponse
$haObject | Add-Member -MemberType NoteProperty -Name DefaultVmSettingsVmToolsMonitoringSettingsEnabled -Value $haConfig.DefaultVmSettings.VmToolsMonitoringSettings.Enabled
$haObject | Add-Member -MemberType NoteProperty -Name DefaultVmSettingsVmToolsMonitoringSettingsVmMonitoring -Value $haConfig.DefaultVmSettings.VmToolsMonitoringSettings.VmMonitoring
$haObject | Add-Member -MemberType NoteProperty -Name DefaultVmSettingsVmToolsMonitoringSettingsClusterSettings -Value $haConfig.DefaultVmSettings.VmToolsMonitoringSettings.ClusterSettings
$haObject | Add-Member -MemberType NoteProperty -Name DefaultVmSettingsVmToolsMonitoringSettingsFailureInterval -Value $haConfig.DefaultVmSettings.VmToolsMonitoringSettings.FailureInterval
$haObject | Add-Member -MemberType NoteProperty -Name DefaultVmSettingsVmToolsMonitoringSettingsMinUpTime -Value $haConfig.DefaultVmSettings.VmToolsMonitoringSettings.MinUpTime
$haObject | Add-Member -MemberType NoteProperty -Name DefaultVmSettingsVmToolsMonitoringSettingsMaxFailures -Value $haConfig.DefaultVmSettings.VmToolsMonitoringSettings.MaxFailures
$haObject | Add-Member -MemberType NoteProperty -Name DefaultVmSettingsVmToolsMonitoringSettingsMaxFailureWindow -Value $haConfig.DefaultVmSettings.VmToolsMonitoringSettings.MaxFailureWindow
$haObject | Add-Member -MemberType NoteProperty -Name Option -Value $haConfig.Option.Value
$haObject | Add-Member -MemberType NoteProperty -Name HeartbeatDatastore -Value $haConfig.HeartbeatDatastore
$haObject | Add-Member -MemberType NoteProperty -Name HBDatastoreCandidatePolicy -Value $haConfig.HBDatastoreCandidatePolicy
$haObject | Add-Member -MemberType NoteProperty -Name DynamicType -Value $haConfig.DynamicType
$haObject | Add-Member -MemberType NoteProperty -Name DynamicProperty -Value $haConfig.DynamicProperty

# Check if there is already a file with the DRS settings in.
if (Test-Path .\$changeNum\$cluster\$cluster-DRS-Settings.xml){
    Write-Host "Checking Saved DRS settings against current settings" -BackgroundColor Yellow -ForegroundColor Blue
       
    $savedDrsConfig = Import-CLIXML ".\$changeNum\$cluster\$cluster-DRS-Settings.xml"
    
    $properties = $savedDrsConfig | Get-Member -MemberType Properties | Select-Object -ExpandProperty Name
    
    foreach($property in $properties){
        
        If ($savedDrsConfig.$property -eq $drsConfig.$property){
            Write-host "MATCH:"$property "settings unchanged" -BackgroundColor DarkGreen -ForegroundColor Green
        } else {
            Write-host "ERROR:" $property "setting has changed." -BackgroundColor DarkRed -ForegroundColor Red
            write-host "$property was"$savedDrsConfig.$property "it is currently $($drsConfig.$property ). Please correct" -BackgroundColor DarkRed -ForegroundColor Red
        }
    }
} else {
    # Record DRS Config to a CSV file.
    Write-Host "No Saved settings found for DRS - Saving..." -BackgroundColor Yellow -ForegroundColor Blue
    $drsConfig | Export-CLIXML ".\$changeNum\$cluster\$cluster-DRS-Settings.xml" 
}

# Check if there is already a file with the HA settings in.
if (Test-Path .\$changeNum\$cluster\$cluster-HA-Settings.xml){
    Write-Host "Checking Saved HA settings against current settings" -BackgroundColor Yellow -ForegroundColor Blue
       
    $savedHAConfig = Import-CLIXML ".\$changeNum\$cluster\$cluster-HA-Settings.xml"
    
    $properties = $savedHAConfig | Get-Member -MemberType Properties | Select-Object -ExpandProperty Name
    
    foreach($property in $properties){
       # write-host "saved -" $savedHAConfig.$property
        #write-host "current -" $haConfig.$property
        If ($savedHAConfig.$property -eq $haObject.$property){
            Write-host "MATCH:"$property "settings unchanged" -BackgroundColor DarkGreen -ForegroundColor Green
        } else {
            Write-host "ERROR:" $property "setting has changed" -BackgroundColor DarkRed -ForegroundColor Red
            write-host "$property was"$savedHAConfig.$property "it is currently $($haObject.$property). Please correct" -BackgroundColor DarkRed -ForegroundColor Red
        }
    }

} else {
    # Record HA Config to a CSV file.
    Write-Host "No Saved settings found for HA - Saving..." -BackgroundColor Yellow -ForegroundColor Blue
    $haObject = new-object PSObject
    $haObject | Add-Member -MemberType NoteProperty -name Enabled -Value $haConfig.Enabled
    $haObject | Add-Member -MemberType NoteProperty -name VmMonitoring -Value $haConfig.VmMonitoring
    $haObject | Add-Member -MemberType NoteProperty -Name HostMonitoring -Value $haConfig.HostMonitoring
    $haObject | Add-Member -MemberType NoteProperty -Name FailoverLevel -Value $haConfig.FailoverLevel
    $haObject | Add-Member -MemberType NoteProperty -Name AdmissionControlPolicyFailoverHost -Value $haConfig.AdmissionControlPolicy.FailoverHosts.Value
    $haObject | Add-Member -MemberType NoteProperty -Name AdmissionControlPolicyCpuFailoverResourcesPercent -Value $haConfig.AdmissionControlPolicy.CpuFailoverResourcesPercent
    $haObject | Add-Member -MemberType NoteProperty -Name AdmissionControlPolicyMemoryFailoverResourcesPercent -Value $haConfig.AdmissionControlPolicy.MemoryFailoverResourcesPercent
    $haObject | Add-Member -MemberType NoteProperty -Name AdmissionControlEnabled -Value $haConfig.AdmissionControlEnabled
    $haObject | Add-Member -MemberType NoteProperty -Name DefaultVmSettingsRestartPriority -Value $haConfig.DefaultVmSettings.RestartPriority
    $haObject | Add-Member -MemberType NoteProperty -Name DefaultVmSettingsIsolationResponse -Value $haConfig.DefaultVmSettings.IsolationResponse
    $haObject | Add-Member -MemberType NoteProperty -Name DefaultVmSettingsVmToolsMonitoringSettingsEnabled -Value $haConfig.DefaultVmSettings.VmToolsMonitoringSettings.Enabled
    $haObject | Add-Member -MemberType NoteProperty -Name DefaultVmSettingsVmToolsMonitoringSettingsVmMonitoring -Value $haConfig.DefaultVmSettings.VmToolsMonitoringSettings.VmMonitoring
    $haObject | Add-Member -MemberType NoteProperty -Name DefaultVmSettingsVmToolsMonitoringSettingsClusterSettings -Value $haConfig.DefaultVmSettings.VmToolsMonitoringSettings.ClusterSettings
    $haObject | Add-Member -MemberType NoteProperty -Name DefaultVmSettingsVmToolsMonitoringSettingsFailureInterval -Value $haConfig.DefaultVmSettings.VmToolsMonitoringSettings.FailureInterval
    $haObject | Add-Member -MemberType NoteProperty -Name DefaultVmSettingsVmToolsMonitoringSettingsMinUpTime -Value $haConfig.DefaultVmSettings.VmToolsMonitoringSettings.MinUpTime
    $haObject | Add-Member -MemberType NoteProperty -Name DefaultVmSettingsVmToolsMonitoringSettingsMaxFailures -Value $haConfig.DefaultVmSettings.VmToolsMonitoringSettings.MaxFailures
    $haObject | Add-Member -MemberType NoteProperty -Name DefaultVmSettingsVmToolsMonitoringSettingsMaxFailureWindow -Value $haConfig.DefaultVmSettings.VmToolsMonitoringSettings.MaxFailureWindow
    $haObject | Add-Member -MemberType NoteProperty -Name Option -Value $haConfig.Option.Value
    $haObject | Add-Member -MemberType NoteProperty -Name HeartbeatDatastore -Value $haConfig.HeartbeatDatastore
    $haObject | Add-Member -MemberType NoteProperty -Name HBDatastoreCandidatePolicy -Value $haConfig.HBDatastoreCandidatePolicy
    $haObject | Add-Member -MemberType NoteProperty -Name DynamicType -Value $haConfig.DynamicType
    $haObject | Add-Member -MemberType NoteProperty -Name DynamicProperty -Value $haConfig.DynamicProperty
    $haObject | Export-CLIXML ".\$changeNum\$cluster\$cluster-HA-Settings.xml" 
}

##########################################################
# Pre-checks complete, disconnect and then stop logging  #
##########################################################

Disconnect-VIserver * -confirm:$false  
Stop-Transcript

# Fix up the file formatting of the log file. Write-Host doesn't include proper line endings.
$fixFileFormatting = Get-Content ".\$changeNum\$cluster\$filename.txt"
$fixFileFormatting > ".\$changeNum\$cluster\$filename.log"
Remove-Item ".\$changeNum\$cluster\$filename.txt"