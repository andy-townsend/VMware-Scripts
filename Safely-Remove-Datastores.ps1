<#
  .AUTHOR
  Andy Townsend - andy@alphatangoconsultants.com

  .SYNOPSIS
  This script will automate the process of unmounting & deleting datastores based on CSV file of input. Operations will only happen if the necessary pre-req checks are passed

  .DESCRIPTION
  The script will perform a number of checks before performing any unmount operations to ensure it is successful. The script will also reconfigure DS Heartbeat configuration as necessary. 

  The pre-requisites that this script checks are as follows. These are all things that could prevent a datastore from being unmounted.
  - Ensure there are no VMs in the datastore
  - Checks SIOC is disabled on the datastore. 
  - Checks if the datastore is being used for HA heartbeats
  - Checks if the datastore is part of a datastore cluster
  - Checks if the datastore is being used as a scratch partition
  - Checks to see if VDS config has been written to the datastore. If it has and there are no VMs on the datastore then its safe to delete the files. These files are only necessary when VMs are restarted by HA

  If any of the pre-reqs fail, it will attempt to fix them. 
  
  If SIOC is enabled, it will disable it. 
  If the DS is being used for HA heartbeats, it will set the preferred datastores to be any DS with 3PAR in the name.
  If there is a .dvsData folder, and there are no VMs on the datastore, it will remove this folder as its no longer needed.

  The script requires 3 inputs, the vCenter and Cluster Hostnames as well as the path to the dsInputCSV. An example of this file is below in the .NOTES section

  .EXAMPLE
  .\storage-reclaims.ps1 -vCenter vcenter.com -cluster myCluster -dsInputCSV .\myCluster-datastores.csv

  .NOTES

  dsInputCSV requires a CSV file with the headers Host, Datastore

#>
param (
    [Parameter(Mandatory=$true)][String] $vCenter,
    [Parameter(Mandatory=$true)][String] $cluster,
    [Parameter(Mandatory=$true)][String] $dsInputCSV
)

#Import DatastoreFunctions.ps1 credit goes here http://blogs.vmware.com/vsphere/2012/01/automating-datastore-storage-device-detachment-in-vsphere-5.html
try { 
    Import-Module .\DatastoreFunctions.psm1 -DisableNameChecking -ErrorAction Stop 2>&1 
}
catch [Exception] { 
	Write-Host $("Failed to load module DatastoreFunctions - Reason: " + $($_.Exception.Message)) -foreground red; 
	exit 
}

# Ask for some credentials & stored in a credential object
$userName = "$env:USERDOMAIN\$env:USERNAME"
$passwd = Read-Host ("Enter Password for " + $userName) -AsSecureString:$true
$cred = New-Object System.Management.Automation.PSCredential -ArgumentList $userName,$passwd

# Generate a filename including date/time and cluster name.
$now=Get-Date -Format "yyyyMMdd_HHmmss"
$filename = "$cluster-storage-reclaim-$now"

# Create a directory to contain the output for the cluster. Start-Transcript will fail to start if there isn't a folder to write into.
if (!(Test-Path ".\$cluster")){
    New-Item -ItemType Directory -Path ".\$cluster" | Out-Null
}

# Make sure transcript isn't running already from a previous failed run of the script.
try{
    Stop-Transcript | Out-Null
} catch [System.InvalidOperationException] {}

# Start transcript to record script output.
Start-Transcript -Path ".\$cluster\$filename.txt"

#Connect to vCenter
Try {
    Connect-VIServer -Server $vCenter -Credential $cred | Out-Null 
}
Catch {
    Throw "Error Connecting to $Vcenter, Please check $Vcenter name AND/OR credentials"
}

Write-Host "Importing CSV of Datastores to unmount" -BackgroundColor Yellow -ForegroundColor Blue
$csvInput = Import-CSV $dsInputCSV

# Get a cluster object to work with later in the script
$objCluster = get-cluster $cluster

# Get the datastores in use for HA heartbeats in the cluster.
$hbDatastores = @()
$hbDatastores = $objCluster.ExtensionData.RetrieveDasAdvancedRuntimeInfo() | %{ $_.HeartbeatDatastoreInfo | %{(get-View -Id $_.Datastore).Name} }


######################################################
# Check if there are any active coredumps being used #
# Check every host in cluster                        #
######################################################
Write-Host "Checking $vmhost for active coredumps" -BackgroundColor Yellow -ForegroundColor Blue
$vmhosts = $objCluster | get-VMhost -state Connected 

foreach($vmhost in $vmhosts){ 
    
    $vmkDumpFile = (get-esxcli -vmhost $vmhost).system.coredump.file.list() | where {$_.Active -eq $true}
    $vmkDumpFilePath = $vmkDumpFile.Path

    if ($vmkDumpFile -eq $null){
        Write-Host "No active coredumps found on $vmhost" -BackgroundColor DarkGreen -ForegroundColor Green
    } else {
        Write-Host "Active coredumps found on $vmhost" -BackgroundColor DarkRed -ForegroundColor Red
        Write-Host "ACTION: Removing $vmkDumpFile from $vmhost" -BackgroundColor Gray -ForegroundColor Yellow
        (get-esxcli -vmhost $vmhost).system.coredump.file.remove($vmkDumpFilePath,$true)
    }
}

####################################################
# Start looping through each line in the CSV file. #
####################################################
foreach($item in $csvInput){

    $vmhost = get-vmhost -name $item.Host
    $vmhostDatastores = @()
    $vmhostDatastores = $vmhost | get-datastore |  Select Name
    $datastore = ($item.Datastore).Trim()

    if ($vmhostDatastores -match $datastore){
        $ds = $vmhost | get-datastore -name $datastore
    } else{
        write-host $datastore "is not found on $vmhost" -BackgroundColor DarkRed -ForegroundColor Red
        continue}
    

    $ds = $vmhost | get-datastore -name $datastore 

    # Find the UUID of the disk that's being used as the scratch location
    $scratchPartition = ($vmhost | get-AdvancedSetting -name "scratchConfig.configuredscratchlocation").Value
    
    Write-Host "Running Pre-Requisites on $ds on $vmhost" -BackgroundColor Yellow -ForegroundColor Blue
    $preReqsFailed = 0

    ###########################################################
    # Check the datastore doesn't have any VMs running in it. #
    ###########################################################

    if ($ds.ExtensionData.Vm.Count -ne 0) {
        Write-Host "ERROR: $ds contains VMs" -BackgroundColor DarkRed -ForegroundColor Red
        $noVMsInDS = $false
        $preReqsFailed = $preReqsFailed + 1
    } else { 
        Write-Host "PASS: $ds contains no VMs" -BackgroundColor DarkGreen -ForegroundColor Green 
        $noVMsInDS = $true
    }

    ###########################################
    # Check SIOC is disabled on the datastore #
    ###########################################
     
    if ($ds.StorageIOControlEnabled){
        Write-Host "FAIL: SIOC is enabled on $ds" -BackgroundColor DarkRed -ForegroundColor Red
        Write-Host "ACTION: Disabling SIOC on $ds" -BackgroundColor Gray -ForegroundColor Yellow
        $Error.Clear()
        try{
            set-datastore $ds -StorageIOControlEnabled $false -Confirm:$false | Out-Null
        } catch {"FAIL: Unable to disable SIOC on $ds"}
        if (!$Error){
            Write-Host "PASS: SIOC is disabled on $ds" -BackgroundColor DarkGreen -ForegroundColor Green
        }
    } else { Write-Host "PASS: SIOC is disabled on $ds" -BackgroundColor DarkGreen -ForegroundColor Green }

    ##################################################################################
    # Check if the datastore is in the array of datastores being used for heartbeats #
    ##################################################################################

    if ($hbDatastores -contains $ds){

        # Reconfigure the cluster to use any *3PAR* datastores for HA heartbeats
        $preferredDatastores = "*3PAR*"
        $dsMoRef = Get-Datastore -Name $preferredDatastores | %{$_.ExtensionData.MoRef}

        $spec = New-Object Vmware.Vim.ClusterConfigSpec
        $spec.dasConfig = New-Object Vmware.Vim.ClusterDasConfigInfo
        $spec.dasConfig.hBDatastoreCandidatePolicy = "allFeasibleDsWithUserPreference"
        $spec.dasConfig.heartbeatDatastore = $dsMoRef

        $Error.Clear()
        try{
            Write-Host "ACTION: Updating HA Heartbeat datastores on $objCluster " -BackgroundColor Gray -ForegroundColor Yellow
            $objCluster.ExtensionData.ReconfigureCluster($spec,$true)
        } catch {"FAIL: Unable to update preferred HA hearbeat datastores" }
        if (!$Error){
            Write-Host "PASS: HA heartbeat datastores updated, $ds no longer used" -BackgroundColor DarkGreen -ForegroundColor Green
        }
    } else { Write-Host "PASS: $ds is not being used for HA heartbeats" -BackgroundColor DarkGreen -ForegroundColor Green }


    ####################################################
    # Check if the datastore is in a Datastore Cluster #
    ####################################################

    $dsParent = get-view $ds.ExtensionData.Parent
    if ($dsParent -is [VMware.Vim.StoragePod]){
        Write-Host "FAIL: $ds is part of a Datastore Cluster" -BackgroundColor DarkRed -ForegroundColor Red
        $preReqsFailed = $preReqsFailed + 1
    } else { Write-Host "PASS: $ds is not in a Datastore Cluster" -BackgroundColor DarkGreen -ForegroundColor Green }

    ################################################################
    # Check if the datastore is being used for a scratch partition #
    ################################################################

    if ($scratchPartition -eq "/vmfs/volumes/$($ds.ExtensionData.Info.VMfs.UUID)" ){
        Write-Host "FAIL: $ds is being used as a scratch partition" -BackgroundColor DarkRed -ForegroundColor Red 
    } else { Write-Host "PASS: $ds is not being used as a scratch partition" -BackgroundColor DarkGreen -ForegroundColor Green }
    
    #######################################################################
    # Check if the datastore is being used to store any VDS configuration # 
    # If it does and $noVMsInDS is true then its safe to remove the file  #
    #######################################################################

    New-PSDrive -Location $ds -Name ds -PSProvider VimDatastore -Root '\' | Out-null
    $result = get-childitem -Path ds:\ | ?{$_.PSIsContainer} | Where {$_.Name -match '.dvsData'}
    
    if($result){
        if ($noVMsInDS){
            #There's no VMs in this datastore so safe to delete
            Write-Host "ACTION: Removing .dvsData folder from $ds" -BackgroundColor Gray -ForegroundColor Yellow
            Remove-Item -Path ds:\.dvsData -Recurse -ErrorAction Stop -ErrorVariable $errs
            if ($errs.Count -eq 0){
                Write-Host "PASS: .dvsData removed from $ds" -BackgroundColor DarkGreen -ForegroundColor Green 
            } else { write-host "FAIL: Unable to remove .dvsData found in $ds" -BackgroundColor DarkRed -ForegroundColor Red }
        }
    }else{
        write-host "PASS: no .dvsData found in $ds" -BackgroundColor DarkGreen -ForegroundColor Green 
    }

    Remove-PSDrive -Name ds -Confirm:$false

    #########################################################
    # Check results and see if we can unmount the datastore #
    #########################################################

    if ($preReqsFailed -eq 0){
        Write-Host "----Pre-Req Tests PASSED----" -BackgroundColor DarkGreen -ForegroundColor Green 
        
        #Unmount the Datastore from this host
        Write-Host "ACTION: Unmounting $ds from $vmhost" -BackgroundColor Gray -ForegroundColor Yellow

        get-datastore $ds | Unmount-Datastore -VMHost $vmhost -Confirm:$false -ErrorVariable $errs
        if ($errs.Count -eq 0){ 
            Write-Host "SUCCESS: $ds unmounted from $vmhost" -BackgroundColor DarkGreen -ForegroundColor Green 
        } else { 
            Write-Host "FAILED: $ds could not be unmounted from $vmhost" -BackgroundColor DarkRed -ForegroundColor Red 
            Exit 
        }

        # Remove Datastore 
        Write-Host "ACTION: Removing $ds from $vmhost" -BackgroundColor Gray -ForegroundColor Yellow
        Remove-Datastore -datastore $ds -VMhost $vmhost -Confirm:$false -ErrorVariable $errs
        if ($errs.Count -eq 0){ 
            Write-Host "SUCCESS: $ds removed from $cluster" -BackgroundColor DarkGreen -ForegroundColor Green 
        } else { 
            Write-Host "FAILED: $ds could not be removed from $cluster" -BackgroundColor DarkRed -ForegroundColor Red 
            Exit 
        }
        <#
        #Detach the LUN from this host
        Write-Host "ACTION: Detaching $ds from $vmhost" -BackgroundColor Gray -ForegroundColor Yellow

        Get-Datastore $ds | Detach-SCSILun -VMHost $vmhost -Confirm:$false  -ErrorVariable $errs
        if ($errs.Count -eq 0){ 
            Write-Host "SUCCESS: $ds unmounted from $vmhost" -BackgroundColor DarkGreen -ForegroundColor Green 
        } else { 
            Write-Host "FAILED: $ds could not be unmounted from $vmhost" -BackgroundColor DarkRed -ForegroundColor Red 
            Exit 
        }
        #>
    } else {
        Write-Host "$ds failed some of the pre-req checks, can't be unmounted at this time" -BackgroundColor DarkRed -ForegroundColor Red
    }

}
Disconnect-VIserver * -confirm:$false  
# Stop recording script output.
Stop-Transcript

# Fix up the file formatting of the log file. Write-Host doesn't include proper line endings.
$fixFileFormatting = Get-Content ".\$cluster\$filename.txt"
$fixFileFormatting > ".\$cluster\$filename.log"
Remove-Item ".\$cluster\$filename.txt"
