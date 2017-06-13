## Functions for managing datastores/SCSI LUNs on VMHosts.  Originally by William Lam, at http://blogs.vmware.com/vsphere/2012/01/automating-datastore-storage-device-detachment-in-vsphere-5.html (linking to https://communities.vmware.com/docs/DOC-18008).
## Updated Jun 2014, Matt Boren -- added things like Confirmation and ShouldProcess (-WhatIf) support, ability to act on datastores at a per-host level, not just at "all attached hosts" level, and updated nouns to correspond with the thing on which the function is acting (SCSI LUN on some, instead of datastore)

Function Get-DatastoreMountInfo {
<#           .Description
    Get Datastore mount info (like, is datastore mounted on given host, is SCSI LUN attached, so on)
#>
[CmdletBinding()]
Param (
    ## one or more datastore objects for which to get Mount info
    [Parameter(Mandatory=$true,ValueFromPipeline=$true)][VMware.VimAutomation.ViCore.Impl.V1.DatastoreManagement.VmfsDatastoreImpl[]]$Datastore
)
Begin {$arrHostsystemViewPropertiesToGet = "Name","ConfigManager.StorageSystem"; $arrStorageSystemViewPropertiesToGet = "SystemFile","StorageDeviceInfo.ScsiLun"}
Process {
    foreach ($dstThisOne in $Datastore) {
        ## if this is a VMFS datastore
        if ($dstThisOne.ExtensionData.info.Vmfs) {
            ## get the canonical names for all of the extents that comprise this datastore
            $arrDStoreExtentCanonicalNames = $dstThisOne.ExtensionData.Info.Vmfs.Extent | Foreach-Object {$_.DiskName}
            ## if there are any hosts associated with this datastore (though, there always should be)
            if ($dstThisOne.ExtensionData.Host) {
                foreach ($oDatastoreHostMount in $dstThisOne.ExtensionData.Host) {
                    ## get the HostSystem and StorageSystem Views
                    $viewThisHost = Get-View $oDatastoreHostMount.Key -Property $arrHostsystemViewPropertiesToGet
                    $viewStorageSys = Get-View $viewThisHost.ConfigManager.StorageSystem -Property $arrStorageSystemViewPropertiesToGet
                    foreach ($oScsiLun in $viewStorageSys.StorageDeviceInfo.ScsiLun) {
                        ## if this SCSI LUN is part of the storage that makes up this datastore (if its canonical name is in the array of extent canonical names)
                        if ($arrDStoreExtentCanonicalNames -contains $oScsiLun.canonicalName) {
                            New-Object -Type PSObject -Property @{
                                Datastore = $dstThisOne.Name
                                ExtentCanonicalName = $oScsiLun.canonicalName
                                VMHost = $viewThisHost.Name
                                Mounted = $oDatastoreHostMount.MountInfo.Mounted
                                ScsiLunState = Switch ($oScsiLun.operationalState[0]) {
                                            "ok" {"Attached"; break}
                                            "off" {"Detached"; break}
                                            default {$oScsiLun.operationalstate[0]}
                                        } ## end switch
                            } ## end new-object
                        } ## end if
                    } ## end foreach
                } ## end foreach
            } ## end if
        } ## end if
    } ## end foreach
} ## end proces
} ## end fn


Function Unmount-Datastore {
<#           .Description
    Unmount VMFS volume(s) from VMHost(s)
    .Example
    Get-Datastore myOldDatastore0 | Unmount-Datastore -VMHost (Get-VMHost myhost0.dom.com, myhost1.dom.com)
    Unmounts the VMFS volume myOldDatastore0 from specified VMHosts
    Get-Datastore myOldDatastore1 | Unmount-Datastore
    Unmounts the VMFS volume myOldDatastore1 from all VMHosts associated with the datastore
    .Outputs
    None
#>
[CmdletBinding(SupportsShouldProcess=$true,ConfirmImpact="High")]
Param (
    ## One or more datastore objects to whose VMFS volumes to unmount
    [Parameter(Mandatory=$true,ValueFromPipeline=$true)][VMware.VimAutomation.ViCore.Impl.V1.DatastoreManagement.VmfsDatastoreImpl[]]$Datastore,
    ## VMHost(s) on which to unmount a VMFS volume; if non specified, will unmount the volume on all VMHosts that have it mounted
    [Parameter(ParameterSetName="SelectedVMHosts")][VMware.VimAutomation.ViCore.Impl.V1.Inventory.VMHostImpl[]]$VMHost
)
Begin {$arrHostsystemViewPropertiesToGet = "Name","ConfigManager.StorageSystem"; $arrStorageSystemViewPropertiesToGet = "SystemFile"}
Process {
    ## for each of the datastores
    foreach ($dstThisOne in $Datastore) {
        ## if the datastore is actually mounted on any host
        if ($dstThisOne.ExtensionData.Host) {
            ## the MoRefs of the HostSystems upon which to act
            $arrMoRefsOfHostSystemsForUnmount = if ($PSCmdlet.ParameterSetName -eq "SelectedVMHosts") {$VMHost | Foreach-Object {$_.Id}} else {$dstThisOne.ExtensionData.Host | Foreach-Object {$_.Key}}
            ## get array of HostSystem Views from which to unmount datastore
            $arrViewsOfHostSystemsForUnmount = Get-View -Property $arrHostsystemViewPropertiesToGet -Id $arrMoRefsOfHostSystemsForUnmount

            foreach ($viewThisHost in $arrViewsOfHostSystemsForUnmount) {
                ## actually do the unmount (if not WhatIf)
                if ($PSCmdlet.ShouldProcess("VMHost '$($viewThisHost.Name)'", "Unmounting VMFS datastore '$($dstThisOne.Name)'")) {
                    $viewStorageSysThisHost = Get-View $viewThisHost.ConfigManager.StorageSystem -Property $arrStorageSystemViewPropertiesToGet
                    ## add try/catch here?  and, return something here?
                    $viewStorageSysThisHost.UnmountVmfsVolume($dstThisOne.ExtensionData.Info.vmfs.uuid)
                } ## end if
            } ## end foreach
        } ## end if
    } ## end foreach
} ## end process
} ## end fn


Function Mount-Datastore {
<#           .Description
    Mount VMFS volume(s) on VMHost(s)
    .Example
    Get-Datastore myOldDatastore1 | Mount-Datastore
    Mounts the VMFS volume myOldDatastore1 on all VMHosts associated with the datastore (where it is not already mounted)
    .Outputs
    None
#>
[CmdletBinding(SupportsShouldProcess=$true)]
Param (
    [Parameter(Mandatory=$true,ValueFromPipeline=$true)][VMware.VimAutomation.ViCore.Impl.V1.DatastoreManagement.VmfsDatastoreImpl[]]$Datastore
)
Begin {$arrHostsystemViewPropertiesToGet = "Name","ConfigManager.StorageSystem"; $arrStorageSystemViewPropertiesToGet = "SystemFile"}
Process {
    foreach ($dstThisOne in $Datastore) {
        ## if there are any hosts associated with this datastore (though, there always should be)
        if ($dstThisOne.ExtensionData.Host) {
            foreach ($oDatastoreHostMount in $dstThisOne.ExtensionData.Host) {
                $viewThisHost = Get-View $oDatastoreHostMount.Key -Property $arrHostsystemViewPropertiesToGet
                if (-not $oDatastoreHostMount.MountInfo.Mounted) {
                    if ($PSCmdlet.ShouldProcess("VMHost '$($viewThisHost.Name)'", "Mounting VMFS Datastore '$($dstThisOne.Name)'")) {
                        $viewStorageSysThisHost = Get-View $viewThisHost.ConfigManager.StorageSystem -Property $arrStorageSystemViewPropertiesToGet
                        $viewStorageSysThisHost.MountVmfsVolume($dstThisOne.ExtensionData.Info.vmfs.uuid);
                    } ## end if
                } ## end if
                else {Write-Verbose -Verbose "Datastore '$($dstThisOne.Name)' already mounted on VMHost '$($viewThisHost.Name)'"}
            } ## end foreach
        } ## end if
    } ## end foreach
} ## end process
} ## end fn


Function Detach-SCSILun {
<#           .Description
    Detach SCSI LUN(s) from VMHost(s).  If specifying host, needs to be a VMHost object (as returned from Get-VMHost).  This was done to avoid any "matched host with similar name pattern" problems that may occur if accepting host-by-name.
    .Example
    Get-Datastore myOldDatastore0 | Detach-SCSILun -VMHost (Get-VMHost myhost0.dom.com, myhost1.dom.com)
    Detaches the SCSI LUN associated with datastore myOldDatastore0 from specified VMHosts
    Get-Datastore myOldDatastore1 | Detach-SCSILun
    Detaches the SCSI LUN associated with datastore myOldDatastore1 from all VMHosts associated with the datastore
    .Outputs
    None
#>
[CmdletBinding(SupportsShouldProcess=$true,ConfirmImpact="High")]
Param (
    ## One or more datastore objects to whose SCSI LUN to detach
    [Parameter(Mandatory=$true,ValueFromPipeline=$true)][VMware.VimAutomation.ViCore.Impl.V1.DatastoreManagement.VmfsDatastoreImpl[]]$Datastore,
    ## VMHost(s) on which to detach the SCSI LUN; if non specified, will detach the SCSI LUN on all VMHosts that have it attached
    [Parameter(ParameterSetName="SelectedVMHosts")][VMware.VimAutomation.ViCore.Impl.V1.Inventory.VMHostImpl[]]$VMHost
)
Begin {$arrHostsystemViewPropertiesToGet = "Name","ConfigManager.StorageSystem"; $arrStorageSystemViewPropertiesToGet = "SystemFile","StorageDeviceInfo.ScsiLun"}
Process {
    foreach ($dstThisOne in $Datastore) {
        ## get the canonical names for all of the extents that comprise this datastore
        $arrDStoreExtentCanonicalNames = $dstThisOne.ExtensionData.Info.Vmfs.Extent | Foreach-Object {$_.DiskName}
        ## if there are any hosts associated with this datastore (though, there always should be)
        if ($dstThisOne.ExtensionData.Host) {
            ## the MoRefs of the HostSystems upon which to act
            $arrMoRefsOfHostSystemsForUnmount = if ($PSCmdlet.ParameterSetName -eq "SelectedVMHosts") {$VMHost | Foreach-Object {$_.Id}} else {$dstThisOne.ExtensionData.Host | Foreach-Object {$_.Key}}
            ## get array of HostSystem Views from which to unmount datastore
            $arrViewsOfHostSystemsForUnmount = Get-View -Property $arrHostsystemViewPropertiesToGet -Id $arrMoRefsOfHostSystemsForUnmount

            foreach ($viewThisHost in $arrViewsOfHostSystemsForUnmount) {
                ## get the StorageSystem View
                $viewStorageSysThisHost = Get-View $viewThisHost.ConfigManager.StorageSystem -Property $arrStorageSystemViewPropertiesToGet
                foreach ($oScsiLun in $viewStorageSysThisHost.StorageDeviceInfo.ScsiLun) {
                    ## if this SCSI LUN is part of the storage that makes up this datastore (if its canonical name is in the array of extent canonical names)
                    if ($arrDStoreExtentCanonicalNames -contains $oScsiLun.canonicalName) {
                        if ($PSCmdlet.ShouldProcess("VMHost '$($viewThisHost.Name)'", "Detach LUN '$($oScsiLun.CanonicalName)'")) {
                            $viewStorageSysThisHost.DetachScsiLun($oScsiLun.Uuid)
                        } ## end if
                    } ## end if
                } ## end foreach
            } ## end foreach
        } ## end if
    } ## end foreach
} ## end process
} ## end fn


Function Attach-SCSILun {
<#           .Description
    Attach SCSI LUN(s) to VMHost(s)
    .Example
    Get-Datastore myOldDatastore1 | Attach-SCSILun
    Attaches the SCSI LUN associated with datastore myOldDatastore1 to all VMHosts associated with the datastore
    .Outputs
    None
#>
[CmdletBinding(SupportsShouldProcess=$true)]
Param (
    ## One or more datastore objects to whose SCSI LUN to attach
    [Parameter(Mandatory=$true,ValueFromPipeline=$true)][VMware.VimAutomation.ViCore.Impl.V1.DatastoreManagement.VmfsDatastoreImpl[]]$Datastore
)
Begin {$arrHostsystemViewPropertiesToGet = "Name","ConfigManager.StorageSystem"; $arrStorageSystemViewPropertiesToGet = "SystemFile","StorageDeviceInfo.ScsiLun"}
Process {
    foreach ($dstThisOne in $Datastore) {
        $arrDStoreExtentCanonicalNames = $dstThisOne.ExtensionData.Info.Vmfs.Extent | Foreach-Object {$_.DiskName}
        ## if there are any hosts associated with this datastore (though, there always should be)
        if ($dstThisOne.ExtensionData.Host) {
            foreach ($oDatastoreHostMount in $dstThisOne.ExtensionData.Host) {
                ## get the HostSystem and StorageSystem Views
                $viewThisHost = Get-View $oDatastoreHostMount.Key -Property $arrHostsystemViewPropertiesToGet
                $viewStorageSysThisHost = Get-View $viewThisHost.ConfigManager.StorageSystem -Property $arrStorageSystemViewPropertiesToGet
                foreach ($oScsiLun in $viewStorageSysThisHost.StorageDeviceInfo.ScsiLun) {
                    ## if this SCSI LUN is part of the storage that makes up this datastore (if its canonical name is in the array of extent canonical names)
                    if ($arrDStoreExtentCanonicalNames -contains $oScsiLun.canonicalName) {
                        ## if this SCSI LUN is not already attached
                        if (-not ($oScsiLun.operationalState[0] -eq "ok")) {
                            if ($PSCmdlet.ShouldProcess("VMHost '$($viewThisHost.Name)'", "Attach LUN '$($oScsiLun.CanonicalName)'")) {
                                $viewStorageSysThisHost.AttachScsiLun($oScsiLun.Uuid)
                            } ## end if
                        } ## end if
                        else {Write-Verbose -Verbose "SCSI LUN '$($oScsiLun.canonicalName)' already attached on VMHost '$($viewThisHost.Name)'"}
                    } ## end if
                } ## end foreach
            } ## end foreach
        } ## end if
    } ## end foreach
} ## end process
} ## end fn
