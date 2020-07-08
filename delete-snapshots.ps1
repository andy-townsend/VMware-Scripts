# Snapshot Reminder Email script based on - SnapReminder V1.0 By Virtu-Al 
# modified by Leon Scheltema  
# modified by Andy Townsend to delete old snapshots 
# 

# Please use the below variables to define your settings before use 
# 

if (-not (Get-PSSnapin VMware.VimAutomation.Core -ErrorAction SilentlyContinue)) 
{ 
  Add-PSSnapin VMware.VimAutomation.Core 
} 
 
$smtpServer = "X.X.X.X" 
$MailFrom = "snapshots@domain.com" 
$VC1 = "vc.domain.com" 
$default_mail_tgt = "vc-admin@domain.com" 

# Please define max. allowed age of VMWare snapshot in hours 
$Age = 24 
$snapshotAge = 3 
  

function Find-User ($username){ 
  if ($username -ne $null) 
   { 
      $usr = (($username.split("\"))[1]) 
      $root = [ADSI]"" 
      $filter = ("(&(objectCategory=user)(samAccountName=$Usr))") 
      $ds = new-object system.DirectoryServices.DirectorySearcher($root,$filter) 
      $ds.PageSize = 1000 
      $ds.FindOne()
   } 
} 

  

function Get-SnapshotTree{ 
    param($tree, $target) 
    $found = $null 

    foreach($elem in $tree){ 
        if($elem.Snapshot.Value -eq $target.Value){ 
            $found = $elem 
            continue 
        } 
    } 

    if($found -eq $null -and $elem.ChildSnapshotList -ne $null){ 
        $found = Get-SnapshotTree $elem.ChildSnapshotList $target 
    } 

    return $found 

} 

  

function Get-SnapshotExtra ($snap) 
{ 
    $guestName = $snap.VM   # The name of the guest 
    $tasknumber = 999       # Windowsize of the Task collector 

    $taskMgr = Get-View TaskManager 

    # Create hash table. Each entry is a create snapshot task 
    $report = @{} 

    $filter = New-Object VMware.Vim.TaskFilterSpec 
    $filter.Time = New-Object VMware.Vim.TaskFilterSpecByTime 
    $filter.Time.beginTime = (($snap.Created).AddSeconds(-600)) 
    $filter.Time.timeType = "startedTime" 
    $filter.State = "success" 
    $filter.Entity = New-Object VMware.Vim.TaskFilterSpecByEntity 
    $filter.Entity.recursion = "self" 
    $filter.Entity.entity = (Get-Vm -Name $snap.VM.Name).Extensiondata.MoRef  
    $collectionImpl = Get-View ($taskMgr.CreateCollectorForTasks($filter)) 

    $dummy = $collectionImpl.RewindCollector 
    $collection = $collectionImpl.ReadNextTasks($tasknumber) 
    while($collection -ne $null){ 
        $collection | where {$_.DescriptionId -eq "VirtualMachine.createSnapshot" -and $_.State -eq "success" -and $_.EntityName -eq $guestName} | %{ 
            $row = New-Object PsObject 
            $row | Add-Member -MemberType NoteProperty -Name User -Value $_.Reason.UserName 
            $vm = Get-View $_.Entity 
            $snapshot = Get-SnapshotTree $vm.Snapshot.RootSnapshotList $_.Result 
            if ( $snapshot -ne $null) 
            { 
                $key = $_.EntityName + "&" + ($snapshot.CreateTime.ToLocalTime().ToString()) 
                $report[$key] = $row 
            } 
        } 
        $collection = $collectionImpl.ReadNextTasks($tasknumber) 
    } 

    $collectionImpl.DestroyCollector() 

    # Get the guest's snapshots and add the user 
    $snapshotsExtra = $snap | % { 
        $key = $_.vm.Name + "&" + ($_.Created.ToLocalTime().ToString()) 
        if($report.ContainsKey($key)){ 
            $_ | Add-Member -MemberType NoteProperty -Name Creator -Value $report[$key].User 
            write-host $report[$key].User is creator of $key           
        } 
        $_ 
    } 
    $snapshotsExtra 
} 

 

Function deleteSnapshot ($snapshot) 
{ 
    Remove-snapshot -Snapshot $snapshot -RemoveChildren -Confirm:$false  
} 


# Function SnapMail ($Mailto, $snapshot, $usrName) 
# { 
    # $msg = new-object Net.Mail.MailMessage 
    # $smtp = new-object Net.Mail.SmtpClient($smtpServer) 
    # $msg.From = $MailFrom 
    # if ( $MailTo -ne "" -and $MailTo -ne $null) 
    # { 
        # Write "Would be adding $Mailto to the recipients list" 
        # $msg.To.Add($Mailto) 
        # $msg.Subject = "Snapshot Reminder" 
    # } 
    # else 
    # { 
        # if ( $usrName -ne "" -and $usrName -ne $null) 
        # { 
            # $msg.Subject = "Snapshot Reminder for $usrName" 
        # } 
        # else 
        # { 
            # $msg.Subject = "Snapshot Reminder for Snapshot with unknown owner" 
        # }         
        # $msg.To.Add($default_mail_tgt) 
    # } 
# if ( $snapshot.Created -lt ((Get-Date).AddDays(-$snapshotAge)) ) 
# { 
# $deleteSnapshot = $snapshot.Name + " on VM " + $snapshot.VM + " will be deleted as is greater than 24 hours old." 
# } 

# $MailText = @" 
# This is a reminder that you have a snapshot active on $($snapshot.VM) which was taken on $($snapshot.Created). 
# Name: $($snapshot.Name) 
# Description: $($snapshot.Description) 
 
# Please delete this snapshot as soon as it is no longer required. 


# Snapshots will be automatically deleted after 24 hours. 

# If you believe you have recieved this email in error, please contact DL-CPE-AppSupport-Release-QATS 

# $($deleteSnapshot) 

# "@   

    # $msg.Body = $MailText 
    # $smtp.Send($msg) 
# } 

Connect-VIServer $VC1 

# -------------- Summary  File Setup----------------------------- 


# Output File 
$strOutFile = "C:\temp\snapshot_report.htm" 

# HTML/CSS style for the output file 
$head = "<style>" 
$head = $head + "BODY{background-color:white;}" 
$head = $head + "TABLE{border-width: 1px;border-style: solid;border-color: black;border-collapse: collapse;}" 
$head = $head + "TH{border-width: 1px;padding: 0px;border-style: solid;border-color: black;background-color:#018AC0}" 
$head = $head + "TD{border-width: 1px;padding-left: 10px;padding-right: 10px;border-style: solid;border-color: black;background-color:e5e5e5}" 
$head = $head + "</style>" 

$strSubject = "Deleted Snapshots - " + (get-date -DisplayHint date) 
$strBody = "Attached is the list of Snapshots and their Creators" 
$strMail = "<H2><u>" + $strSubject + "</u></H2>" 

# -------------- Logic ----------------------------- 
$myCol = @() 

foreach ($snap in ( Get-VM -name "vm-Name" | Get-Snapshot | Where {$_.Created -lt ((Get-Date).AddHours(-$Age))})) 
{ 
    $SnapshotInfo = Get-SnapshotExtra $snap 
    $usr = Find-User $SnapshotInfo.Creator 
    $mailto = $usr.Properties.mail 
    #SnapMail $mailto $SnapshotInfo $usr.Properties.displayname 

    $myObj = "" | Select-Object VM, Snapshot, Created, CreatedBy, EmailedTo, Description, Deleted 
    $myObj.VM = $snap.vm.name 
    $myObj.Snapshot = $snap.name 
    $myObj.Created = $snap.created 

    if ( $usr -ne $null) 
    { 
        [String]$a = $usr.Properties.name 
        $myObj.CreatedBy = $a 
    } 
    else 
    { 
        $myObj.CreatedBy = "Unknown Creator" 
    } 

    if ( $mailto -eq "" -or $mailto -eq $null) 
    { 
        $myObj.EmailedTo = $default_mail_tgt 
    } 
    else 
    { 
        [String]$a = $usr.Properties.mail 
        $myObj.EmailedTo = $a 
    } 

     

    if ( $myObj.Created -lt ((Get-Date).AddDays(-$snapshotAge))) 
    {
        #$deleteSnapshot = $myObj.Snapshot + " on VM " + $myObj.VM + " will be deleted" 
        deleteSnapshot($snap) 
    } 
        $myObj.Description = $snap.Description 
        $myObj.Deleted = (Get-Date) 
        $myCol += $myObj 
} 

# Write the output to an HTML file 
$myCol | Sort-Object VM | ConvertTo-HTML -Head $head -Body $strMail | Out-File $strOutFile 
$strFrom = $MailFrom 
$strTo = $default_mail_tgt 

# Mail the output file 
$msg = new-object Net.Mail.MailMessage 
$att = new-object Net.Mail.Attachment($strOutFile) 
$smtp = new-object Net.Mail.SmtpClient($smtpServer) 

$msg.From = $strFrom 
$msg.To.Add($strTo) 
$msg.Subject = $strSubject 
$msg.IsBodyHtml = 1 
$msg.Body = Get-Content $strOutFile 
$msg.Attachments.Add($att) 
$msg.Headers.Add("message-id", "<3BD50098E401463AA228377848493927-1>") # Adding a Bell Icon for Outlook users 

$smtp.Send($msg) 
$msg.Dispose() 

Disconnect-VIServer $VC1 -confirm:0 
