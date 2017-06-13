param( [string] $VISRV)
#$idleLimit = 10080 #This is 7 days in minutes
$idleLimit = 1 #This is 2 days in minutes
#$idleLimit = 2880 #This is 2 days in minutes
#$idleLimit = 1440 #This is 1 days in minutes


$SMTPSRV = "mailserver.com" # Set the SMTP Server address
$EmailFrom = "sender@sender.com" # Set the Email address to recieve from
$EmailTo = "receiver@receiver.com" # Set the Email address to send the email to

# Import the necessary VMware modules
Get-Module -Name VMWare* -ListAvailable | Import-Module

# Import list of usernames that should never be disconnected
$users = Import-csv ".\protected-users.csv"

function Send-SMTPmail($to, $from, $subject, $smtpserver, $body) {
	$mailer = new-object Net.Mail.SMTPclient($smtpserver)
	$msg = new-object Net.Mail.MailMessage($from,$to,$subject,$body)
	$msg.IsBodyHTML = $true
	$mailer.send($msg)
}

$VIServer = Connect-VIServer $VISRV 

If ($VIServer.IsConnected -ne $true){
	# Fix for scheduled tasks not running.
	$USER = $env:username
	$APPPATH = "C:\Documents and Settings\" + $USER + "\Application Data"

	#SET THE APPDATA ENVIRONMENT WHEN NEEDED
	if ($env:appdata -eq $null -or $env:appdata -eq 0)
	{
		$env:appdata = $APPPATH
	}

	$VIServer = Connect-VIServer $VISRV 
	If ($VIServer.IsConnected -ne $true){
		Write $VIServer
		send-SMTPmail -to $EmailTo -from $EmailFrom -subject "ERROR: $VISRV vCheck" -smtpserver $SMTPSRV -body "The Connect-VISERVER Cmdlet did not work, please check you VI Server."
		exit
	}
}
	
	$sessionMgr = Get-View $VIServer.ExtensionData.Client.ServiceContent.SessionManager

	$allSessions = @()
	$msg = @()
	$sessionMgr.SessionList | foreach {
		$session = New-Object -TypeName PSObject -Property @{
			Key = $_.Key
			UserName = $_.UserName
			LoginTime = ($_.LoginTime).ToLocalTime()
			LastActiveTime  = ($_.LastActiveTime).ToLocalTime()
		}
		
		$session | Add-Member -MemberType NoteProperty -Name IdleMinutes -Value ([Math]::Round(((Get-Date) - ($_.LastActiveTime).ToLocalTime()).TotalMinutes))
		$allSessions += $session
	}

	foreach ($session in $allSessions){
		if ($session.IdleMinutes -gt $idleLimit){
			# Check the username for the idle session
			# if its in the protected-users.csv then it should not be disconnected
			if ($users.Username -notcontains $session.UserName){
				$msg += "Disconnecting session for $($session.UserName) which has been idle for $($session.IdleMinutes) minutes<br/>"
				#$sessionMgr.TerminateSession($session.Key)			
			} else {$msg = "No Idle sessions found"}
		}
	}	

	send-SMTPmail -to $EmailTo -from $EmailFrom -subject "Disconnected vCenter Sessions - $($VISRV)" -smtpserver $SMTPSRV -body $msg 



