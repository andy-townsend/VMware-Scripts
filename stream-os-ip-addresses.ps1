ForEach ($arg in $args) {
	$osHash = @{}
	Write-Host "##########################"
	Write-Host "Running for stream: " $arg
	
	$streamVMs = Get-VM -Name "stream$($arg)_*" | where { $_.PowerState -eq "PoweredOn" }
	
	ForEach ($vm in $streamVMs){
		$vmOS = (Get-VM $vm | Get-View).Summary.Config.GuestFullName
		
		if ($vmOS -notlike "*Windows*"){
			[string]$realOS = $vm | Invoke-VMScript -GuestUser root -GuestPassword 1w2wtL -ScriptText "if [ -e /etc/yellow-release ]; then cat /etc/yellow-release; else cat /etc/redhat-release; fi"
			$output = $vm | %{ $_.Name; ":"; $_.guest.IPAddress[0]; ":"; $realOS }
			$vmName = $vm | %{ $_.Name; }
			$osHash.Add($vmName, $realOS)
				
			#Write-Host "NIX-TYPE:" $realOS.gettype()
			Write-Host $output 
			$output -join ' ' | Out-File -filepath "stream$($arg)-vms-report-os-and-ips.csv" -append 
		}else{
			[string]$realOS = $vm | Invoke-VMScript -GuestUser administrator -GuestPassword 1w2wtL -ScriptText "wmic os get Caption | findstr /C:'Windows'"
			
			$output = $vm | %{ $_.Name; ":"; $_.guest.IPAddress[0]; ":"; $realOS}
			$vmName = $vm | %{ $_.Name; }
			$osHash.Add($vmName, $realOS)
					
			#Write-Host "WIN-TYPE:" $realOS.gettype()			
			Write-Host $output 
			$output -join ' ' | Out-File -filepath "stream$($arg)-vms-report-os-and-ips.csv" -append 
		}
		
	}
	Write-Host "###########OS TOTALS###############"
	$osReport = "OS Totals for Stream $($arg)" | Out-File -FilePath "cloud-os-types-for-stream$($arg).csv" -Append
	$osHash.Values | Group-Object | Select Count, Name | Sort-Object | Ft -autosize | Out-File -FilePath "cloud-os-types-for-stream$($arg).csv" -Append
	Write-Host "##########################"
}
