function WFL-exploit-T1552.002 {
   
    write-host
    write-host "Exploit function not provided for this module, please execute exploit function  (Ex: WFL-check-T1552.002)" -ForegroundColor Red
    write-host

} function WFL-check-T1552.002 {
    write-host
     

    reg.exe query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon" # Windows Autologin
 
    reg.exe query "HKLM\SYSTEM\Current\ControlSet\Services\SNMP" # SNMP parameters
    reg.exe query "HKCU\Software\SimonTatham\PuTTY\Sessions" # Putty clear text proxy credentials
    reg.exe query "HKCU\Software\ORL\WinVNC3\Password" # VNC credentials
    reg.exe query "HKEY_LOCAL_MACHINE\SOFTWARE\RealVNC\WinVNC4" /v password
    REG.exe QUERY HKLM /F "password" /t REG_SZ /S /K
    REG.exe QUERY HKCU /F "password" /t REG_SZ /S /K
    
} function WFL-info-T1552.002 {
    Write-Host  
    Write-Host "            Adversaries may search the Registry on compromised systems 
    for insecurely stored credentials. 
    The Windows Registry stores configuration information that
    can be used by the system or other programs. 
    Adversaries may query the Registry looking for credentials 
    and passwords that have been stored for use by other programs or services.
    Sometimes these credentials are used for automatic logons."
    Write-Host 
} 
             




             

             
             

