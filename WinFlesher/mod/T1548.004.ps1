function WFL-exploit-T1548.004 {
   
    write-host
    write-host "Exploit function not provided for this module, please execute exploit function  (Ex: WFL-check-T1552.002)" -ForegroundColor Red
    write-host

} function WFL-check-T1548.004 {
    write-host

  
    $exists_HKCU = Get-ItemProperty -Path HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer -Name "AlwaysInstallElevated" -ErrorAction SilentlyContinue
    
    If (($null -ne $exists_HKCU) -and ($exists_HKCU.Length -ne 0)) {
        write-host "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer - AlwaysInstallElevated exist! The system may be vulnerable!" -ForegroundColor Green
    }
    write-host "System does not seem Vulnerable - HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer - AlwaysInstallElevated doesn't exist." -ForegroundColor Red
    write-host
    $exists_HKLM = Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer -Name "AlwaysInstallElevated" -ErrorAction SilentlyContinue
    
    If (($null -ne $exists_HKLM) -and ($exists_HKLM.Length -ne 0)) {
        write-host "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer - AlwaysInstallElevated exist! The system may be vulnerable!" -ForegroundColor Green
    }
    write-host "System does not seem Vulnerable - HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer - AlwaysInstallElevated doesn't exist." -ForegroundColor Red
    write-host
    
    
}
    
function WFL-info-T1548.004 {
    Write-Host  
    Write-Host "            Adversaries may abuse AlwaysInstallElevated 
    to obtain admin privileges in order to install malicious software on victims and install 
    persistence mechanisms.This technique may be combined with Masquerading to trick the 
    user into granting escalated privileges to malicious code."
    Write-Host 
} 
             




             

             
             

