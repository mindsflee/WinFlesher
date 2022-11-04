function WFL-exploit-T1555.003 {
    write-host
    Get-Childitem -Path C:\inetpub\ -Include web.config -File -Recurse -ErrorAction SilentlyContinue




} function WFL-check-T1555.003 {
    write-host
    write-host "Check function not provided for this module, please execute exploit function  (Ex: WFL-exploit-T1574.010)" -ForegroundColor Red
    write-host
} function WFL-info-T1555.003 {
    Write-Host  
    Write-Host "            Adversaries may acquire credentials from web browsers by reading
    files specific to the target browser. Web browsers commonly save credentials 
    such as website usernames and passwords so that they do not need to be 
    entered manually in the future. Web browsers typically store the credentials
    in an encrypted format within a credential store; however, methods exist to extract 
    plaintext credentials from web browsers."
    Write-Host 
} 
             




             

             
             

