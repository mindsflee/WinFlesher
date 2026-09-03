Register-WFLModule `
    -Name "SEC-WSUSInsecureTransport" `
    -Category "Network Security" `
    -Type "Check" `
    -MITRE "T1184" `
    -Tactic "Execution / Privilege Escalation" `
    -Impact "CRITICAL INFRASTRUCTURE COMPROMISE VIA WSUS CODE INJECTION" `
    -Description "Identifies WSUS servers operating over unencrypted HTTP or misconfigured client targeting policies, exposing endpoints to Man-in-the-Middle and arbitrary SYSTEM code execution." `
    -Remediation @{
        Module        = 'SEC-WSUSInsecureTransport'
        Category      = 'Infrastructure Security / Transport Layer'
        Type          = 'Specific'
        Description   = 'Enforce HTTPS (SSL/TLS) on the WSUS website, configure SCCM/GPO to require SSL certificate validation, and restrict administrative access to authorized security personnel.'
        Impact        = 'High. Endpoints must be re-configured to trust the WSUS SSL certificate to prevent update synchronization failures.'
        VariableGuide = 'Verify the WSUS server FQDN and ensure an appropriate computer/server SSL certificate is bound to IIS port 8531.'
        Code          = @'
# Example of mandatory SSL configuration on WSUS via wsusutil
$WsusServer = "WSUS01.contoso.local"
# Using HTTPS moves the standard port from 8530 (HTTP) to 8531 (HTTPS)
& "C:\Program Files\Update Services\Tools\wsusutil.exe" configuressl $WsusServer
'@
    } -Run {

        try {

            $Results = @()
            $Errors = @()
            $WsusServers = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)

           
            if (
                $Global:WinFlesher.Context.ActiveDirectory.Available -and
                (Get-Command Get-ADComputer -ErrorAction SilentlyContinue)
            ) {
                try {
                    $AdWsus = Get-ADComputer -Filter "Name -like '*WSUS*'" -Properties DnsHostName -ErrorAction Stop
                    foreach ($computer in $AdWsus) {
                        if ($computer.DnsHostName) {
                            [void]$WsusServers.Add($computer.DnsHostName)
                        }
                    }
                }
                catch {
                    $Errors += [PSCustomObject]@{
                        Target = "ActiveDirectory"
                        Stage  = "WSUSServerDiscovery"
                        Error  = $_.Exception.Message
                    }
                }
            }

            try {
                $WUServerReg = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "WUServer" -ErrorAction SilentlyContinue
                if ($WUServerReg -and $WUServerReg.WUServer) {
                   
                    $uri = [System.Uri]$WUServerReg.WUServer
                    if ($uri -and $uri.Host) {
                        [void]$WsusServers.Add($uri.Host)
                    }
                }
            }
            catch {}

            
            if ($WsusServers.Count -eq 0) {
                [void]$WsusServers.Add($env:COMPUTERNAME)
            }

            foreach ($Server in $WsusServers) {

                if ([string]::IsNullOrEmpty($Server)) { continue }

                try {
                   
                    $WsusConfig = Invoke-Command -ComputerName $Server -ScriptBlock {
                        $Info = [PSCustomObject]@{
                            HttpPort    = $null
                            HttpsPort   = $null
                            UseSSL      = $false
                            IsInstalled = $false
                        }

                        $WsusReg = Get-ItemProperty -Path "HKLM:\Software\Microsoft\Update Services\Server\Setup" -ErrorAction SilentlyContinue
                        if ($WsusReg) {
                            $Info.IsInstalled = $true
                            $Info.HttpPort = $WsusReg.PortNumber
                            $Info.HttpsPort = $WsusReg.SslPortNumber
                        }

                       
                        Import-Module WebAdministration -ErrorAction SilentlyContinue
                        $WsusBinding = Get-WebBinding -Name "WSUS Administration" -ErrorAction SilentlyContinue
                        foreach ($Binding in $WsusBinding) {
                            if ($Binding.protocol -eq "https") {
                                $Info.UseSSL = $true
                            }
                        }
                        return $Info
                    } -ErrorAction Stop

                    if (-not $WsusConfig.IsInstalled) { continue }

                    $IsVulnerable = $false
                    $Severity = "Info"
                    $Exploitability = "Informational"
                    $RiskReasons = @()

                   
                    if (-not $WsusConfig.UseSSL) {
                        $IsVulnerable = $true
                        $Severity = "Critical"
                        $Exploitability = "High"
                        $RiskReasons += "WSUS is configured to serve updates over unencrypted HTTP (Port $($WsusConfig.HttpPort)), allowing local network attackers to perform Man-in-the-Middle attacks and inject arbitrary payloads executed as NT AUTHORITY\SYSTEM."
                    } else {
                        $RiskReasons += "WSUS communication is secured via HTTPS/SSL."
                    }

                    $Results += [PSCustomObject]@{
                        ServerName     = [string]$Server
                        HttpPort       = $WsusConfig.HttpPort
                        HttpsPort      = $WsusConfig.HttpsPort
                        UseSSL         = $WsusConfig.UseSSL
                        IsVulnerable   = $IsVulnerable
                        Severity       = $Severity
                        Exploitability = $Exploitability
                        RiskReason     = ($RiskReasons -join "; ")
                    }

                }
                catch {
                    $Errors += [PSCustomObject]@{
                        Target = [string]$Server
                        Stage  = "WSUSInspection"
                        Error  = $_.Exception.Message
                    }
                }
            }

            Add-WFLDetail -Name "SEC-WSUSInsecureTransport" -Data $Results
            Add-WFLDetail -Name "SEC-WSUSInsecureTransport-Errors" -Data $Errors

            $VulnerableCount = @($Results | Where-Object { $_.IsVulnerable }).Count

            if ($VulnerableCount -gt 0) {
                Add-WFLFinding `
                    -Title "WSUS servers exposed to unencrypted transport and code injection" `
                    -Severity "Critical" `
                    -Category "Network Security" `
                    -MITRE "T1184" `
                    -Tactic "Execution / Privilege Escalation" `
                    -Source "SEC-WSUSInsecureTransport" `
                    -Evidence "WsusServersChecked=$($Results.Count); VulnerableServers=$VulnerableCount; Risk=HTTP Plaintext Update Channel Active" `
                    -Recommendation "Immediately enforce SSL/TLS on all WSUS servers using wsusutil and ensure group policies mandate HTTPS communication for client agent updates to prevent MITRE T1184 exploits."
            } else {
                Add-WFLFinding `
                    -Title "WSUS transport security check passed" `
                    -Severity "Info" `
                    -Category "Network Security" `
                    -MITRE "T1184" `
                    -Tactic "Execution / Privilege Escalation" `
                    -Source "SEC-WSUSInsecureTransport" `
                    -Evidence "WsusServersChecked=$($Results.Count); InsecureTransportFound=0" `
                    -Recommendation "Maintain proper certificate lifecycle management for WSUS endpoints."
            }

        }
        catch {
            Add-WFLFinding `
                -Title "WSUS security check failed" `
                -Severity "Info" `
                -Category "Network Security" `
                -MITRE "T1184" `
                -Tactic "Execution / Privilege Escalation" `
                -Source "SEC-WSUSInsecureTransport" `
                -Evidence $_.Exception.Message `
                -Recommendation "Verify WinRM access and administrative privileges across target infrastructure servers."
        }
    }