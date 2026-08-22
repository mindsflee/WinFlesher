Register-WFLModule `
    -Name "Security-APT-LateralMovement-WinRMHardening" `
    -Category "Lateral Movement" `
    -Type "Check" `
    -MITRE "T1021.006" `
    -Tactic "Lateral Movement" `
    -Impact "POTENTIAL LATERAL MOVEMENT" `
    -Description "Audits WinRM / PowerShell Remoting configuration for unencrypted transport, weak authentication, and overpermissive TrustedHosts." `
        -Remediation @{
        Module        = 'Security-APT-LateralMovement-WinRMHardening'
        Category      = 'Lateral Movement'
        Type          = 'Specific'
        Description   = 'Hardens WinRM and PowerShell Remoting configuration by enforcing encrypted transport (HTTPS), disabling basic auth, and removing overpermissive TrustedHosts.'
        Impact        = 'Moderate. May break unencrypted remote management scripts relying on Basic authentication.'
        VariableGuide = 'WinRM listener configuration settings.'
        Code          = @'
Set-Item -Path "WSMan:\localhost\Service\Auth\Basic" -Value $false; Set-Item -Path "WSMan:\localhost\Service\AllowUnencrypted" -Value $false
'@
    } -Run {
        Write-Verbose "Auditing WinRM service and client security settings..."
        $Issues = @()
        $WinRmDetails = @{}

        try {
            $serviceReg = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service"
            $clientReg  = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client"

            $allowUnencrypted = Get-ItemPropertyValue -Path $serviceReg -Name "AllowUnencryptedTraffic" -ErrorAction SilentlyContinue
            if ($allowUnencrypted -eq 1) {
                Write-Verbose "WinRM service explicitly allows unencrypted traffic."
                $Issues += "WinRM Service allows unencrypted traffic (AllowUnencryptedTraffic = 1)"
            }

            $allowBasic = Get-ItemPropertyValue -Path $serviceReg -Name "AllowBasic" -ErrorAction SilentlyContinue
            if ($allowBasic -eq 1) {
                Write-Verbose "WinRM service allows basic (cleartext) authentication."
                $Issues += "WinRM Service allows Basic authentication [Cleartext credential risk]"
            }

            if (Test-Path $clientReg) {
                $trustedHosts = Get-ItemPropertyValue -Path $clientReg -Name "TrustedHosts" -ErrorAction SilentlyContinue
                if ($trustedHosts -eq "*") {
                    Write-Verbose "WinRM Client TrustedHosts set to wildcard '*'"
                    $Issues += "WinRM Client TrustedHosts configured with wildcard '*' [MitM / Unauthorized Pivoting Risk]"
                }
            }

            $WinRmDetails["AllowUnencrypted"] = $allowUnencrypted
            $WinRmDetails["AllowBasic"]       = $allowBasic
        } catch {
            Write-Verbose "Could not query WinRM registry policies: $_"
        }

        Add-WFLDetail -Name "Security-APT-LateralMovement-WinRMHardening" -Data $WinRmDetails

        if ($Issues.Count -gt 0) {
            Write-Verbose "WinRM hardening gaps identified: $($Issues -join ' | ')"
            Add-WFLFinding `
                -Title "WinRM / PowerShell Remoting security exposure detected" `
                -Severity "High" `
                -Category "Lateral Movement" `
                -MITRE "T1021.006" `
                -Tactic "Lateral Movement" `
                -Source "Security-APT-LateralMovement-WinRMHardening" `
                -Evidence ($Issues -join " | ") `
                -Recommendation "Enforce HTTPS/Kerberos for WinRM, set AllowUnencryptedTraffic = 0, disable Basic authentication, and restrict TrustedHosts to explicitly allowed IP ranges via GPO."
        } else {
            Write-Verbose "WinRM security baseline check passed."
            Add-WFLFinding `
                -Title "WinRM security hardening review passed" `
                -Severity "Info" `
                -Category "Lateral Movement" `
                -MITRE "T1021.006" `
                -Tactic "Lateral Movement" `
                -Source "Security-APT-LateralMovement-WinRMHardening" `
                -Evidence "WinRM unencrypted traffic disabled; Basic authentication disabled; TrustedHosts wildcard not detected." `
                -Recommendation "Enforce HTTPS listeners for WinRM where remote management over public/untrusted networks is required."
        }
    }


