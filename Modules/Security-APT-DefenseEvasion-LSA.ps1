Register-WFLModule `
    -Name "Security-APT-DefenseEvasion-LSA" `
    -Category "Endpoint Security" `
    -Type "Check" `
    -MITRE "T1003.001, T1562.001" `
    -Tactic "Credential Access, Defense Evasion" `
    -Impact "POTENTIAL CREDENTIAL COMPROMISE" `
    -Description "Checks for critical APT-targeted LSASS protection gaps, Credential Guard, and WDigest plaintext exposure." `
        -Remediation @{
        Module        = 'Security-APT-DefenseEvasion-LSA'
        Category      = 'Credential Access / Defense Evasion'
        Type          = 'Specific'
        Description   = 'Enforces LSA protection (RunAsPPL), Credential Guard, and disables WDigest plaintext credential caching.'
        Impact        = 'Moderate. Reboots required to fully enforce virtualization-based security features.'
        VariableGuide = 'Registry keys governing LSA security.'
        Code          = @'
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RunAsPPL" -Value 1; Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "UseLogonCredential" -Value 0
'@
    } -Run {
        Write-Verbose "Executing APT-focused LSASS and Credential Protection checks..."

        $Issues = @()

        try {
            $lsaPpl = Get-ItemPropertyValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RunAsPPL" -ErrorAction SilentlyContinue
            if ($null -eq $lsaPpl -or [int]$lsaPpl -eq 0) {
                Write-Verbose "LSA Protection (RunAsPPL) is disabled or not configured."
                $Issues += "LSA Protection (RunAsPPL) disabled [LSASS vulnerable to memory dumping]"
            } else {
                Write-Verbose "LSA Protection (RunAsPPL) is active with value: $lsaPpl"
            }
        } catch {
            Write-Verbose "Unable to query RunAsPPL registry key."
            $Issues += "Unable to verify LSA Protection registry configuration"
        }

        try {
            $wdigest = Get-ItemPropertyValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" -Name "UseLogonCredential" -ErrorAction SilentlyContinue
            if ([int]$wdigest -eq 1) {
                Write-Verbose "WDigest plaintext credential caching is forcibly enabled."
                $Issues += "WDigest cleartext credential caching explicitly enabled [High risk of LSASS password extraction]"
            }
        } catch {
        }

        try {
            $credGuard = Get-ItemPropertyValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "LsaCfgFlags" -ErrorAction SilentlyContinue
            if ($null -eq $credGuard -or [int]$credGuard -eq 0) {
                Write-Verbose "Credential Guard (VBS) is not enabled via registry."
                $Issues += "Virtualization-based Security (Credential Guard) not enabled"
            }
        } catch {
            $Issues += "Credential Guard configuration not found"
        }

        $AptDetails = [PSCustomObject]@{
            RunAsPPL           = $lsaPpl
            UseLogonCredential = $wdigest
            LsaCfgFlags        = $credGuard
        }
        Add-WFLDetail -Name "Security-APT-DefenseEvasion-LSA" -Data $AptDetails

        if ($Issues.Count -gt 0) {
            Write-Verbose "APT credential defense gaps identified: $($Issues -join ' | ')"

            $Severity = "Medium"
            if ($Issues -match "RunAsPPL disabled" -or $Issues -match "WDigest cleartext") {
                $Severity = "High"
            }

            Add-WFLFinding `
                -Title "APT Credential Access and LSASS protection gaps detected" `
                -Severity $Severity `
                -Category "Endpoint Security" `
                -MITRE "T1003.001, T1562.001" `
                -Tactic "Credential Access, Defense Evasion" `
                -Source "Security-APT-DefenseEvasion-LSA" `
                -Evidence ($Issues -join " | ") `
                -Recommendation "Enable LSA Protection (RunAsPPL = 1 or 2), ensure WDigest UseLogonCredential = 0, and configure Windows Defender Credential Guard via GPO/Intune."
        }
        else {
            Write-Verbose "APT LSASS and Credential Guard checks passed successfully."
            Add-WFLFinding `
                -Title "APT Credential and LSA protections review passed" `
                -Severity "Info" `
                -Category "Endpoint Security" `
                -MITRE "T1003.001, T1562.001" `
                -Tactic "Credential Access, Defense Evasion" `
                -Source "Security-APT-DefenseEvasion-LSA" `
                -Evidence "RunAsPPL=$lsaPpl; UseLogonCredential=$wdigest; LsaCfgFlags=$credGuard" `
                -Recommendation "Maintain Credential Guard and LSA protection policies enforced across the enterprise."
        }
    }


