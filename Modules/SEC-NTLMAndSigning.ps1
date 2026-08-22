Register-WFLModule `
    -Name "SEC-NTLMAndSigning" `
    -Category "Network Security" `
    -Type "Check" `
    -MITRE "T1557" `
    -Tactic "Credential Access" `
    -Impact "POTENTIAL LATERAL MOVEMENT" `
    -Description "Audits SMB Signing, LDAP Channel Binding, and NTLMv1 exposure across domain controllers." `
        -Remediation @{
        Module        = 'SEC-NTLMAndSigning'
        Category      = 'Credential Access / Lateral Movement'
        Type          = 'Specific'
        Description   = 'Enforces SMB signing, LDAP channel binding, and restricts NTLMv1 / NTLM traffic domain-wide.'
        Impact        = 'Moderate to High. Enforcing strict SMB signing and disabling NTLMv1 may disrupt legacy appliances or unauthenticated network scanners.'
        VariableGuide = 'Group Policy settings for Network Security.'
        Code          = @'
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "requiresecuritysignature" -Value 1
'@
    } -Run {
        try {
            $LsaPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
            $LdapPath = "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters"

            $LmCompatibility = (Get-ItemProperty -Path $LsaPath -Name "LmCompatibilityLevel" -ErrorAction SilentlyContinue).LmCompatibilityLevel
            $LdapSigning = (Get-ItemProperty -Path $LdapPath -Name "LDAPServerIntegrity" -ErrorAction SilentlyContinue).LDAPServerIntegrity
            $LdapChannelBinding = (Get-ItemProperty -Path $LdapPath -Name "LdapEnforceChannelBinding" -ErrorAction SilentlyContinue).LdapEnforceChannelBinding

            $Issues = @()

            if ($null -eq $LmCompatibility -or $LmCompatibility -lt 5) {
                $Issues += "NTLMv1 or weak NTLM response authentication allowed (LmCompatibilityLevel < 5)."
            }
            if ($null -eq $LdapSigning -or $LdapSigning -eq 0) {
                $Issues += "LDAP Server Signing is not enforced."
            }
            if ($null -eq $LdapChannelBinding -or $LdapChannelBinding -eq 0) {
                $Issues += "LDAP Channel Binding token enforcement is disabled."
            }

            Add-WFLDetail -Name "SEC-NTLMAndSigning" -Data $Issues
            $Severity = if ($Issues.Count -gt 0) { "High" } else { "Info" }

            Add-WFLFinding `
                -Title "NTLM & LDAP Protocol Hardening Audit" `
                -Severity $Severity `
                -Category "Network Security" `
                -MITRE "T1557" `
                -Tactic "Credential Access" `
                -Source "SEC-NTLMAndSigning" `
                -Evidence "Identified $($Issues.Count) protocol signing/enforcement misconfigurations." `
                -Recommendation "Set LmCompatibilityLevel to 5 (Send NTLMv2 only), enforce LDAP signing and channel binding."
        }
        catch {
            Add-WFLFinding -Title "NTLM/Signing check failed" -Severity "Info" -Category "Network Security" -Source "SEC-NTLMAndSigning" -Evidence $_.Exception.Message
        }
    }


