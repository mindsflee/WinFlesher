Register-WFLModule `
    -Name "AD-Password-Policy" `
    -Category "Active Directory" `
    -Type "Check" `
    -MITRE "T1201" `
    -Tactic "Credential Access" `
    -Impact "POTENTIAL CREDENTIAL COMPROMISE" `
    -Description "Audits the Active Directory default domain password and lockout policy against security baselines." `
     -Remediation @{
        Module        = 'AD-PasswordPolicy.ps1'
        Category      = 'Active Directory Security'
        Type          = 'Specific'
        Description   = 'Implement a Fine-Grained Password Policy (FGPP) to enforce password complexity and expiration.'
        Impact        = 'Mitigates the risk of brute-force and credential stuffing attacks against privileged accounts.'
        VariableGuide = 'Default policy parameters can be adjusted directly within the script block.'
        Code          = @'
New-ADFineGrainedPasswordPolicy -Name "Secure-Admin-FGPP" `
    -Precedence 1 `
    -ComplexityEnabled $true `
    -MinPasswordLength 14 `
    -PasswordHistoryCount 24 `
    -MinPasswordAge "1.00:00:00" `
    -MaxPasswordAge "60.00:00:00" `
    -LockoutThreshold 5 `
    -LockoutObservationWindow "00:30:00" `
    -LockoutDuration "00:30:00"
Add-ADFineGrainedPasswordPolicySubject -Identity "Secure-Admin-FGPP" -Subjects "Administrators"
'@
    } -Run {

        if (-not $Global:WinFlesher.Context.ActiveDirectory.Available) {
            Add-WFLFinding `
                -Title "Password policy review unavailable" `
                -Severity "Info" `
                -Category "Active Directory" `
                -Source "AD-Password-Policy" `
                -Evidence "AD unavailable."
            return
        }

        try {
            $Policy = Get-ADDefaultDomainPasswordPolicy

            Add-WFLDetail `
                -Name "AD-PasswordPolicy" `
                -Data $Policy

            $Issues = @()
            $MinLength = $Policy.MinPasswordLength

            if ($MinLength -lt 8) {
                $Issues += "MinPasswordLength critically low ($MinLength < 8)"
                $LengthSeverity = "High"  # Usa "Critical" se hai abilitato la severity estesa nell'engine
            }
            elseif ($MinLength -lt 10) {
                $Issues += "MinPasswordLength weak ($MinLength < 10)"
                $LengthSeverity = "High"
            }
            elseif ($MinLength -lt 12) {
                $Issues += "MinPasswordLength sub-optimal ($MinLength < 12)"
                $LengthSeverity = "Medium"
            }
            else {
                $LengthSeverity = "Info"
            }

            $LockoutSeverity = "Info"
            if ($Policy.LockoutThreshold -eq 0) {
                $Issues += "Account Lockout Threshold is disabled (Spray exposure)"
                $LockoutSeverity = "Medium"
            }

            $SeverityMap = @{ "Info" = 0; "Medium" = 1; "High" = 2; "Critical" = 3 }
            
            $MaxScore = [Math]::Max($SeverityMap[$LengthSeverity], $SeverityMap[$LockoutSeverity])
            
            $Severity = switch ($MaxScore) {
                3 { "Critical" }
                2 { "High" }
                1 { "Medium" }
                default { "Info" }
            }


            $EvidenceText = if ($Issues.Count -gt 0) { $Issues -join " | " } else { "Password policy meets basic length criteria (>= 12 chars) and lockout threshold is enabled." }

            Add-WFLFinding `
                -Title "AD Default Password & Lockout Policy Audit" `
                -Severity $Severity `
                -Category "Active Directory" `
                -MITRE "T1201" `
                -Tactic "Credential Access" `
                -Source "AD-Password-Policy" `
                -Evidence $EvidenceText `
                -Recommendation "Enforce a minimum password length of at least 14 characters (NIST/CIS benchmark) and set an account lockout threshold to mitigate password spraying."

        }
        catch {
            Add-WFLFinding `
                -Title "Unable to retrieve password policy" `
                -Severity "Info" `
                -Category "Active Directory" `
                -Source "AD-Password-Policy" `
                -Evidence $_.Exception.Message
        }
    }


