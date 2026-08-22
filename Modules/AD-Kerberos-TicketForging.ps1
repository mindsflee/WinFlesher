Register-WFLModule `
    -Name "AD-Kerberos-TicketForging" `
    -Category "Active Directory" `
    -Type "Check" `
    -MITRE "T1558.001, T1558.002" `
    -Tactic "Credential Access" `
    -Impact "POTENTIAL DOMAIN COMPROMISE" `
    -Description "Audits Active Directory posture against Golden Ticket (KRBTGT hygiene, encryption) and Silver Ticket (User & Computer SPN exposure)." `
        -Remediation @{
        Module        = 'AD-Kerberos-TicketForging'
        Category      = 'Credential Access'
        Type          = 'Specific'
        Description   = 'Mitigates Golden and Silver ticket exposure vectors by enforcing strong encryption requirements and rotating master service credentials.'
        Impact        = 'Moderate. Requires ensuring all network services support AES before disabling legacy RC4 ticket encryption.'
        VariableGuide = 'Domain-wide cryptographic hardening configuration.'
        Code          = @'
Set-ADAccountPassword -Identity "krbtgt" -NewPassword ($SecurePassword)
'@
    } -Run {

        if (-not $Global:WinFlesher.Context.ActiveDirectory.Available) {
            Add-WFLFinding `
                -Title "Kerberos ticket forging review unavailable" `
                -Severity "Info" `
                -Category "Active Directory" `
                -MITRE "T1558.001, T1558.002" `
                -Tactic "Credential Access" `
                -Source "AD-Kerberos-TicketForging" `
                -Evidence "Active Directory discovery unavailable." `
                -Recommendation "Run from a domain-joined host with RSAT ActiveDirectory module."
            return
        }

        try {

            $Findings = @()

            $Krbtgt = Get-ADUser -Identity "krbtgt" -Properties passwordLastSet, userAccountControl, msDS-SupportedEncryptionTypes -ErrorAction SilentlyContinue

            if ($Krbtgt) {
                $PwdLastSet = $Krbtgt.passwordLastSet
                $DaysOld = if ($PwdLastSet) { [math]::Round(((Get-Date) - $PwdLastSet).TotalDays) } else { 9999 }
                $EncTypes = [int]$Krbtgt.'msDS-SupportedEncryptionTypes'

                $HasAES = (($EncTypes -band 8) -ne 0) -or (($EncTypes -band 16) -ne 0)

                $GoldenRisk = "Medium"
                $RiskFactors = @()

                if ($DaysOld -gt 180) {
                    $GoldenRisk = "High"
                    $RiskFactors += "KRBTGT password older than 180 days ($DaysOld days)"
                }
                if ($DaysOld -gt 365) {
                    $GoldenRisk = "Critical"
                    $RiskFactors += "KRBTGT password older than 365 days ($DaysOld days)"
                }

                if (-not $HasAES -and $EncTypes -ne 0) {
                    $RiskFactors += "KRBTGT does not explicitly enforce AES encryption (RC4 enabled)"
                    if ($GoldenRisk -ne "Critical") { $GoldenRisk = "High" }
                }

                if ($RiskFactors.Count -eq 0) {
                    $RiskFactors += "KRBTGT password age is acceptable ($DaysOld days) - Baseline Review"
                }

                $Findings += [PSCustomObject]@{
                    Category          = "Golden Ticket"
                    TargetObject      = $Krbtgt.SamAccountName
                    ObjectClass       = "user"
                    DistinguishedName = $Krbtgt.DistinguishedName
                    IssueType         = "KRBTGT Hygiene Review"
                    PasswordLastSet   = $PwdLastSet
                    PasswordAgeDays   = $DaysOld
                    Severity          = $GoldenRisk
                    Details           = ($RiskFactors -join "; ")
                }
            }

            $SpnUsers = Get-ADUser -LDAPFilter "(servicePrincipalName=*)" `
                -Properties servicePrincipalName, passwordLastSet, userAccountControl, msDS-SupportedEncryptionTypes, adminCount -ErrorAction SilentlyContinue

            foreach ($User in $SpnUsers) {
                
                $UAC = [int]$User.userAccountControl
                $PwdNeverExpires = (($UAC -band 65536) -ne 0)
                $Disabled = (($UAC -band 2) -ne 0)

                if ($Disabled) { continue }

                $PwdLastSet = $User.passwordLastSet
                $DaysOld = if ($PwdLastSet) { [math]::Round(((Get-Date) - $PwdLastSet).TotalDays) } else { 9999 }
                $EncTypes = [int]$User.'msDS-SupportedEncryptionTypes'
                
                $NoAES = ($EncTypes -ne 0) -and (($EncTypes -band 24) -eq 0)

                $SilverRisk = "Low"
                $RiskFactors = @()

                if ($NoAES) {
                    $RiskFactors += "User SPN uses RC4/Weak Encryption"
                    $SilverRisk = "Medium"
                }
                if ($PwdNeverExpires) {
                    $RiskFactors += "User SPN with Password Never Expires"
                    if ($SilverRisk -eq "Low") { $SilverRisk = "Medium" }
                }
                if ($DaysOld -gt 180) {
                    $RiskFactors += "User SPN password older than 180 days ($DaysOld days)"
                    $SilverRisk = "High"
                }

                if ($User.adminCount -eq 1) {
                    $RiskFactors += "Privileged Account / Domain Admin Target (adminCount=1)"
                    $SilverRisk = "Critical"
                } elseif ($PwdNeverExpires -and $NoAES) {
                    $SilverRisk = "Critical"
                }

                if ($SilverRisk -eq "Low") { continue }

                $Findings += [PSCustomObject]@{
                    Category          = "Silver Ticket"
                    TargetObject      = $User.SamAccountName
                    ObjectClass       = "user"
                    DistinguishedName = $User.DistinguishedName
                    IssueType         = "Vulnerable User SPN Target"
                    PasswordLastSet   = $PwdLastSet
                    PasswordAgeDays   = $DaysOld
                    Severity          = $SilverRisk
                    Details           = ($RiskFactors -join "; ")
                }
            }

            $SpnComputers = Get-ADComputer -LDAPFilter "(servicePrincipalName=*)" `
                -Properties servicePrincipalName, passwordLastSet, userAccountControl, msDS-SupportedEncryptionTypes -ErrorAction SilentlyContinue

            foreach ($Comp in $SpnComputers) {
                
                $UAC = [int]$Comp.userAccountControl
                $PwdNeverExpires = (($UAC -band 65536) -ne 0)
                $Disabled = (($UAC -band 2) -ne 0)
                $DontRequirePreAuth = (($UAC -band 4194304) -ne 0)

                if ($Disabled) { continue }

                $PwdLastSet = $Comp.passwordLastSet
                $DaysOld = if ($PwdLastSet) { [math]::Round(((Get-Date) - $PwdLastSet).TotalDays) } else { 9999 }

                $SilverRisk = "Low"
                $RiskFactors = @()

                if ($PwdNeverExpires) {
                    $RiskFactors += "Computer Account with Password Never Expires (Machine Password Rotation Disabled)"
                    $SilverRisk = "High"
                }
                if ($DontRequirePreAuth) {
                    $RiskFactors += "Computer Account has Kerberos Pre-Authentication Disabled"
                    $SilverRisk = "Critical"
                }

                if ($SilverRisk -eq "Low") { continue }

                $Findings += [PSCustomObject]@{
                    Category          = "Silver Ticket"
                    TargetObject      = $Comp.Name
                    ObjectClass       = "computer"
                    DistinguishedName = $Comp.DistinguishedName
                    IssueType         = "Vulnerable Computer SPN Target"
                    PasswordLastSet   = $PwdLastSet
                    PasswordAgeDays   = $DaysOld
                    Severity          = $SilverRisk
                    Details           = ($RiskFactors -join "; ")
                }
            }

            Add-WFLDetail `
                -Name "AD-Kerberos-TicketForging" `
                -Data $Findings

            $CriticalCount = @($Findings | Where-Object { $_.Severity -eq "Critical" }).Count
            $HighCount     = @($Findings | Where-Object { $_.Severity -eq "High" }).Count
            $MediumCount   = @($Findings | Where-Object { $_.Severity -eq "Medium" }).Count

            $Severity = "Info"
            if ($MediumCount -gt 0)   { $Severity = "Medium" }
            if ($HighCount -gt 0)     { $Severity = "High" }
            if ($CriticalCount -gt 0) { $Severity = "Critical" }

            Add-WFLFinding `
                -Title "Kerberos Ticket Forging Risk Detected (Golden/Silver Ticket Exposure)" `
                -Severity $Severity `
                -Category "Active Directory" `
                -MITRE "T1558.001, T1558.002" `
                -Tactic "Credential Access" `
                -Source "AD-Kerberos-TicketForging" `
                -Evidence "ExposedTargets=$($Findings.Count); Critical=$CriticalCount; High=$HighCount; Medium=$MediumCount" `
                -Recommendation "For Golden Ticket: Enforce AES256 on KRBTGT and rotate password twice. For Silver Ticket: Review SPN service/computer accounts with PasswordNeverExpires, weak encryption, or privileged access."

        }
        catch {
            Add-WFLFinding `
                -Title "Kerberos ticket forging review failed" `
                -Severity "Info" `
                -Category "Active Directory" `
                -MITRE "T1558.001, T1558.002" `
                -Tactic "Credential Access" `
                -Source "AD-Kerberos-TicketForging" `
                -Evidence $_.Exception.Message `
                -Recommendation "Verify Active Directory module availability and permissions to query objects."
        }
    }


