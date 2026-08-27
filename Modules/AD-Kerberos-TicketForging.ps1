Register-WFLModule `
    -Name "AD-Kerberos-TicketForging" `
    -Category "Active Directory" `
    -Type "Check" `
    -MITRE "T1558.001, T1558.002" `
    -Tactic "Credential Access" `
    -Impact "POTENTIAL DOMAIN COMPROMISE" `
    -Description "Audits Active Directory posture against Golden Ticket (KRBTGT hygiene, encryption) and Silver Ticket (User & Computer SPN exposure, excluding gMSAs and Azure AD SSO)." `
    -Remediation @{
        Module        = 'AD-Kerberos-TicketForging'
        Category      = 'Credential Access'
        Type          = 'Specific'
        Description   = 'Mitigates Golden and Silver ticket exposure vectors by enforcing strong encryption requirements and rotating master service credentials.'
        Impact        = 'Moderate. Ensuring network services support AES before disabling legacy RC4.'
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

            # --- 1. KRBTGT AUDIT (Severity Matrix by Password Age) ---
            $Krbtgt = Get-ADUser -Identity "krbtgt" -Properties passwordLastSet, userAccountControl, msDS-SupportedEncryptionTypes -ErrorAction SilentlyContinue

            if ($Krbtgt) {
                $PwdLastSet = $Krbtgt.passwordLastSet
                $DaysOld = if ($PwdLastSet) { [math]::Round(((Get-Date) - $PwdLastSet).TotalDays) } else { 9999 }
                $EncTypes = [int]$Krbtgt.'msDS-SupportedEncryptionTypes'
                $HasAES = (($EncTypes -band 8) -ne 0) -or (($EncTypes -band 16) -ne 0)

                $GoldenRisk = "Info"
                $RiskFactors = @()

                if ($DaysOld -ge 3650) {
                    $GoldenRisk = "Critical"
                    $RiskFactors += "KRBTGT password older than 10 years ($DaysOld days)"
                }
                elseif ($DaysOld -ge 1825) {
                    $GoldenRisk = "High"
                    $RiskFactors += "KRBTGT password between 5 and 10 years old ($DaysOld days)"
                }
                elseif ($DaysOld -ge 730) {
                    $GoldenRisk = "Medium"
                    $RiskFactors += "KRBTGT password between 2 and 5 years old ($DaysOld days)"
                }
                else {
                    $RiskFactors += "KRBTGT password age is under 2 years ($DaysOld days) - Baseline Review"
                }

                if (-not $HasAES -and $EncTypes -ne 0) {
                    $RiskFactors += "KRBTGT does not explicitly enforce AES encryption (RC4 enabled)"
                    if ($GoldenRisk -in @("Info", "Medium")) { $GoldenRisk = "High" }
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

            # --- 2. USER SPN AUDIT (Excluding gMSAs) ---
            $SpnUsers = Get-ADUser -LDAPFilter "(&(servicePrincipalName=*)(!(objectClass=msDS-GroupManagedServiceAccount)))" `
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
                    $RiskFactors += "User SPN explicitly uses weak encryption (RC4/No AES)"
                    $SilverRisk = "Medium"
                }
                if ($PwdNeverExpires) {
                    $RiskFactors += "User SPN with Password Never Expires"
                    if ($SilverRisk -eq "Low") { $SilverRisk = "Medium" }
                }
                if ($DaysOld -gt 365) {
                    $RiskFactors += "User SPN password older than 365 days ($DaysOld days)"
                    $SilverRisk = "High"
                }

                if ($User.adminCount -eq 1 -and ($PwdNeverExpires -or $NoAES -or ($DaysOld -gt 365))) {
                    $RiskFactors += "Privileged Account with SPN and high-risk posture (adminCount=1)"
                    $SilverRisk = "Critical"
                } elseif ($User.adminCount -eq 1) {
                    $RiskFactors += "Privileged Account with SPN (adminCount=1)"
                    if ($SilverRisk -eq "Low") { $SilverRisk = "Medium" }
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

            # --- 3. COMPUTER SPN AUDIT (Excluding Azure AD SSO & Fixed Computer Logic) ---
            $SpnComputers = Get-ADComputer -LDAPFilter "(servicePrincipalName=*)" `
                -Properties servicePrincipalName, passwordLastSet, userAccountControl, msDS-SupportedEncryptionTypes -ErrorAction SilentlyContinue

            foreach ($Comp in $SpnComputers) {
                # Esclusione account Entra Connect Seamless SSO
                if ($Comp.SamAccountName -like "AZUREADSSOACC*") { continue }

                $UAC = [int]$Comp.userAccountControl
                $Disabled = (($UAC -band 2) -ne 0)
                $DontRequirePreAuth = (($UAC -band 4194304) -ne 0)

                if ($Disabled) { continue }

                $PwdLastSet = $Comp.passwordLastSet
                $DaysOld = if ($PwdLastSet) { [math]::Round(((Get-Date) - $PwdLastSet).TotalDays) } else { 9999 }

                $SilverRisk = "Low"
                $RiskFactors = @()

             
                if ($DontRequirePreAuth) {
                    $RiskFactors += "Computer Account has Kerberos Pre-Authentication Disabled"
                    $SilverRisk = "Critical"
                }

                
if ($DaysOld -ge 3650) {
    $SilverRisk = "Critical"
    $RiskFactors += "Computer account password older than 10 years ($DaysOld days)"
}
elseif ($DaysOld -ge 1825) {
    $SilverRisk = "High"
    $RiskFactors += "Computer account password between 5 and 10 years old ($DaysOld days)"
}
elseif ($DaysOld -ge 730) {
    $SilverRisk = "Medium"
    $RiskFactors += "Computer account password between 2 and 5 years old ($DaysOld days)"
}
elseif ($DaysOld -ge 365) {
    if ($SilverRisk -eq "Low") { $SilverRisk = "Low" } # O gestito come Info/Low per evitare falsi positivi aggressivi
    $RiskFactors += "Computer account password between 1 and 2 years old ($DaysOld days)"
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

            Add-WFLDetail -Name "AD-Kerberos-TicketForging" -Data $Findings

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
                -Recommendation "For Golden Ticket: Enforce AES256 on KRBTGT and rotate password twice. For Silver Ticket: Review SPN service/computer accounts with weak encryption, disabled pre-auth, or stale machine passwords."

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