Register-WFLModule `
    -Name "AD-ASREP-Roast-Exposure" `
    -Category "Active Directory" `
    -Type "Check" `
    -MITRE "T1558.004" `
    -Tactic "Credential Access" `
    -Impact "POTENTIAL CREDENTIAL COMPROMISE" `
    -Description "Identifies enabled Active Directory users that do not require Kerberos pre-authentication and may be exposed to AS-REP roasting." `
        -Remediation @{
        Module        = 'AD-ASREP-Roast-Exposure'
        Category      = 'Credential Access'
        Type          = 'Specific'
        Description   = 'Disables Kerberos pre-authentication for service accounts that do not strictly require it, mitigating offline brute-force vectors.'
        Impact        = 'Low. Disabling pre-auth enhances security immediately. However, if a legacy application explicitly relies on pre-authentication bypass parameters, authentication for that specific service may fail.'
        VariableGuide = 'Target accounts are automatically filtered via -Filter {DoesNotRequirePreAuth -eq True}. No manual variable mapping required unless scoping to a specific Organizational Unit (OU) via -SearchBase.'
        Code          = @'
Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true} | Set-ADUser -DoesNotRequirePreAuth $false
'@
    } -Run {

        if (-not $Global:WinFlesher.Context.ActiveDirectory.Available) { return }

        try {

            function Test-WFLPrivilegedAsrepAccount {
                param(
                    [object]$User
                )

                if ($User.AdminCount -eq 1) {
                    return $true
                }

                $PrivilegedGroupPatterns = @(
                    "Domain Admins",
                    "Enterprise Admins",
                    "Schema Admins",
                    "Administrators",
                    "Account Operators",
                    "Server Operators",
                    "Backup Operators",
                    "DnsAdmins",
                    "Group Policy Creator Owners"
                )

                foreach ($GroupDN in @($User.MemberOf)) {
                    foreach ($Pattern in $PrivilegedGroupPatterns) {
                        if ([string]$GroupDN -like "*CN=$Pattern,*") {
                            return $true
                        }
                    }
                }

                return $false
            }

           function Get-WFLAsrepSeverity {
    param(
        [bool]$Enabled,
        [bool]$IsPrivileged,
        [int]$PasswordAgeDays,
        [bool]$HasSPN
    )

    if (-not $Enabled)
    {
        return "Low"
    }

    if ($IsPrivileged)
    {
        return "Critical"
    }

    if ($PasswordAgeDays -eq -1)
    {
        return "Medium"
    }

    if ($PasswordAgeDays -ge 365)
    {
        return "High"
    }

    if ($HasSPN -and $PasswordAgeDays -ge 180)
    {
        return "High"
    }

    return "Medium"
}

            $Users = Get-ADUser `
                -LDAPFilter "(userAccountControl:1.2.840.113556.1.4.803:=4194304)" `
                -Properties SamAccountName,Enabled,AdminCount,PasswordLastSet,LastLogonDate,ServicePrincipalName,MemberOf,userAccountControl `
                -ErrorAction Stop

            $Findings = @()
            $Now = Get-Date

            foreach ($User in $Users) {

               $PasswordAgeDays = -1

if ($null -ne $User.PasswordLastSet)
{
   
$PasswordAgeDays = (New-TimeSpan -Start $User.PasswordLastSet -End $Now).Days
}

                $HasSPN = @($User.ServicePrincipalName).Count -gt 0
                $IsPrivileged = Test-WFLPrivilegedAsrepAccount -User $User

                $Severity = Get-WFLAsrepSeverity `
                    -Enabled ([bool]$User.Enabled) `
                    -IsPrivileged ([bool]$IsPrivileged) `
                    -PasswordAgeDays $PasswordAgeDays `
                    -HasSPN ([bool]$HasSPN)

                $Exploitability = "Potential"

                if ($Severity -eq "Critical" -or $Severity -eq "High") {
                    $Exploitability = "Likely"
                }

                if (-not $User.Enabled) {
                    $Exploitability = "Not directly exploitable"
                }

                $RiskReasons = @()

                if ($User.Enabled) {
                    $RiskReasons += "Account enabled"
                }
                else {
                    $RiskReasons += "Account disabled"
                }

                if ($IsPrivileged) {
                    $RiskReasons += "Privileged or AdminCount account"
                }

                if ($HasSPN) {
                    $RiskReasons += "SPN present"
                }

                if ($PasswordAgeDays -ge 365) {
                    $RiskReasons += "Password older than 365 days"
                }
                elseif ($PasswordAgeDays -ge 180) {
                    $RiskReasons += "Password older than 180 days"
                }

                $Findings += [PSCustomObject]@{
                    SamAccountName   = $User.SamAccountName
                    Enabled          = [bool]$User.Enabled
                    AdminCount       = $User.AdminCount
                    HasSPN           = $HasSPN
                    SPNCount         = @($User.ServicePrincipalName).Count
                    PasswordLastSet  = $User.PasswordLastSet
                    PasswordAgeDays  = $PasswordAgeDays
                    LastLogonDate    = $User.LastLogonDate
                    IsPrivileged     = $IsPrivileged
                    Severity         = $Severity
                    Exploitability   = $Exploitability
                    RiskReason       = ($RiskReasons -join "; ")
                }
            }

            Add-WFLDetail -Name "AD-ASREP-Roast-Exposure" -Data $Findings

            $EnabledCount  = @($Findings | Where-Object { $_.Enabled -eq $true }).Count
            $DisabledCount = @($Findings | Where-Object { $_.Enabled -eq $false }).Count
            $CriticalCount = @($Findings | Where-Object { $_.Severity -eq "Critical" }).Count
            $HighCount     = @($Findings | Where-Object { $_.Severity -eq "High" }).Count
            $MediumCount   = @($Findings | Where-Object { $_.Severity -eq "Medium" }).Count
            $LowCount      = @($Findings | Where-Object { $_.Severity -eq "Low" }).Count

            $Severity = "Info"

            if ($LowCount -gt 0) {
                $Severity = "Low"
            }

            if ($MediumCount -gt 0) {
                $Severity = "Medium"
            }

            if ($HighCount -gt 0) {
                $Severity = "High"
            }

            if ($CriticalCount -gt 0) {
                $Severity = "Critical"
            }

            if ($Findings.Count -eq 0) {
                Add-WFLFinding `
                    -Title "AS-REP roast exposure review passed" `
                    -Severity "Info" `
                    -Category "Active Directory" `
                    -MITRE "T1558.004" `
                    -Tactic "Credential Access" `
                    -Source "AD-ASREP-Roast-Exposure" `
                    -Evidence "ASREPUsers=0" `
                    -Recommendation "No accounts with Kerberos pre-authentication disabled were detected."
                return
            }

            Add-WFLFinding `
                -Title "AS-REP roast exposure detected" `
                -Severity $Severity `
                -Category "Active Directory" `
                -MITRE "T1558.004" `
                -Tactic "Credential Access" `
                -Source "AD-ASREP-Roast-Exposure" `
                -Evidence "ASREPUsers=$($Findings.Count); Enabled=$EnabledCount; Disabled=$DisabledCount; Critical=$CriticalCount; High=$HighCount; Medium=$MediumCount; Low=$LowCount" `
                -Recommendation "Enable Kerberos pre-authentication on affected accounts. Prioritize enabled privileged accounts, accounts with SPNs, and accounts with old passwords."

        }
        catch {
            Add-WFLFinding `
                -Title "AS-REP roast exposure review failed" `
                -Severity "Info" `
                -Category "Active Directory" `
                -MITRE "T1558.004" `
                -Tactic "Credential Access" `
                -Source "AD-ASREP-Roast-Exposure" `
                -Evidence $_.Exception.Message `
                -Recommendation "Verify Active Directory module availability and permissions to query userAccountControl attributes."
        }
    }


