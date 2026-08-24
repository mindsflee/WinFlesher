Register-WFLModule `
    -Name "AD-Kerberos-Exposure" `
    -Category "Active Directory" `
    -Type "Check" `
    -MITRE "T1558.001, T1558.002, T1558.003" `
    -Tactic "Credential Access" `
    -Impact "POTENTIAL CREDENTIAL COMPROMISE" `
    -Description "Reviews Kerberos SPN exposure and risk factors across users, managed service accounts, computer objects, and KRBTGT." `
        -Remediation @{
        Module        = 'AD-Kerberos-Exposure'
        Category      = 'Credential Access'
        Type          = 'Specific'
        Description   = 'Audits and remediates Kerberos Service Principal Name (SPN) exposures, weak encryption types (RC4), and unconstrained settings across user and service accounts.'
        Impact        = 'Low. Enforcing AES encryption and cleaning up duplicate or overly broad SPNs hardens the Kerberos authentication architecture.'
        VariableGuide = 'Targets accounts with vulnerable SPN mappings.'
        Code          = @'
Set-ADUser -Identity "ServiceAccount" -KerberosEncryptionType AES128,AES256
'@
    } -Run {

        $AD = $Global:WinFlesher.Context.ActiveDirectory

        if (-not $AD.Available) {
            Add-WFLFinding `
                -Title "Kerberos review unavailable" `
                -Severity "Info" `
                -Category "Active Directory" `
                -MITRE "T1558.001, T1558.002, T1558.003" `
                -Tactic "Credential Access" `
                -Source "AD-Kerberos-Exposure" `
                -Evidence "Active Directory discovery unavailable." `
                -Recommendation "Run from a domain-joined host with RSAT ActiveDirectory module."
            return
        }

        try {

            $SpnObjects = Get-ADObject `
                -LDAPFilter "(servicePrincipalName=*)" `
                -Properties `
                    servicePrincipalName,
                    samAccountName,
                    adminCount,
                    userAccountControl,
                    pwdLastSet,
                    msDS-SupportedEncryptionTypes,
                    distinguishedName `
                -ErrorAction Stop

            $Findings = @()
            $Now = Get-Date

            foreach ($Obj in $SpnObjects) {

                $Name = [string]$Obj.Name
                $SamAccountName = [string]$Obj.samAccountName

                if ([string]::IsNullOrEmpty($SamAccountName)) {
                    $SamAccountName = $Name
                }

                $ObjectClass = [string]$Obj.ObjectClass
                $DN = [string]$Obj.DistinguishedName
                $SPNs = @($Obj.servicePrincipalName)
                $SPNCount = $SPNs.Count

                $UserAccountControl = 0
                if ($null -ne $Obj.userAccountControl) {
                    $UserAccountControl = [int]$Obj.userAccountControl
                }

                $Enabled = ($UserAccountControl -band 2) -eq 0
                $PasswordNeverExpires = ($UserAccountControl -band 65536) -ne 0
                $DontRequirePreAuth = ($UserAccountControl -band 4194304) -ne 0

                $PasswordLastSet = $null
                $PasswordAgeDays = -1

                if ($null -ne $Obj.pwdLastSet -and [int64]$Obj.pwdLastSet -gt 0) {
                    try {
                        $PasswordLastSet = [DateTime]::FromFileTime([int64]$Obj.pwdLastSet)
                        $PasswordAgeDays = (New-TimeSpan -Start $PasswordLastSet -End $Now).Days
                    } catch {
                        $PasswordLastSet = $null
                        $PasswordAgeDays = -1
                    }
                }

                $AdminCount = 0
                if ($null -ne $Obj.adminCount) {
                    $AdminCount = [int]$Obj.adminCount
                }

                $EncTypes = 0
                if ($null -ne $Obj.'msDS-SupportedEncryptionTypes') {
                    $EncTypes = [int]$Obj.'msDS-SupportedEncryptionTypes'
                }
                $HasAES = (($EncTypes -band 8) -ne 0) -or (($EncTypes -band 16) -ne 0)

                $IsKrbtgt = ($SamAccountName -eq "krbtgt" -or $Name -eq "krbtgt")
                $IsComputer = ($ObjectClass -eq "computer")
                $IsManagedServiceAccount = ($ObjectClass -eq "msDS-ManagedServiceAccount" -or $ObjectClass -eq "msDS-GroupManagedServiceAccount")
                $IsUser = ($ObjectClass -eq "user")
                $IsPrivileged = ($AdminCount -eq 1 -or $DN -like "*OU=Domain Controllers,*")

                $RiskReasons = @()
                $Severity = "Info"
                $Exploitability = "Informational"
                $KerberoastCandidate = $false
                $Category = "Silver Ticket"


              if ($IsKrbtgt) {

    $Category = "Golden Ticket Hygiene"
    $Exploitability = "Conditional"
    $KerberoastCandidate = $false
    $Severity = "Info"

    $RiskReasons += "KRBTGT hygiene review"

    if ($PasswordAgeDays -ge 3650) {
        $Severity = "Critical"
        $Exploitability = "Material exposure"
        $RiskReasons += "KRBTGT password older than 3650 days ($PasswordAgeDays days)"
    }
    elseif ($PasswordAgeDays -ge 1825) {
        $Severity = "High"
        $Exploitability = "Elevated exposure"
        $RiskReasons += "KRBTGT password older than 1825 days ($PasswordAgeDays days)"
    }
    elseif ($PasswordAgeDays -ge 730) {
        $Severity = "Medium"
        $Exploitability = "Hygiene gap"
        $RiskReasons += "KRBTGT password older than 730 days ($PasswordAgeDays days)"
    }
    else {
        $RiskReasons += "KRBTGT password age does not exceed configured risk thresholds"
    }

    if ($EncTypes -eq 0) {
        $RiskReasons += "Encryption types not explicitly configured; effective domain behavior must be validated"
    }
    elseif (-not $HasAES) {
        $RiskReasons += "AES not enabled in msDS-SupportedEncryptionTypes"

        if ($Severity -eq "Info") {
            $Severity = "Medium"
        }
    }
}
elseif ($IsComputer) {

    $Category = "Computer Service Principal"
    $KerberoastCandidate = $false
    $Severity = "Info"
    $Exploitability = "Expected computer SPN"

    if (-not $Enabled) {
        $Severity = "Low"
        $Exploitability = "Not directly exploitable"
        $RiskReasons += "Disabled computer account retains SPNs"
    }
    elseif ($DontRequirePreAuth) {
        $Severity = "High"
        $Exploitability = "Likely"
        $RiskReasons += "Computer account has Kerberos pre-authentication disabled"
    }
    elseif ($IsPrivileged -and $PasswordNeverExpires) {
        $Severity = "Critical"
        $Exploitability = "High"
        $RiskReasons += "Privileged computer or Domain Controller with Password Never Expires"
    }
    elseif ($PasswordNeverExpires) {
        $Severity = "Medium"
        $Exploitability = "Conditional"
        $RiskReasons += "Computer account password rotation disabled"
    }
    elseif ($IsPrivileged -and $PasswordAgeDays -ge 365) {
        $Severity = "Medium"
        $Exploitability = "Conditional"
        $RiskReasons += "Privileged computer password older than 365 days ($PasswordAgeDays days)"
    }
    else {
        $RiskReasons += "Standard computer account SPN"
    }

    if ($EncTypes -eq 0) {
        $RiskReasons += "Encryption types inherited or not explicitly configured"
    }
    elseif (-not $HasAES) {
        $RiskReasons += "AES not explicitly enabled"

        if ($Severity -eq "Info") {
            $Severity = "Low"
        }
    }
}
elseif ($IsManagedServiceAccount) {

    $Category = "Managed Service Account"
    $KerberoastCandidate = $false
    $Severity = "Info"
    $Exploitability = "Low"

    $RiskReasons += "Managed Service Account with automatically managed password"

    if (-not $Enabled) {
        $Severity = "Low"
        $Exploitability = "Not directly exploitable"
        $RiskReasons += "Managed Service Account is disabled"
    }
    elseif ($DontRequirePreAuth) {
        $Severity = "High"
        $Exploitability = "Likely"
        $RiskReasons += "Kerberos pre-authentication disabled"
    }
    elseif ($IsPrivileged -and $EncTypes -ne 0 -and -not $HasAES) {
        $Severity = "High"
        $Exploitability = "Conditional"
        $RiskReasons += "Privileged managed service account without AES enabled"
    }
    elseif ($IsPrivileged) {
        $Severity = "Medium"
        $Exploitability = "Conditional"
        $RiskReasons += "Privileged managed service account"
    }
    elseif ($EncTypes -ne 0 -and -not $HasAES) {
        $Severity = "Medium"
        $Exploitability = "Conditional"
        $RiskReasons += "Managed service account without AES enabled"
    }
    elseif ($EncTypes -eq 0) {
        $RiskReasons += "Encryption types not explicitly configured"
    }
}
elseif ($IsUser) {

    $Category = "Kerberoastable User SPN"
    $KerberoastCandidate = $Enabled
    $Severity = "Info"
    $Exploitability = "Informational"

    if (-not $Enabled) {
        $Severity = "Low"
        $Exploitability = "Not directly exploitable"
        $RiskReasons += "Disabled user account retains SPNs"
    }
    else {
        $Severity = "Medium"
        $Exploitability = "Potential"
        $RiskReasons += "Enabled user account with SPN"

        if ($DontRequirePreAuth) {
            $Severity = "Critical"
            $Exploitability = "High"
            $RiskReasons += "Kerberos pre-authentication disabled"
            $RiskReasons += "Account is exposed to both AS-REP roasting and Kerberoasting"
        }
        elseif (
            $IsPrivileged -and
            $PasswordNeverExpires -and
            $EncTypes -ne 0 -and
            -not $HasAES
        ) {
            $Severity = "Critical"
            $Exploitability = "Likely"
            $RiskReasons += "Privileged user SPN with Password Never Expires and no AES"
        }
        elseif ($IsPrivileged) {
            $Severity = "High"
            $Exploitability = "Likely"
            $RiskReasons += "Privileged user SPN account"
        }
        elseif (
            $PasswordNeverExpires -and
            $EncTypes -ne 0 -and
            -not $HasAES
        ) {
            $Severity = "High"
            $Exploitability = "Likely"
            $RiskReasons += "Password Never Expires combined with no AES"
        }
        elseif ($PasswordNeverExpires) {
            $Severity = "High"
            $Exploitability = "Likely"
            $RiskReasons += "Password Never Expires"
        }
        elseif ($PasswordAgeDays -ge 3650) {
            $Severity = "High"
            $Exploitability = "Likely"
            $RiskReasons += "Password older than 3650 days ($PasswordAgeDays days)"
        }
        elseif ($PasswordAgeDays -ge 1825) {
            $Severity = "Medium"
            $Exploitability = "Potential"
            $RiskReasons += "Password older than 1825 days ($PasswordAgeDays days)"
        }

        if ($EncTypes -eq 0) {
            $RiskReasons += "Encryption types not explicitly configured; weak encryption cannot be confirmed from this attribute alone"
        }
        elseif (-not $HasAES) {
            $RiskReasons += "AES not enabled in msDS-SupportedEncryptionTypes"

            if ($Severity -eq "Medium") {
                $Severity = "High"
                $Exploitability = "Likely"
            }
        }
    }
}
else {

    $Category = "Non-standard SPN Object"
    $Severity = "Low"
    $Exploitability = "Conditional"
    $KerberoastCandidate = $false
    $RiskReasons += "Non-standard SPN object class"
}

                if ($SPNCount -gt 0) {
                    $RiskReasons += "SPNCount=$SPNCount"
                }

                $Findings += [PSCustomObject]@{
                    Name                    = $Name
                    SamAccountName          = $SamAccountName
                    ObjectClass             = $ObjectClass
                    DistinguishedName       = $DN
                    SPNCount                = $SPNCount
                    Category                = $Category
                    Severity                = $Severity
                    ServicePrincipalName    = ($SPNs -join "; ")
                    Exploitability          = $Exploitability
                    Enabled                 = $Enabled
                    AdminCount              = $AdminCount
                    PasswordNeverExpires    = $PasswordNeverExpires
                    PasswordLastSet         = $PasswordLastSet
                    PasswordAgeDays         = $PasswordAgeDays
                    IsKrbtgt                = $IsKrbtgt
                    IsComputer              = $IsComputer
                    IsManagedServiceAccount = $IsManagedServiceAccount
                    IsUser                  = $IsUser
                    IsPrivileged            = $IsPrivileged
                    KerberoastCandidate     = $KerberoastCandidate
                    RiskReason              = ($RiskReasons -join "; ")
                }
            }

            Add-WFLDetail -Name "AD-Kerberos-Exposure" -Data $Findings

            $TotalSPNObjects = $Findings.Count
            $UserSPNCount = @($Findings | Where-Object { $_.IsUser -and -not $_.IsKrbtgt }).Count
            $ManagedServiceAccountCount = @($Findings | Where-Object { $_.IsManagedServiceAccount }).Count
            $ComputerSPNCount = @($Findings | Where-Object { $_.IsComputer }).Count
            $KerberoastCandidateCount = @($Findings | Where-Object { $_.KerberoastCandidate }).Count
			$ActionableKerberoastCount = @(
    $Findings |
        Where-Object {
            $_.KerberoastCandidate -and
            $_.Enabled -and
            $_.Severity -in @("Critical", "High", "Medium")
        }
).Count
            $PrivilegedSPNCount = @($Findings | Where-Object { $_.IsPrivileged }).Count
            $PasswordNeverExpiresCount = @($Findings | Where-Object { $_.PasswordNeverExpires }).Count
            $OldPasswordCount = @(
    $Findings |
        Where-Object {
            $_.Enabled -and
            (
                $_.IsUser -or
                $_.IsManagedServiceAccount
            ) -and
            -not $_.IsKrbtgt -and
            $_.PasswordAgeDays -ge 1825
        }
).Count

            $CriticalCount = @($Findings | Where-Object { $_.Severity -eq "Critical" }).Count
            $HighCount     = @($Findings | Where-Object { $_.Severity -eq "High" }).Count
            $MediumCount   = @($Findings | Where-Object { $_.Severity -eq "Medium" }).Count
            $LowCount      = @($Findings | Where-Object { $_.Severity -eq "Low" }).Count

            $Severity = "Info"
            if ($LowCount -gt 0)      { $Severity = "Low" }
            if ($MediumCount -gt 0)   { $Severity = "Medium" }
            if ($HighCount -gt 0)     { $Severity = "High" }
            if ($CriticalCount -gt 0) { $Severity = "Critical" }

            if ($TotalSPNObjects -eq 0) {
                Add-WFLFinding `
                    -Title "Kerberos exposure review passed" `
                    -Severity "Info" `
                    -Category "Active Directory" `
                    -MITRE "T1558.001, T1558.002, T1558.003" `
                    -Tactic "Credential Access" `
                    -Source "AD-Kerberos-Exposure" `
                    -Evidence "No SPN-bearing AD objects found." `
                    -Recommendation "No action required."
                return
            }

            Add-WFLFinding `
                -Title "Kerberos service account exposure review" `
                -Severity $Severity `
                -Category "Active Directory" `
                -MITRE "T1558.001, T1558.002, T1558.003" `
                -Tactic "Credential Access" `
                -Source "AD-Kerberos-Exposure" `
                -Evidence "SPNObjects=$TotalSPNObjects; ActionableKerberoastCandidates=$ActionableKerberoastCount; UserSPNs=$UserSPNCount; ManagedServiceAccounts=$ManagedServiceAccountCount; ComputerSPNs=$ComputerSPNCount; PrivilegedSPNs=$PrivilegedSPNCount; PasswordNeverExpires=$PasswordNeverExpiresCount; UserOrServicePasswordsOver1825Days=$OldPasswordCount; Critical=$CriticalCount; High=$HighCount; Medium=$MediumCount; Low=$LowCount" `
                -Recommendation "Review SPN-bearing users, computer objects, and managed service accounts. Prioritize privileged accounts, Password Never Expires accounts, and weak Kerberos encryption settings."
        }
        catch {
            Add-WFLFinding `
                -Title "Kerberos exposure review failed" `
                -Severity "Info" `
                -Category "Active Directory" `
                -MITRE "T1558.001, T1558.002, T1558.003" `
                -Tactic "Credential Access" `
                -Source "AD-Kerberos-Exposure" `
                -Evidence $_.Exception.Message `
                -Recommendation "Verify Active Directory module availability and permissions to query SPN-bearing objects."
        }
    }


