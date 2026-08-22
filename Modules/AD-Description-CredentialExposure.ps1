Register-WFLModule `
    -Name "AD-Description-CredentialExposure" `
    -Category "Active Directory" `
    -Type "Check" `
    -MITRE "T1552.001" `
    -Tactic "Credential Access" `
    -Impact "POTENTIAL CREDENTIAL COMPROMISE" `
    -Description "Reviews AD object descriptions for exposed passwords, default credentials, tokens or secrets." `
        -Remediation @{
        Module        = 'AD-Description-CredentialExposure'
        Category      = 'Credential Access'
        Type          = 'Specific'
        Description   = 'Scans Active Directory object descriptions, user notes, and info fields for leaked passwords, default keys, or tokens, clearing them upon detection.'
        Impact        = 'Low. Removing plain-text secrets from description attributes eliminates immediate credential harvesting risks.'
        VariableGuide = 'Automatic discovery targets objects matching regex patterns for passwords or keys in Description fields.'
        Code          = @'
Get-ADUser -Filter {Description -like "*pass*" -or Description -like "*pwd*"} -Properties Description | Set-ADUser -Description $null
'@
    } -Run {

        if (-not $Global:WinFlesher.Context.ActiveDirectory.Available) {
            Add-WFLFinding `
                -Title "AD description credential exposure review unavailable" `
                -Severity "Info" `
                -Category "Active Directory" `
                -MITRE "T1552.001" `
                -Tactic "Credential Access" `
                -Source "AD-Description-CredentialExposure" `
                -Evidence "Active Directory discovery unavailable." `
                -Recommendation "Run from a domain-joined host with RSAT ActiveDirectory module."
            return
        }

        try {

            function Get-WFLMaskedDescription {
                param(
                    [string]$Description
                )

                if ([string]::IsNullOrWhiteSpace($Description)) {
                    return $Description
                }

                $Masked = $Description

                $SecretPatterns = @(
                    '(?i)(password|passwd|pwd|pass|secret|token|apikey|api_key|api-key)\s*[:=,+-]\s*([^\s;,]{4,})',
                    '(?i)(user password)\s*[:=,+-]?\s*([^\s;,]{4,})',
                    '(?i)(defaultpassword|default password|changeme123!?)'
                )

                foreach ($Pattern in $SecretPatterns) {
                    $Masked = [regex]::Replace(
                        $Masked,
                        $Pattern,
                        {
                            param($Match)

                            if ($Match.Groups.Count -ge 3) {
                                return "$($Match.Groups[1].Value)=***MASKED***"
                            }

                            return "***MASKED_SECRET_HINT***"
                        }
                    )
                }

                return $Masked
            }

            function Get-WFLDescriptionSeverity {
                param(
                    [string]$ObjectClass,
                    [bool]$Enabled,
                    [bool]$IsPrivileged,
                    [bool]$HasExplicitSecret,
                    [bool]$HasDefaultPasswordHint
                )

                if ($IsPrivileged -and ($HasExplicitSecret -or $HasDefaultPasswordHint)) {
                    return "Critical"
                }

                if ($ObjectClass -eq "user" -and $Enabled -eq $true -and $HasExplicitSecret) {
                    return "High"
                }

                if ($ObjectClass -eq "user" -and $Enabled -eq $true -and $HasDefaultPasswordHint) {
                    return "High"
                }

                if ($HasExplicitSecret) {
                    return "Medium"
                }

                if ($HasDefaultPasswordHint) {
                    return "Medium"
                }

                return "Low"
            }

            $Objects = Get-ADObject `
                -LDAPFilter "(description=*)" `
                -Properties description,samAccountName,objectClass,userAccountControl,adminCount,distinguishedName `
                -ErrorAction Stop

            $Findings = @()

            $ExplicitSecretPattern  = '(?i)(password|passwd|pwd|secret|token|apikey|api[_-]?key)\s*[:=,+-]\s*([^\s;,]{3,})'
            $DefaultPasswordPattern = '(?i)(defaultpassword|default password|changeme123|tempPass\d*|Welcome123!?)'

            $SystemDNBlacklist = @(
                'CN=IP Security,CN=System,',
                'CN=Allowed RODC Password Replication Group,',
                'CN=Denied RODC Password Replication Group,',
                'CN=Windows Authorization Access Group,',
                'CN=Policies,CN=System,'
            )

            foreach ($Obj in $Objects) {

                $DN = [string]$Obj.DistinguishedName
                $Description = [string]$Obj.Description

                if ([string]::IsNullOrWhiteSpace($Description)) {
                    continue
                }

                $IsSystemObject = $false
                foreach ($Path in $SystemDNBlacklist) {
                    if ($DN -like "*$Path*") {
                        $IsSystemObject = $true
                        break
                    }
                }
                if ($IsSystemObject) { continue }

                $HasExplicitSecret = $Description -match $ExplicitSecretPattern
                $HasDefaultPasswordHint = $Description -match $DefaultPasswordPattern

                if (-not $HasExplicitSecret -and -not $HasDefaultPasswordHint) {
                    continue
                }

                $ObjectClass = [string]$Obj.ObjectClass
                $SamAccountName = [string]$Obj.samAccountName

                if ([string]::IsNullOrWhiteSpace($SamAccountName)) {
                    $SamAccountName = [string]$Obj.Name
                }

                $UserAccountControl = 0
                if ($null -ne $Obj.userAccountControl) {
                    $UserAccountControl = [int]$Obj.userAccountControl
                }

                $Enabled = $null
                if ($UserAccountControl -ne 0) {
                    $Enabled = (($UserAccountControl -band 2) -eq 0)
                }

                $AdminCount = 0
                if ($null -ne $Obj.adminCount) {
                    $AdminCount = [int]$Obj.adminCount
                }

                $IsPrivileged = ($AdminCount -eq 1)

                $PasswordLastSet = $null
                if ($ObjectClass -eq "user" -or $ObjectClass -eq "computer") {
                    try {
                        $ADAcc = Get-ADObject -Identity $DN -Properties passwordLastSet -ErrorAction SilentlyContinue
                        if ($ADAcc) {
                            $PasswordLastSet = $ADAcc.passwordLastSet
                        }
                    } catch { }
                }

                $Severity = Get-WFLDescriptionSeverity `
                    -ObjectClass $ObjectClass `
                    -Enabled ([bool]$Enabled) `
                    -IsPrivileged ([bool]$IsPrivileged) `
                    -HasExplicitSecret ([bool]$HasExplicitSecret) `
                    -HasDefaultPasswordHint ([bool]$HasDefaultPasswordHint)

                $Exploitability = "Potential"
                if ($Severity -eq "Critical" -or $Severity -eq "High") {
                    $Exploitability = "Likely"
                }
                if ($Enabled -eq $false) {
                    $Exploitability = "Conditional"
                }

                $RiskReasons = @()
                if ($HasExplicitSecret) {
                    $RiskReasons += "Explicit credential-like value in description"
                }
                if ($HasDefaultPasswordHint) {
                    $RiskReasons += "Default password hint in description"
                }
                if ($IsPrivileged) {
                    $RiskReasons += "AdminCount privileged object"
                }
                if ($ObjectClass -eq "user" -and $Enabled -eq $true) {
                    $RiskReasons += "Enabled user object"
                }
                if ($ObjectClass -eq "user" -and $Enabled -eq $false) {
                    $RiskReasons += "Disabled user object"
                }

                $Findings += [PSCustomObject]@{
                    Name                   = [string]$Obj.Name
                    SamAccountName         = $SamAccountName
                    ObjectClass            = $ObjectClass
                    DistinguishedName      = $DN
                    Enabled                = $Enabled
                    AdminCount             = $AdminCount
                    IsPrivileged           = $IsPrivileged
                    PasswordLastSet        = $PasswordLastSet
                    HasExplicitSecret      = $HasExplicitSecret
                    HasDefaultPasswordHint = $HasDefaultPasswordHint
                    DescriptionMasked      = Get-WFLMaskedDescription -Description $Description
                    Severity               = $Severity
                    Exploitability         = $Exploitability
                    RiskReason             = ($RiskReasons -join "; ")
                }
            }

            Add-WFLDetail `
                -Name "AD-Description-CredentialExposure" `
                -Data $Findings

            $CriticalCount = @($Findings | Where-Object { $_.Severity -eq "Critical" }).Count
            $HighCount     = @($Findings | Where-Object { $_.Severity -eq "High" }).Count
            $MediumCount   = @($Findings | Where-Object { $_.Severity -eq "Medium" }).Count
            $LowCount      = @($Findings | Where-Object { $_.Severity -eq "Low" }).Count

            $ExplicitSecretCount = @($Findings | Where-Object { $_.HasExplicitSecret -eq $true }).Count
            $DefaultHintCount    = @($Findings | Where-Object { $_.HasDefaultPasswordHint -eq $true }).Count

            $Severity = "Info"
            if ($LowCount -gt 0)      { $Severity = "Low" }
            if ($MediumCount -gt 0)   { $Severity = "Medium" }
            if ($HighCount -gt 0)     { $Severity = "High" }
            if ($CriticalCount -gt 0) { $Severity = "Critical" }

            if ($Findings.Count -eq 0) {
                Add-WFLFinding `
                    -Title "AD description credential exposure review passed" `
                    -Severity "Info" `
                    -Category "Active Directory" `
                    -MITRE "T1552.001" `
                    -Tactic "Credential Access" `
                    -Source "AD-Description-CredentialExposure" `
                    -Evidence "ObjectsWithCredentialHints=0" `
                    -Recommendation "No credential-like values were detected in AD object descriptions."
                return
            }

            Add-WFLFinding `
                -Title "Credential-like values found in AD object descriptions" `
                -Severity $Severity `
                -Category "Active Directory" `
                -MITRE "T1552.001" `
                -Tactic "Credential Access" `
                -Source "AD-Description-CredentialExposure" `
                -Evidence "ObjectsWithCredentialHints=$($Findings.Count); ExplicitSecrets=$ExplicitSecretCount; DefaultPasswordHints=$DefaultHintCount; Critical=$CriticalCount; High=$HighCount; Medium=$MediumCount; Low=$LowCount" `
                -Recommendation "Remove passwords, default password hints, tokens and secrets from AD object descriptions. Rotate any exposed credentials and review enabled users first."

        }
        catch {
            Add-WFLFinding `
                -Title "AD description credential exposure review failed" `
                -Severity "Info" `
                -Category "Active Directory" `
                -MITRE "T1552.001" `
                -Tactic "Credential Access" `
                -Source "AD-Description-CredentialExposure" `
                -Evidence $_.Exception.Message `
                -Recommendation "Verify Active Directory module availability and permissions to query object descriptions."
        }
    }


