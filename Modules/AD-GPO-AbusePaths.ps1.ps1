Register-WFLModule `
    -Name "AD-GPO-AbusePaths" `
    -Category "Active Directory" `
    -Type "Check" `
    -MITRE "T1484.001" `
    -Tactic "Defense Evasion / Privilege Escalation" `
    -Impact "POTENTIAL PRIVILEGE ESCALATION" `
    -Description "Reviews dangerous delegated permissions on Group Policy Objects." `
        -Remediation @{
        Module        = 'AD-GPO-AbusePaths.ps1'
        Category      = 'Active Directory Security'
        Type          = 'Specific'
        Description   = 'Restore standard GPO ACLs and eliminate unauthorized modification permissions.'
        Impact        = 'Prevents unauthorized tampering with critical Group Policy Objects by non-privileged users.'
        VariableGuide = 'Use [GUID_GPO] and [Name_DC] retrieved from the assessment context.'
        Code          = @'
Import-Module GroupPolicy
$gpoGuid = "[GUID_GPO]"
$gpoPath = "CN={$gpoGuid},CN=Policies,CN=System,DC=dominio,DC=local"
$acl = Get-Acl "AD:\$gpoPath"
Set-Acl -Path "AD:\$gpoPath" -AclObject $acl
Write-Host "[+] GPO $gpoGuid ACLs successfully restored to security baselines." -ForegroundColor Green
'@
    } -Run {

        if (-not $Global:WinFlesher.Context.ActiveDirectory.Available) {
            return
        }

        try {

            function Test-WFLTrustedGpoIdentity {
                param(
                    [string]$Identity
                )

                if ([string]::IsNullOrWhiteSpace($Identity)) {
                    return $true
                }
if ($Identity -match '^S-1-5-') {
    return $false
}

                $TrustedPatterns = @(
                    "NT AUTHORITY\SYSTEM",
                    "BUILTIN\Administrators",
                    "Domain Admins",
                    "Enterprise Admins",
                    "Schema Admins",
                    "Group Policy Creator Owners",
                    "CREATOR OWNER",
                    "SELF"
                )

                foreach ($Pattern in $TrustedPatterns) {
    if ($Identity -like "*$Pattern*") {
        return $true
    }
}

if ($Identity -match '\$$') {
    return $true
}

return $false
			}

            function Get-WFLGpoDangerousRights {
                param(
                    [object]$Rule
                )

                $DangerousRights = @()

                $Rights = [string]$Rule.ActiveDirectoryRights

                if ($Rights -match "GenericAll") {
                    $DangerousRights += "GenericAll"
                }

                if ($Rights -match "GenericWrite") {
                    $DangerousRights += "GenericWrite"
                }

                if ($Rights -match "WriteDacl") {
                    $DangerousRights += "WriteDacl"
                }

                if ($Rights -match "WriteOwner") {
                    $DangerousRights += "WriteOwner"
                }

               if (
    $Rights -match "WriteProperty" -and
    $Rights -notmatch "ReadProperty"
)
{
    $DangerousRights += "WriteProperty"
}

                return $DangerousRights
            }

            function Get-WFLGpoSeverity {
                param(
                    [string[]]$DangerousRights
                )

               if (
    $DangerousRights -contains "GenericAll" -or
    $DangerousRights -contains "WriteDacl" -or
    $DangerousRights -contains "WriteOwner"
) {
    return "Critical"
}

                if (
                    $DangerousRights -contains "GenericWrite" -or
                    $DangerousRights -contains "WriteProperty"
                ) {
                    return "Medium"
                }

                return "Low"
            }

            $Domain = Get-ADDomain
            $DomainDN = $Domain.DistinguishedName

            $GpoObjects = Get-ADObject `
                -LDAPFilter "(objectClass=groupPolicyContainer)" `
                -SearchBase "CN=Policies,CN=System,$DomainDN" `
                -Properties displayName `
                -ErrorAction Stop

            $Findings = @()
            $AclErrors = @()
			
			            foreach ($Gpo in $GpoObjects) {

                try {

                    $GpoName = $Gpo.DisplayName
                    $GpoDN   = $Gpo.DistinguishedName

                    $LdapPath = "LDAP://$GpoDN"

                    $Entry = New-Object System.DirectoryServices.DirectoryEntry($LdapPath)
                    $Security = $Entry.ObjectSecurity

                    $Rules = $Security.GetAccessRules(
                        $true,
                        $true,
                        [System.Security.Principal.NTAccount]
                    )

                    foreach ($Rule in $Rules) {

                        if ([string]$Rule.AccessControlType -ne "Allow") {
                            continue
                        }

                        $Identity = [string]$Rule.IdentityReference

                        if (Test-WFLTrustedGpoIdentity -Identity $Identity) {
                            continue
                        }

                        $DangerousRights = @(
                            Get-WFLGpoDangerousRights -Rule $Rule
                        )

                        if ($DangerousRights.Count -eq 0) {
                            continue
                        }

                        $Severity = Get-WFLGpoSeverity `
                            -DangerousRights $DangerousRights

                        $Exploitability = "Potential"

                        if ($Severity -eq "High") {
                            $Exploitability = "Likely"
                        }

          $PrincipalType = if ($Identity -match '^S-1-5-') {
    "UnresolvedSID"
} elseif ($Identity -match '\$$') {
    "Computer"
} else {
    "UserOrGroup"
}

$PrincipalType = if ($Identity -match '^S-1-5-') {
    "UnresolvedSID"
} elseif ($Identity -match '\$$') {
    "Computer"
} else {
    "UserOrGroup"
}

$FindingClass = if (
    $DangerousRights -contains "GenericAll" -or
    $DangerousRights -contains "WriteDacl" -or
    $DangerousRights -contains "WriteOwner"
) {
    "FullGPOControl"
} elseif ($DangerousRights -contains "GenericWrite") {
    "PartialGPOControl"
} else {
    "PropertyControl"
}

$Findings += [PSCustomObject]@{
    GPOName         = $GpoName
    GPODN           = $GpoDN
    Identity        = $Identity
    PrincipalType   = $PrincipalType
    Rights          = [string]$Rule.ActiveDirectoryRights
    DangerousRights = ($DangerousRights -join "; ")
    FindingClass    = $FindingClass
    ObjectType      = [string]$Rule.ObjectType
    IsInherited     = [bool]$Rule.IsInherited
    InheritanceType = [string]$Rule.InheritanceType
    Severity        = $Severity
    Exploitability  = $Exploitability
}
					}


                }
                catch {

                    $AclErrors += [PSCustomObject]@{
                        GPOName = $Gpo.DisplayName
                        GPODN   = $Gpo.DistinguishedName
                        Error   = $_.Exception.Message
                    }
                }
            }

            Add-WFLDetail `
                -Name "AD-GPO-AbusePaths" `
                -Data $Findings

            Add-WFLDetail `
                -Name "AD-GPO-AbusePaths-ACL-Errors" `
                -Data $AclErrors

            $CriticalCount = @(
                $Findings | Where-Object {
                    $_.Severity -eq "Critical"
                }
            ).Count

            $HighCount = @(
                $Findings | Where-Object {
                    $_.Severity -eq "High"
                }
            ).Count

            $MediumCount = @(
                $Findings | Where-Object {
                    $_.Severity -eq "Medium"
                }
            ).Count

            $LowCount = @(
                $Findings | Where-Object {
                    $_.Severity -eq "Low"
                }
            ).Count

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

            if (
                $Findings.Count -eq 0 -and
                $AclErrors.Count -gt 0
            ) {

                Add-WFLFinding `
                    -Title "GPO abuse path review incomplete" `
                    -Severity "Low" `
                    -Category "Active Directory" `
                    -MITRE "T1484.001" `
                    -Tactic "Defense Evasion / Privilege Escalation" `
                    -Source "AD-GPO-AbusePaths" `
                    -Evidence "GPOsReviewed=$($GpoObjects.Count); DangerousDelegations=0; AclErrors=$($AclErrors.Count)" `
                    -Recommendation "Review Show-WFLDetails -Name AD-GPO-AbusePaths-ACL-Errors."

                return
            }

            if ($Findings.Count -eq 0) {

                Add-WFLFinding `
                    -Title "GPO abuse path review passed" `
                    -Severity "Info" `
                    -Category "Active Directory" `
                    -MITRE "T1484.001" `
                    -Tactic "Defense Evasion / Privilege Escalation" `
                    -Source "AD-GPO-AbusePaths" `
                    -Evidence "GPOsReviewed=$($GpoObjects.Count); DangerousDelegations=0; AclErrors=$($AclErrors.Count)" `
                    -Recommendation "No dangerous delegated GPO control permissions detected."

                return
            }

            Add-WFLFinding `
                -Title "GPO abuse paths detected" `
                -Severity $Severity `
                -Category "Active Directory" `
                -MITRE "T1484.001" `
                -Tactic "Defense Evasion / Privilege Escalation" `
                -Source "AD-GPO-AbusePaths" `
                -Evidence "GPOsReviewed=$($GpoObjects.Count); DangerousDelegations=$($Findings.Count); Critical=$CriticalCount; High=$HighCount; Medium=$MediumCount; Low=$LowCount; AclErrors=$($AclErrors.Count)" `
                -Recommendation "Review non-standard principals with GenericAll, GenericWrite, WriteDacl, WriteOwner or WriteProperty on Group Policy Objects."

        }
        catch {

            Add-WFLFinding `
                -Title "GPO abuse path review failed" `
                -Severity "Info" `
                -Category "Active Directory" `
                -MITRE "T1484.001" `
                -Tactic "Defense Evasion / Privilege Escalation" `
                -Source "AD-GPO-AbusePaths" `
                -Evidence $_.Exception.Message `
                -Recommendation "Verify Active Directory module availability and permissions."
        }
    }


