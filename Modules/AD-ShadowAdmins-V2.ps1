Register-WFLModule `
    -Name "AD-ShadowAdmins-V2" `
    -Category "Active Directory" `
    -Type "Check" `
    -MITRE "T1098" `
    -Tactic "Persistence" `
    -Impact "POTENTIAL DOMAIN COMPROMISE" `
    -Description "Reviews dangerous delegated permissions on Tier-0 Active Directory objects using DirectoryServices ACL parsing." `
    -Remediation @{
        Module        = 'AD-ShadowAdmins-V2'
        Category      = 'Persistence / ACL Abuse'
        Type          = 'Specific'
        Description   = 'Identifies and strips dangerous explicit object control permissions (such as GenericAll, WriteDacl, WriteOwner, and ResetPassword) granted to non-standard principals on Tier-0 Active Directory objects (AdminSDHolder and privileged groups).'
        Impact        = 'Moderate. Removing unauthorized explicit ACEs neutralizes stealthy persistence and privilege escalation vectors, but verify that legitimate administrative delegation models are not disrupted.'
        VariableGuide = '$TargetDN: The Distinguished Name of the Tier-0 object (e.g., AdminSDHolder or Domain Admins) requiring ACL sanitization.'
        Code          = @'
$TargetDN = "CN=AdminSDHolder,CN=System,DC=corp,DC=local"
$Acl = Get-Acl "AD:\$TargetDN"
# Review explicit rules and remove unauthorized access control entries.
'@
    } -Run {

        if (-not $Global:WinFlesher.Context.ActiveDirectory.Available) {
            Add-WFLFinding `
                -Title "Shadow Admins V2 review unavailable" `
                -Severity "Info" `
                -Category "Active Directory" `
                -MITRE "T1098" `
                -Tactic "Persistence" `
                -Source "AD-ShadowAdmins-V2" `
                -Evidence "Active Directory discovery unavailable." `
                -Recommendation "Run from a domain-joined host with RSAT ActiveDirectory module."

            return
        }

        function New-WFLShadowTarget {
            param(
                [string]$Name,
                [string]$DistinguishedName,
                [string]$TargetType
            )

            [PSCustomObject]@{
                Name              = $Name
                DistinguishedName = $DistinguishedName
                TargetType        = $TargetType
            }
        }

        function Test-WFLTrustedIdentity {
            param(
                [string]$Identity
            )

            if ([string]::IsNullOrWhiteSpace($Identity)) {
                return $true
            }

            $TrustedPatterns = @(
                "NT AUTHORITY\SYSTEM",
                "BUILTIN\Administrators",
                "Domain Admins",
                "Enterprise Admins",
                "Schema Admins",
                "Domain Controllers",
                "Enterprise Domain Controllers",
                "CREATOR OWNER",
                "SELF",

                "Organization Management",
                "Exchange Trusted Subsystem",
                "Exchange Servers",

                "Key Admins",
                "Enterprise Key Admins",
                "Cert Publishers"
            )

            foreach ($Pattern in $TrustedPatterns) {
                if ($Identity -like "*$Pattern*") {
                    return $true
                }
            }

            return $false
        }

        function Get-WFLAclDanger {
            param(
                [object]$Rule
            )

            $DangerousRights = @()

            $Rights = [string]$Rule.ActiveDirectoryRights
            $ObjectType = [string]$Rule.ObjectType

            $ResetPasswordGuid = "00299570-246d-11d0-a768-00aa006e0529"
            $EmptyGuid         = "00000000-0000-0000-0000-000000000000"

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

            if ($Rights -match "ExtendedRight") {

                if ($ObjectType -eq $ResetPasswordGuid) {
                    $DangerousRights += "ResetPassword"
                }
                elseif ($ObjectType -eq $EmptyGuid) {
                    $DangerousRights += "AllExtendedRights"
                }
            }

            return $DangerousRights
        }

        function Get-WFLTargetAclIssues {
            param(
                [object]$Target
            )

            $Issues = @()

            try {
                $LdapPath = "LDAP://$($Target.DistinguishedName)"
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

                    if (Test-WFLTrustedIdentity -Identity $Identity) {
                        continue
                    }

                    $DangerousRights = @(Get-WFLAclDanger -Rule $Rule)

                    if ($DangerousRights.Count -eq 0) {
                        continue
                    }

                    $IsCriticalTarget = $Target.Name -in @(
                        "AdminSDHolder",
                        "Domain Admins",
                        "Enterprise Admins",
                        "Schema Admins"
                    )

                    $EffectiveSeverity = "Medium"

                    if ($DangerousRights -contains "GenericAll") {
                        $EffectiveSeverity = "High"
                    }

                    if (
                        $DangerousRights -contains "WriteDacl" -or
                        $DangerousRights -contains "WriteOwner"
                    ) {
                        $EffectiveSeverity = "High"
                    }

                    if (
                        $IsCriticalTarget -and
                        (
                            $DangerousRights -contains "GenericAll" -or
                            $DangerousRights -contains "WriteDacl" -or
                            $DangerousRights -contains "WriteOwner"
                        )
                    ) {
                        $EffectiveSeverity = "Critical"
                    }

                    $Issues += [PSCustomObject]@{
                        Identity          = $Identity
                        TargetName        = $Target.Name
                        TargetType        = $Target.TargetType
                        TargetDN          = $Target.DistinguishedName
                        Rights            = [string]$Rule.ActiveDirectoryRights
                        DangerousRights   = ($DangerousRights -join "; ")
                        ObjectType        = [string]$Rule.ObjectType
                        IsInherited       = [bool]$Rule.IsInherited
                        InheritanceType   = [string]$Rule.InheritanceType
                        EffectiveSeverity = $EffectiveSeverity
                    }
                }
            }
            catch {
                $Issues += [PSCustomObject]@{
                    Identity          = "ERROR"
                    TargetName        = $Target.Name
                    TargetType        = $Target.TargetType
                    TargetDN          = $Target.DistinguishedName
                    Rights            = "N/A"
                    DangerousRights   = "N/A"
                    ObjectType        = "N/A"
                    IsInherited       = $false
                    InheritanceType   = "N/A"
                    EffectiveSeverity = "Info"
                    Error             = $_.Exception.Message
                }
            }

            return $Issues
        }

        try {
            $Domain = Get-ADDomain
            $DomainDN = $Domain.DistinguishedName

            $Targets = @()

            $Targets += New-WFLShadowTarget `
                -Name "AdminSDHolder" `
                -DistinguishedName "CN=AdminSDHolder,CN=System,$DomainDN" `
                -TargetType "AdminSDHolder"

            $GroupNames = @(
                "Domain Admins",
                "Enterprise Admins",
                "Schema Admins"
            )

            foreach ($GroupName in $GroupNames) {
                try {
                    $Group = Get-ADGroup -Identity $GroupName -ErrorAction Stop

                    $Targets += New-WFLShadowTarget `
                        -Name $Group.Name `
                        -DistinguishedName $Group.DistinguishedName `
                        -TargetType "PrivilegedGroup"
                }
                catch {}
            }

            $BuiltinAdministratorsDN = "CN=Administrators,CN=Builtin,$DomainDN"

            $Targets += New-WFLShadowTarget `
                -Name "Administrators" `
                -DistinguishedName $BuiltinAdministratorsDN `
                -TargetType "BuiltinPrivilegedGroup"

            $AllIssues = @()

            foreach ($Target in $Targets) {
                $AllIssues += @(Get-WFLTargetAclIssues -Target $Target)
            }

            $ValidIssues = @(
                $AllIssues |
                Where-Object {
                    $_.DangerousRights -and
                    $_.EffectiveSeverity -ne "Info"
                }
            )

            $AclErrors = @(
                $AllIssues |
                Where-Object {
                    $_.PSObject.Properties.Name -contains "Error"
                }
            )

            Add-WFLDetail `
                -Name "AD-ShadowAdmins-V2" `
                -Data $ValidIssues

            Add-WFLDetail `
                -Name "AD-ShadowAdmins-V2-ACL-Errors" `
                -Data $AclErrors

            $CriticalCount = @(
                $ValidIssues |
                Where-Object { $_.EffectiveSeverity -eq "Critical" }
            ).Count

            $HighCount = @(
                $ValidIssues |
                Where-Object { $_.EffectiveSeverity -eq "High" }
            ).Count

            $MediumCount = @(
                $ValidIssues |
                Where-Object { $_.EffectiveSeverity -eq "Medium" }
            ).Count

            $Severity = "Info"

            if ($MediumCount -gt 0) {
                $Severity = "Medium"
            }

            if ($HighCount -gt 0) {
                $Severity = "High"
            }

            if ($CriticalCount -gt 0) {
                $Severity = "Critical"
            }

            if ($ValidIssues.Count -eq 0) {

                if ($AclErrors.Count -gt 0) {
                    Add-WFLFinding `
                        -Title "Shadow Admins V2 review incomplete" `
                        -Severity "Low" `
                        -Category "Active Directory" `
                        -MITRE "T1098" `
                        -Tactic "Persistence" `
                        -Source "AD-ShadowAdmins-V2" `
                        -Evidence "TargetsReviewed=$($Targets.Count); ShadowAdminPaths=0; AclErrors=$($AclErrors.Count)" `
                        -Recommendation "ACL review could not be completed for one or more Tier-0 objects. Review Show-WFLDetails -Name AD-ShadowAdmins-V2-ACL-Errors and verify LDAP bind permissions, object distinguished names and directory connectivity."
                    return
                }

                Add-WFLFinding `
                    -Title "Shadow Admins V2 review passed" `
                    -Severity "Info" `
                    -Category "Active Directory" `
                    -MITRE "T1098" `
                    -Tactic "Persistence" `
                    -Source "AD-ShadowAdmins-V2" `
                    -Evidence "TargetsReviewed=$($Targets.Count); ShadowAdminPaths=0; AclErrors=0" `
                    -Recommendation "No dangerous delegated permissions detected on reviewed Tier-0 objects."
                return
            }

            Add-WFLFinding `
                -Title "Shadow Admins V2 delegated privilege paths detected" `
                -Severity $Severity `
                -Category "Active Directory" `
                -MITRE "T1098" `
                -Tactic "Persistence" `
                -Source "AD-ShadowAdmins-V2" `
                -Evidence "TargetsReviewed=$($Targets.Count); ShadowAdminPaths=$($ValidIssues.Count); Critical=$CriticalCount; High=$HighCount; Medium=$MediumCount; AclErrors=$($AclErrors.Count)" `
                -Recommendation "Review non-standard principals with GenericAll, GenericWrite, WriteDacl, WriteOwner, ResetPassword or AllExtendedRights on Tier-0 objects. Use Show-WFLDetails -Name AD-ShadowAdmins-V2 for details."
        }
        catch {
            Add-WFLFinding `
                -Title "Shadow Admins V2 review failed" `
                -Severity "Info" `
                -Category "Active Directory" `
                -MITRE "T1098" `
                -Tactic "Persistence" `
                -Source "AD-ShadowAdmins-V2" `
                -Evidence $_.Exception.Message `
                -Recommendation "Verify Active Directory module, permissions and domain connectivity."
        }
    }