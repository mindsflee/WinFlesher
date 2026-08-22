Register-WFLModule `
    -Name "AD-Group-Control-Paths" `
    -Category "Active Directory" `
    -Type "Check" `
    -MITRE "T1098" `
    -Tactic "Persistence / Privilege Escalation" `
    -Impact "POTENTIAL DOMAIN COMPROMISE" `
    -Description "Reviews dangerous delegated permissions over privileged Active Directory groups." `
        -Remediation @{
        Module        = 'AD-Group-Control-Paths'
        Category      = 'Persistence / Privilege Escalation'
        Type          = 'Specific'
        Description   = 'Removes dangerous object control rights (GenericAll, WriteDacl, WriteOwner) held by non-privileged users over Tier-0 security groups.'
        Impact        = 'Low to Moderate. Hardening group ACLs closes critical attack paths leading directly to domain compromise.'
        VariableGuide = '$GroupName: The privileged Active Directory group (e.g., "Domain Admins").'
        Code          = @'
'@
    } -Run {

        if (-not $Global:WinFlesher.Context.ActiveDirectory.Available) {
            return
        }

        try {

            function Test-WFLTrustedGroupAclIdentity {
                param(
                    [string]$Identity
                )

                if ([string]::IsNullOrWhiteSpace($Identity)) {
                    return $true
                }
$TrustedSids = @(
    "S-1-5-32-544", # Administrators
    "S-1-5-32-548", # Account Operators
    "S-1-5-32-549", # Server Operators
    "S-1-5-32-550", # Print Operators
    "S-1-5-32-551"  # Backup Operators
)

if ($Identity -in $TrustedSids) {
    return $true
}

if ($Identity -match '^S-1-5-21-') {
    return $false
}

              $TrustedPatterns = @(
    "NT AUTHORITY\SYSTEM",
    "BUILTIN\Administrators",
    "Domain Admins",
    "Enterprise Admins",
    "Schema Admins",
    "Administrators",
    "Account Operators",
    "Server Operators",
    "Backup Operators",
    "Print Operators",
    "CREATOR OWNER",
    "SELF",

    "Organization Management",
    "Exchange Servers",
    "Exchange Trusted Subsystem",
    "Exchange Windows Permissions",
    "Recipient Management",
    "Recipient Management EMT-",

    "MSOL_"
)

                foreach ($Pattern in $TrustedPatterns) {
                    if ($Identity -like "*$Pattern*") {
                        return $true
                    }
                }

                return $false
            }

            function Get-WFLPrincipalType {
                param(
                    [string]$Identity
                )

                if ($Identity -match '^S-1-5-') {
                    return "UnresolvedSID"
                }

                if ($Identity -match '\$$') {
                    return "Computer"
                }

                return "UserOrGroup"
            }

            function Get-WFLGroupControlRights {
                param(
                    [object]$Rule
                )

                $DangerousRights = @()

                $Rights = [string]$Rule.ActiveDirectoryRights
                $ObjectType = [string]$Rule.ObjectType

                $MemberAttributeGuid = "bf9679c0-0de6-11d0-a285-00aa003049e2"
                $EmptyGuid = "00000000-0000-0000-0000-000000000000"

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
    $ObjectType -eq $MemberAttributeGuid
) {
    $DangerousRights += "WriteMembers"
}
                if (
                    $Rights -match "Self" -and
                    $ObjectType -eq $MemberAttributeGuid
                ) {
                    $DangerousRights += "SelfMembership"
                }

                return $DangerousRights
            }

            function Get-WFLGroupFindingClass {
                param(
                    [string[]]$DangerousRights
                )

                if (
                    $DangerousRights -contains "GenericAll" -or
                    $DangerousRights -contains "WriteDacl" -or
                    $DangerousRights -contains "WriteOwner"
                ) {
                    return "FullGroupControl"
                }

                if ($DangerousRights -contains "WriteMembers") {
                    return "MembershipControl"
                }

                if ($DangerousRights -contains "GenericWrite") {
                    return "GenericWriteControl"
                }

                if ($DangerousRights -contains "SelfMembership") {
                    return "SelfMembershipControl"
                }

                return "OtherControl"
            }

            function Get-WFLGroupControlSeverity {
                param(
                    [bool]$IsTier0,
                    [string]$FindingClass,
                    [string]$PrincipalType
                )

                if ($FindingClass -eq "FullGroupControl") {
                    if ($IsTier0) {
                        return "Critical"
                    }

                    return "High"
                }

                if ($FindingClass -eq "MembershipControl") {
                    if ($IsTier0) {
                        return "Critical"
                    }

                    return "High"
                }

                if ($FindingClass -eq "GenericWriteControl") {
                    if ($IsTier0) {
                        return "High"
                    }

                    return "Medium"
                }

                if ($FindingClass -eq "SelfMembershipControl") {
                    if ($IsTier0) {
                        return "High"
                    }

                    return "Medium"
                }

                return "Medium"
            }

            $Tier0Groups = @(
                "Domain Admins",
                "Enterprise Admins",
                "Schema Admins",
                "Administrators"
            )

            $PrivilegedGroups = @(
                "Domain Admins",
                "Enterprise Admins",
                "Schema Admins",
                "Administrators",
                "Account Operators",
                "Server Operators",
                "Backup Operators",
                "Print Operators",
                "DnsAdmins",
                "Group Policy Creator Owners",
                "Cert Publishers",
                "Key Admins",
                "Enterprise Key Admins"
            )

           $Targets = @()
$TargetErrors = @()
$Findings = @()
$AclErrors = @()

$SeenFindings = @{}

			
			            foreach ($GroupName in $PrivilegedGroups) {

                try {
                    $Group = Get-ADGroup `
                        -Identity $GroupName `
                        -Properties DistinguishedName,GroupScope,GroupCategory `
                        -ErrorAction Stop

                    $IsTier0 = $false
                    if ($GroupName -in $Tier0Groups) {
                        $IsTier0 = $true
                    }

                    $Targets += [PSCustomObject]@{
                        Name              = $Group.Name
                        DistinguishedName = $Group.DistinguishedName
                        GroupScope        = $Group.GroupScope
                        GroupCategory     = $Group.GroupCategory
                        IsTier0           = $IsTier0
                    }
                }
                catch {
                    $TargetErrors += [PSCustomObject]@{
                        GroupName = $GroupName
                        Error     = $_.Exception.Message
                    }
                }
            }

            foreach ($Target in $Targets) {

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

                        if (Test-WFLTrustedGroupAclIdentity -Identity $Identity) {
                            continue
                        }

                        $DangerousRights = @(
                            Get-WFLGroupControlRights -Rule $Rule
                        )

                        if ($DangerousRights.Count -eq 0) {
                            continue
                        }

                        $PrincipalType = Get-WFLPrincipalType -Identity $Identity

                        $FindingClass = Get-WFLGroupFindingClass `
                            -DangerousRights $DangerousRights

                        $Severity = Get-WFLGroupControlSeverity `
                            -IsTier0 ([bool]$Target.IsTier0) `
                            -FindingClass $FindingClass `
                            -PrincipalType $PrincipalType

                        $Exploitability = "Potential"

                        if (
                            $Severity -eq "Critical" -or
                            $Severity -eq "High"
                        ) {
                            $Exploitability = "Likely"
                        }

                        if ($PrincipalType -eq "Computer") {
                            $Exploitability = "Conditional"
                        }

$FindingKey = "$($Target.Name)|$Identity|$FindingClass|$($DangerousRights -join ',')|$($Rule.ObjectType)"

if ($SeenFindings.ContainsKey($FindingKey))
{
    continue
}

$SeenFindings[$FindingKey] = $true

                        $Findings += [PSCustomObject]@{
                            GroupName        = $Target.Name
                            GroupDN          = $Target.DistinguishedName
                            IsTier0          = [bool]$Target.IsTier0
                            Identity         = $Identity
                            PrincipalType    = $PrincipalType
                            FindingClass     = $FindingClass
                            Rights           = [string]$Rule.ActiveDirectoryRights
                            DangerousRights  = ($DangerousRights -join "; ")
                            ObjectType       = [string]$Rule.ObjectType
                            IsInherited      = [bool]$Rule.IsInherited
                            InheritanceType  = [string]$Rule.InheritanceType
                            Severity         = $Severity
                            Exploitability   = $Exploitability
                        }
                    }
                }
                catch {
                    $AclErrors += [PSCustomObject]@{
                        GroupName = $Target.Name
                        GroupDN   = $Target.DistinguishedName
                        Error     = $_.Exception.Message
                    }
                }
            }

            Add-WFLDetail `
                -Name "AD-Group-Control-Paths" `
                -Data $Findings

            Add-WFLDetail `
                -Name "AD-Group-Control-Paths-Targets" `
                -Data $Targets

            Add-WFLDetail `
                -Name "AD-Group-Control-Paths-Target-Errors" `
                -Data $TargetErrors

            Add-WFLDetail `
                -Name "AD-Group-Control-Paths-ACL-Errors" `
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

            if (
                $Findings.Count -eq 0 -and
                $AclErrors.Count -gt 0
            ) {
                Add-WFLFinding `
                    -Title "Privileged group control path review incomplete" `
                    -Severity "Low" `
                    -Category "Active Directory" `
                    -MITRE "T1098" `
                    -Tactic "Persistence / Privilege Escalation" `
                    -Source "AD-Group-Control-Paths" `
                    -Evidence "GroupsReviewed=$($Targets.Count); ControlPaths=0; AclErrors=$($AclErrors.Count); TargetErrors=$($TargetErrors.Count)" `
                    -Recommendation "Review Show-WFLDetails -Name AD-Group-Control-Paths-ACL-Errors and AD-Group-Control-Paths-Target-Errors."

                return
            }

            if ($Findings.Count -eq 0) {
                Add-WFLFinding `
                    -Title "Privileged group control path review passed" `
                    -Severity "Info" `
                    -Category "Active Directory" `
                    -MITRE "T1098" `
                    -Tactic "Persistence / Privilege Escalation" `
                    -Source "AD-Group-Control-Paths" `
                    -Evidence "GroupsReviewed=$($Targets.Count); ControlPaths=0; AclErrors=$($AclErrors.Count); TargetErrors=$($TargetErrors.Count)" `
                    -Recommendation "No dangerous delegated control permissions detected on reviewed privileged groups."

                return
            }

            Add-WFLFinding `
                -Title "Privileged group control paths detected" `
                -Severity $Severity `
                -Category "Active Directory" `
                -MITRE "T1098" `
                -Tactic "Persistence / Privilege Escalation" `
                -Source "AD-Group-Control-Paths" `
                -Evidence "GroupsReviewed=$($Targets.Count); ControlPaths=$($Findings.Count); Critical=$CriticalCount; High=$HighCount; Medium=$MediumCount; AclErrors=$($AclErrors.Count); TargetErrors=$($TargetErrors.Count)" `
                -Recommendation "Review non-standard principals with GenericAll, WriteDacl, WriteOwner, GenericWrite, WriteMembers or SelfMembership permissions over privileged groups. Prioritize Tier-0 groups first."

        }
        catch {

            Add-WFLFinding `
                -Title "Privileged group control path review failed" `
                -Severity "Info" `
                -Category "Active Directory" `
                -MITRE "T1098" `
                -Tactic "Persistence / Privilege Escalation" `
                -Source "AD-Group-Control-Paths" `
                -Evidence $_.Exception.Message `
                -Recommendation "Verify Active Directory module availability, LDAP connectivity and permissions."
        }
    }


