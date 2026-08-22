Register-WFLModule `
    -Name "AD-ComputerObject-Abuse" `
    -Category "Active Directory" `
    -Type "Check" `
    -MITRE "T1098" `
    -Tactic "Privilege Escalation / Lateral Movement" `
    -Impact "POTENTIAL PRIVILEGE ESCALATION" `
    -Description "Reviews dangerous delegated permissions on Active Directory computer objects." `
        -Remediation @{
        Module        = 'AD-ComputerObject-Abuse'
        Category      = 'Privilege Escalation'
        Type          = 'Specific'
        Description   = 'Reviews and cleans up dangerous delegated write or control permissions on Active Directory computer objects.'
        Impact        = 'Low. Removing excessive object control permissions stops lateral movement pathways without affecting standard computer domain trust operations.'
        VariableGuide = '$ComputerName: The target computer account name exhibiting risky delegations.'
        Code          = @'
'@
    } -Run {

        if (-not $Global:WinFlesher.Context.ActiveDirectory.Available) {
            return
        }

        try {

            function Test-WFLTrustedComputerIdentity {
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

if ($Identity -in $TrustedSids)
{
    return $true
}

                $TrustedPatterns = @(
                    "NT AUTHORITY\SYSTEM",
                    "BUILTIN\Administrators",
                    "Domain Admins",
                    "Enterprise Admins",
                    "Schema Admins",
                    "Administrators",
                    "Exchange Trusted Subsystem",
                    "Exchange Windows Permissions",
                    "Exchange Servers",
                    "Organization Management",
					"Recipient Management",
					"Recipient Management EMT-",
                    "SELF",
                    "CREATOR OWNER",
                    "MSOL_"
                )

                foreach ($Pattern in $TrustedPatterns) {
                    if ($Identity -like "*$Pattern*") {
                        return $true
                    }
                }
if ($Identity -match '\$$')
{
    return $true
}
                return $false
            }

            function Get-WFLComputerPrincipalType {
                param(
                    [string]$Identity
                )

               if ($Identity -match '^S-1-5-21-')
{
    return "UnresolvedSID"
}


                if ($Identity -match '\$$') {
                    return "Computer"
                }

                return "UserOrGroup"
            }

            function Get-WFLComputerDangerousRights {
                param(
                    [object]$Rule
                )

                $DangerousRights = @()

                $ObjectType = [string]$Rule.ObjectType
                $Rights = [string]$Rule.ActiveDirectoryRights

                $ResetPasswordGuid = "00299570-246d-11d0-a768-00aa006e0529"
                $RBCDGuid          = "3f78c3e5-f79a-46bd-a0b8-9d18116ddc79"
                $SPNGuid           = "f3a64788-5306-11d1-a9c5-0000f80367c1"

                if ($Rights -match "GenericAll") {
                    $DangerousRights += "GenericAll"
                }


                if ($Rights -match "WriteDacl") {
                    $DangerousRights += "WriteDacl"
                }

                if ($Rights -match "WriteOwner") {
                    $DangerousRights += "WriteOwner"
                }

                if (
                    $Rights -match "ExtendedRight" -and
                    $ObjectType -eq $ResetPasswordGuid
                )
                {
                    $DangerousRights += "ResetPassword"
                }

                if (
                    $Rights -match "WriteProperty" -and
                    $ObjectType -eq $SPNGuid
                )
                {
                    $DangerousRights += "WriteSPN"
                }

                if (
                    $Rights -match "WriteProperty" -and
                    $ObjectType -eq $RBCDGuid
                )
                {
                    $DangerousRights += "WriteRBCD"
                }

                return $DangerousRights
            }

            function Get-WFLComputerFindingClass {
                param(
                    [string[]]$DangerousRights
                )

                if (
                    $DangerousRights -contains "GenericAll" -or
                    $DangerousRights -contains "WriteDacl" -or
                    $DangerousRights -contains "WriteOwner"
                )
                {
                    return "FullComputerControl"
                }

                if ($DangerousRights -contains "WriteRBCD")
                {
                    return "RBCDControl"
                }

                if ($DangerousRights -contains "WriteSPN")
                {
                    return "SPNControl"
                }

                if ($DangerousRights -contains "ResetPassword")
                {
                    return "PasswordReset"
                }

                if ($DangerousRights -contains "GenericWrite")
                {
                    return "GenericWrite"
                }

                return "Other"
            }

         
		 function Get-WFLComputerSeverity {
    param(
        [bool]$IsDomainController,
        [string]$FindingClass,
        [string]$OperatingSystem
    )

    if ($IsDomainController)
    {
        switch ($FindingClass)
        {
            "FullComputerControl" { return "Critical" }
            "RBCDControl"         { return "Critical" }
            "PasswordReset"       { return "Critical" }
            default               { return "High" }
        }
    }

    if ($OperatingSystem -match "Server")
    {
        switch ($FindingClass)
        {
            "FullComputerControl" { return "High" }
            "RBCDControl"         { return "High" }
            "PasswordReset"       { return "High" }
            "SPNControl"          { return "Medium" }
            default               { return "Medium" }
        }
    }

    switch ($FindingClass)
    {
        "FullComputerControl" { return "Medium" }
        "RBCDControl"         { return "Medium" }
        "PasswordReset"       { return "Medium" }
        "SPNControl"          { return "Low" }
        default               { return "Low" }
    }
}
		 
		 
            

            $Computers = Get-ADComputer `
                -Filter * `
                -Properties DNSHostName,OperatingSystem,PrimaryGroupID `
                -ErrorAction Stop

            $Findings = @()
            $AclErrors = @()
			
			            foreach ($Computer in $Computers) {

                try {

                    $ComputerName = $Computer.Name
                    $ComputerDN   = $Computer.DistinguishedName

                    $IsDomainController = $false
                    if ($Computer.PrimaryGroupID -eq 516) {
                        $IsDomainController = $true
                    }
				

                    $LdapPath = "LDAP://$ComputerDN"

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

                        if (Test-WFLTrustedComputerIdentity -Identity $Identity) {
                            continue
                        }

                        $DangerousRights = @(
                            Get-WFLComputerDangerousRights -Rule $Rule
                        )

                        if ($DangerousRights.Count -eq 0) {
                            continue
                        }
if ($Rule.IsInherited) {
    continue
}

                        $PrincipalType = Get-WFLComputerPrincipalType -Identity $Identity

                        $FindingClass = Get-WFLComputerFindingClass `
                            -DangerousRights $DangerousRights

                        $Severity = Get-WFLComputerSeverity `
    -IsDomainController ([bool]$IsDomainController) `
    -FindingClass $FindingClass `
    -OperatingSystem $Computer.OperatingSystem

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
						
						$AssetClass = "Workstation"
$HighValueAsset = $false

if ($IsDomainController)
{
    $AssetClass = "DomainController"
    $HighValueAsset = $true
}
elseif ($Computer.OperatingSystem -match "Server")
{
    $AssetClass = "Server"
    $HighValueAsset = $true
}

$AssetClass = "Workstation"

if ($IsDomainController)
{
    $AssetClass = "DomainController"
}
elseif ($Computer.OperatingSystem -match "Server")
{
    $AssetClass = "Server"
}



                        $Findings += [PSCustomObject]@{
                            ComputerName       = $ComputerName
                            ComputerDN         = $ComputerDN
                            DNSHostName        = $Computer.DNSHostName
                            OperatingSystem    = $Computer.OperatingSystem
							AssetClass = $AssetClass
							HighValueAsset = $HighValueAsset
                            IsDomainController = [bool]$IsDomainController
                            Identity           = $Identity
                            PrincipalType      = $PrincipalType
                            FindingClass       = $FindingClass
                            Rights             = [string]$Rule.ActiveDirectoryRights
                            DangerousRights    = ($DangerousRights -join "; ")
                            ObjectType         = [string]$Rule.ObjectType
                            IsInherited        = [bool]$Rule.IsInherited
                            InheritanceType    = [string]$Rule.InheritanceType
                            Severity           = $Severity
                            Exploitability     = $Exploitability
                        }
                    }
                }
                catch {

                    $AclErrors += [PSCustomObject]@{
                        ComputerName = $Computer.Name
                        ComputerDN   = $Computer.DistinguishedName
                        Error        = $_.Exception.Message
                    }
                }
            }

            Add-WFLDetail `
                -Name "AD-ComputerObject-Abuse" `
                -Data $Findings

            Add-WFLDetail `
                -Name "AD-ComputerObject-Abuse-ACL-Errors" `
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
                    -Title "Computer object abuse path review incomplete" `
                    -Severity "Low" `
                    -Category "Active Directory" `
                    -MITRE "T1098" `
                    -Tactic "Privilege Escalation / Lateral Movement" `
                    -Source "AD-ComputerObject-Abuse" `
                    -Evidence "ComputersReviewed=$($Computers.Count); AbusePaths=0; AclErrors=$($AclErrors.Count)" `
                    -Recommendation "Review Show-WFLDetails -Name AD-ComputerObject-Abuse-ACL-Errors. Verify LDAP permissions and object accessibility."

                return
            }

            if ($Findings.Count -eq 0) {

                Add-WFLFinding `
                    -Title "Computer object abuse path review passed" `
                    -Severity "Info" `
                    -Category "Active Directory" `
                    -MITRE "T1098" `
                    -Tactic "Privilege Escalation / Lateral Movement" `
                    -Source "AD-ComputerObject-Abuse" `
                    -Evidence "ComputersReviewed=$($Computers.Count); AbusePaths=0; AclErrors=$($AclErrors.Count)" `
                    -Recommendation "No dangerous delegated permissions detected on reviewed computer objects."

                return
            }

            Add-WFLFinding `
                -Title "Computer object abuse paths detected" `
                -Severity $Severity `
                -Category "Active Directory" `
                -MITRE "T1098" `
                -Tactic "Privilege Escalation / Lateral Movement" `
                -Source "AD-ComputerObject-Abuse" `
                -Evidence "ComputersReviewed=$($Computers.Count); AbusePaths=$($Findings.Count); Critical=$CriticalCount; High=$HighCount; Medium=$MediumCount; Low=$LowCount; AclErrors=$($AclErrors.Count)" `
                -Recommendation "Review non-standard principals with GenericAll, GenericWrite, WriteDacl, WriteOwner, ResetPassword, WriteSPN or WriteRBCD on computer objects. Prioritize Domain Controllers, servers and RBCD-capable paths."

        }
        catch {

            Add-WFLFinding `
                -Title "Computer object abuse path review failed" `
                -Severity "Info" `
                -Category "Active Directory" `
                -MITRE "T1098" `
                -Tactic "Privilege Escalation / Lateral Movement" `
                -Source "AD-ComputerObject-Abuse" `
                -Evidence $_.Exception.Message `
                -Recommendation "Verify Active Directory module availability, LDAP connectivity and permissions."
        }
    }


