Register-WFLModule `
    -Name "AD-DnsAdmins-Abuse" `
    -Category "Active Directory" `
    -Type "Check" `
    -MITRE "T1098" `
    -Tactic "Privilege Escalation / Persistence" `
    -Impact "POTENTIAL DOMAIN COMPROMISE" `
    -Description "Reviews DnsAdmins membership and DNS-related privilege exposure." `
        -Remediation @{
        Module        = 'AD-DnsAdmins-Abuse'
        Category      = 'Privilege Escalation / Persistence'
        Type          = 'Specific'
        Description   = 'Removes unauthorized user accounts from the high-privilege DnsAdmins security group to prevent DLL injection and remote execution vectors on DNS servers.'
        Impact        = 'Low. Restricting DnsAdmins group membership blocks privilege escalation paths to Domain Admin.'
        VariableGuide = '$UserAccount: The unauthorized user identity to be expelled from the group.'
        Code          = @'
Remove-ADGroupMember -Identity "DnsAdmins" -Members "SuspiciousAccountName" -Confirm:$false
'@
    } -Run {

        if (-not $Global:WinFlesher.Context.ActiveDirectory.Available)
        {
            Add-WFLFinding `
                -Title "DnsAdmins abuse review unavailable" `
                -Severity "Info" `
                -Category "Active Directory" `
                -MITRE "T1098" `
                -Tactic "Privilege Escalation / Persistence" `
                -Source "AD-DnsAdmins-Abuse" `
                -Evidence "Active Directory discovery unavailable." `
                -Recommendation "Run from a domain-joined host with RSAT ActiveDirectory module."

            return
        }

        try
        {
            function Resolve-WFLDnsAdminPrincipal {
                param(
                    [object]$Member
                )

                $Result = [PSCustomObject]@{
                    Name                 = [string]$Member.Name
                    SamAccountName       = [string]$Member.SamAccountName
                    ObjectClass          = [string]$Member.ObjectClass
                    DistinguishedName    = [string]$Member.DistinguishedName
                    Enabled              = ""
                    AdminCount           = ""
                    PasswordNeverExpires = ""
                    PasswordLastSet      = ""
                    LastLogonDate        = ""
                    Resolved             = $false
                    ResolutionError      = ""
                }

                try
                {
                    if ($Member.ObjectClass -eq "user")
                    {
                        $Obj = Get-ADUser `
                            -Identity $Member.DistinguishedName `
                            -Properties Enabled,AdminCount,PasswordNeverExpires,PasswordLastSet,LastLogonDate `
                            -ErrorAction Stop

                        $Result.Enabled              = [string]$Obj.Enabled
                        $Result.AdminCount           = [string]$Obj.AdminCount
                        $Result.PasswordNeverExpires = [string]$Obj.PasswordNeverExpires
                        $Result.PasswordLastSet      = [string]$Obj.PasswordLastSet
                        $Result.LastLogonDate        = [string]$Obj.LastLogonDate
                        $Result.Resolved             = $true
                    }
                    elseif ($Member.ObjectClass -eq "group")
                    {
                        $Obj = Get-ADGroup `
                            -Identity $Member.DistinguishedName `
                            -Properties AdminCount `
                            -ErrorAction Stop

                        $Result.AdminCount = [string]$Obj.AdminCount
                        $Result.Resolved   = $true
                    }
                    elseif ($Member.ObjectClass -eq "computer")
                    {
                        $Obj = Get-ADComputer `
                            -Identity $Member.DistinguishedName `
                            -Properties Enabled,AdminCount,PasswordLastSet,LastLogonDate `
                            -ErrorAction Stop

                        $Result.Enabled         = [string]$Obj.Enabled
                        $Result.AdminCount      = [string]$Obj.AdminCount
                        $Result.PasswordLastSet = [string]$Obj.PasswordLastSet
                        $Result.LastLogonDate   = [string]$Obj.LastLogonDate
                        $Result.Resolved        = $true
                    }
                }
                catch
                {
                    $Result.ResolutionError = $_.Exception.Message
                }

                return $Result
            }

            function Get-WFLDnsAdminSeverity {
                param(
                    [string]$ObjectClass,
                    [string]$Enabled,
                    [string]$AdminCount,
                    [bool]$DnsOnDomainController
                )

                if ($ObjectClass -eq "user")
                {
                    if ($AdminCount -eq "1")
                    {
                        return "Critical"
                    }

                    if ($Enabled -eq "True" -and $DnsOnDomainController)
                    {
                        return "High"
                    }

                    if ($Enabled -eq "True")
                    {
                        return "Medium"
                    }

                    return "Low"
                }

                if ($ObjectClass -eq "group")
                {
                    if ($DnsOnDomainController)
                    {
                        return "High"
                    }

                    return "Medium"
                }

                if ($ObjectClass -eq "computer")
                {
                    if ($DnsOnDomainController)
                    {
                        return "Medium"
                    }

                    return "Low"
                }

                return "Medium"
            }

            $Results = @()
            $Errors = @()

            $DnsGroup = $null

            try
            {
                $DnsGroup = Get-ADGroup `
                    -Identity "DnsAdmins" `
                    -Properties DistinguishedName `
                    -ErrorAction Stop
            }
            catch
            {
                Add-WFLDetail `
                    -Name "AD-DnsAdmins-Abuse" `
                    -Data $Results

                Add-WFLFinding `
                    -Title "DnsAdmins group not found" `
                    -Severity "Info" `
                    -Category "Active Directory" `
                    -MITRE "T1098" `
                    -Tactic "Privilege Escalation / Persistence" `
                    -Source "AD-DnsAdmins-Abuse" `
                    -Evidence "DnsAdmins group could not be found in this domain." `
                    -Recommendation "No DnsAdmins group exposure detected, or the group is not present in this environment."

                return
            }

            $DnsOnDomainController = $false
            $DomainControllers = @()

            try
            {
                $DomainControllers = @(
                    Get-ADDomainController -Filter * -ErrorAction Stop
                )

                if ($DomainControllers.Count -gt 0)
                {
                    $DnsOnDomainController = $true
                }
            }
            catch
            {
                $Errors += [PSCustomObject]@{
                    Stage = "DomainControllerDiscovery"
                    Error = $_.Exception.Message
                }
            }

            $Members = @()

            try
            {
                $Members = @(
                    Get-ADGroupMember `
                        -Identity $DnsGroup.DistinguishedName `
                        -Recursive `
                        -ErrorAction Stop
                )
            }
            catch
            {
                $Errors += [PSCustomObject]@{
                    Stage = "DnsAdminsMembership"
                    Error = $_.Exception.Message
                }
            }

            foreach ($Member in $Members)
            {
                $Principal = Resolve-WFLDnsAdminPrincipal -Member $Member

                $Severity = Get-WFLDnsAdminSeverity `
                    -ObjectClass $Principal.ObjectClass `
                    -Enabled $Principal.Enabled `
                    -AdminCount $Principal.AdminCount `
                    -DnsOnDomainController ([bool]$DnsOnDomainController)

                $Exploitability = "Potential"

                if ($Severity -eq "Critical" -or $Severity -eq "High")
                {
                    $Exploitability = "Likely"
                }

                if ($Principal.Enabled -eq "False")
                {
                    $Exploitability = "Conditional"
                }

                $RiskReasons = @()

                if ($DnsOnDomainController)
                {
                    $RiskReasons += "DNS role is associated with domain controller infrastructure"
                }

                if ($Principal.ObjectClass -eq "user" -and $Principal.Enabled -eq "True")
                {
                    $RiskReasons += "Enabled user is member of DnsAdmins"
                }

                if ($Principal.ObjectClass -eq "group")
                {
                    $RiskReasons += "Group is nested into DnsAdmins"
                }

                if ($Principal.AdminCount -eq "1")
                {
                    $RiskReasons += "AdminCount privileged object"
                }

                if ($Principal.PasswordNeverExpires -eq "True")
                {
                    $RiskReasons += "Password never expires"
                }

                if ($RiskReasons.Count -eq 0)
                {
                    $RiskReasons += "DnsAdmins membership detected"
                }

                $Results += [PSCustomObject]@{
                    Name                  = $Principal.Name
                    SamAccountName        = $Principal.SamAccountName
                    ObjectClass           = $Principal.ObjectClass
                    DistinguishedName     = $Principal.DistinguishedName
                    Enabled               = $Principal.Enabled
                    AdminCount            = $Principal.AdminCount
                    PasswordNeverExpires  = $Principal.PasswordNeverExpires
                    PasswordLastSet       = $Principal.PasswordLastSet
                    LastLogonDate         = $Principal.LastLogonDate
                    DnsOnDomainController = $DnsOnDomainController
                    Severity              = $Severity
                    Exploitability        = $Exploitability
                    RiskReason            = ($RiskReasons -join "; ")
                    Resolved              = $Principal.Resolved
                    ResolutionError       = $Principal.ResolutionError
                }
            }

            Add-WFLDetail `
                -Name "AD-DnsAdmins-Abuse" `
                -Data $Results

            Add-WFLDetail `
                -Name "AD-DnsAdmins-Abuse-Errors" `
                -Data $Errors

            $CriticalCount = @(
                $Results | Where-Object {
                    $_.Severity -eq "Critical"
                }
            ).Count

            $HighCount = @(
                $Results | Where-Object {
                    $_.Severity -eq "High"
                }
            ).Count

            $MediumCount = @(
                $Results | Where-Object {
                    $_.Severity -eq "Medium"
                }
            ).Count

            $LowCount = @(
                $Results | Where-Object {
                    $_.Severity -eq "Low"
                }
            ).Count

            $EnabledUserCount = @(
                $Results | Where-Object {
                    $_.ObjectClass -eq "user" -and
                    $_.Enabled -eq "True"
                }
            ).Count

            $Severity = "Info"

            if ($LowCount -gt 0)
            {
                $Severity = "Low"
            }

            if ($MediumCount -gt 0)
            {
                $Severity = "Medium"
            }

            if ($HighCount -gt 0)
            {
                $Severity = "High"
            }

            if ($CriticalCount -gt 0)
            {
                $Severity = "Critical"
            }

            if ($Results.Count -eq 0)
            {
                Add-WFLFinding `
                    -Title "DnsAdmins abuse review passed" `
                    -Severity "Info" `
                    -Category "Active Directory" `
                    -MITRE "T1098" `
                    -Tactic "Privilege Escalation / Persistence" `
                    -Source "AD-DnsAdmins-Abuse" `
                    -Evidence "DnsAdminsMembers=0; Errors=$($Errors.Count)" `
                    -Recommendation "No members detected in DnsAdmins."
                return
            }

            Add-WFLFinding `
                -Title "DnsAdmins membership exposure detected" `
                -Severity $Severity `
                -Category "Active Directory" `
                -MITRE "T1098" `
                -Tactic "Privilege Escalation / Persistence" `
                -Source "AD-DnsAdmins-Abuse" `
                -Evidence "DnsAdminsMembers=$($Results.Count); EnabledUsers=$EnabledUserCount; Critical=$CriticalCount; High=$HighCount; Medium=$MediumCount; Low=$LowCount; Errors=$($Errors.Count)" `
                -Recommendation "Review all DnsAdmins members and nested groups. Remove unnecessary users/groups and restrict DNS administration to tightly controlled administrative accounts."

        }
        catch
        {
            Add-WFLFinding `
                -Title "DnsAdmins abuse review failed" `
                -Severity "Info" `
                -Category "Active Directory" `
                -MITRE "T1098" `
                -Tactic "Privilege Escalation / Persistence" `
                -Source "AD-DnsAdmins-Abuse" `
                -Evidence $_.Exception.Message `
                -Recommendation "Verify Active Directory module availability and permissions to query DnsAdmins membership."
        }
    }


