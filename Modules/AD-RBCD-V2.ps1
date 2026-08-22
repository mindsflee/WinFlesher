Register-WFLModule `
    -Name "AD-RBCD-V2" `
    -Category "Active Directory" `
    -Type "Check" `
    -MITRE "T1550" `
    -Tactic "Lateral Movement" `
    -Impact "POTENTIAL DOMAIN COMPROMISE" `
    -Description "Reviews Resource-Based Constrained Delegation and correlates delegated principals with target criticality." `
        -Remediation @{
        Module        = 'AD-RBCD-V2'
        Category      = 'Lateral Movement'
        Type          = 'Specific'
        Description   = 'Cleans up unauthorized Resource-Based Constrained Delegation (msDS-AllowedToActOnBehalfOfOtherIdentity) configurations on computer objects.'
        Impact        = 'Low. Removes dangerous delegation bindings that could allow privilege escalation via forced computer authentication.'
        VariableGuide = '$TargetComputer: The resource object hosting the dangerous delegation attribute.'
        Code          = @'
Set-ADComputer -Identity "TargetComputer" -PrincipalsAllowedToDelegateToAccount $null
'@
    } -Run {

        if (-not $Global:WinFlesher.Context.ActiveDirectory.Available) {
            Add-WFLFinding `
                -Title "RBCD V2 review unavailable" `
                -Severity "Info" `
                -Category "Active Directory" `
                -MITRE "T1550" `
                -Tactic "Lateral Movement" `
                -Source "AD-RBCD-V2" `
                -Evidence "Active Directory discovery unavailable." `
                -Recommendation "Run from a domain-joined host with RSAT ActiveDirectory module."

            return
        }

        function Resolve-WFLSid {
            param(
                [System.Security.Principal.SecurityIdentifier]$Sid
            )

            $Result = [PSCustomObject]@{
                SID                 = [string]$Sid.Value
                NTAccount           = ""
                SamAccountName      = ""
                ObjectClass         = ""
                Enabled             = ""
                AdminCount          = ""
                DistinguishedName   = ""
                Resolved            = $false
                ResolutionError     = ""
            }

            try {
                $NTAccount = $Sid.Translate([System.Security.Principal.NTAccount])
                $Result.NTAccount = [string]$NTAccount.Value
            }
            catch {
                $Result.NTAccount = ""
            }

            try {
                $Obj = Get-ADObject `
                    -LDAPFilter "(objectSid=$($Sid.Value))" `
                    -Properties samAccountName,objectClass,enabled,adminCount,distinguishedName `
                    -ErrorAction SilentlyContinue |
                    Select-Object -First 1

                if ($Obj) {
                    $Result.SamAccountName    = [string]$Obj.samAccountName
                    $Result.ObjectClass       = [string]$Obj.objectClass
                    $Result.Enabled           = [string]$Obj.enabled
                    $Result.AdminCount        = [string]$Obj.adminCount
                    $Result.DistinguishedName = [string]$Obj.distinguishedName
                    $Result.Resolved          = $true
                }
            }
            catch {
                $Result.ResolutionError = $_.Exception.Message
            }

            return $Result
        }

        function Convert-WFLRBCDDescriptor {
            param(
                [byte[]]$SecurityDescriptor
            )

            $Principals = @()

            if (-not $SecurityDescriptor) {
                return $Principals
            }

            try {
                $RawSD = New-Object System.Security.AccessControl.RawSecurityDescriptor($SecurityDescriptor, 0)

                foreach ($Ace in $RawSD.DiscretionaryAcl) {
                    try {
                        $Sid = New-Object System.Security.Principal.SecurityIdentifier($Ace.SecurityIdentifier.Value)
                        $Principal = Resolve-WFLSid -Sid $Sid

                        $Principals += [PSCustomObject]@{
                            SID               = $Principal.SID
                            NTAccount         = $Principal.NTAccount
                            SamAccountName    = $Principal.SamAccountName
                            ObjectClass       = $Principal.ObjectClass
                            Enabled           = $Principal.Enabled
                            AdminCount        = $Principal.AdminCount
                            DistinguishedName = $Principal.DistinguishedName
                            Resolved          = $Principal.Resolved
                            AceType           = [string]$Ace.AceType
                            AceFlags          = [string]$Ace.AceFlags
                            AccessMask        = [string]$Ace.AccessMask
                        }
                    }
                    catch {}
                }
            }
            catch {}

            return $Principals
        }

        function Test-WFLTargetIsDC {
            param(
                [object]$Computer
            )

            try {
                if ($Computer.PrimaryGroupID -eq 516) {
                    return $true
                }

                if ($Computer.UserAccountControl -band 8192) {
                    return $true
                }

                $DCNames = @(
                    $Global:WinFlesher.Context.ADDomainControllers |
                    ForEach-Object { $_.HostName; $_.Name }
                )

                foreach ($DCName in $DCNames) {
                   if ($null -ne $DCName -and $DCName -ne "") {
                        if ([string]$Computer.DNSHostName -like "*$DCName*" -or [string]$Computer.Name -like "*$DCName*") {
                            return $true
                        }
                    }
                }
            }
            catch {}

            return $false
        }

        try {

            $Computers = @(
                Get-ADComputer `
                    -LDAPFilter "(msDS-AllowedToActOnBehalfOfOtherIdentity=*)" `
                    -Properties `
                        DNSHostName,
                        OperatingSystem,
                        Enabled,
                        PrimaryGroupID,
                        UserAccountControl,
                        msDS-AllowedToActOnBehalfOfOtherIdentity `
                    -ErrorAction Stop
            )

            $Results = @()

            foreach ($Computer in $Computers) {

                $TargetIsDC = Test-WFLTargetIsDC -Computer $Computer

                $Principals = @(
                    Convert-WFLRBCDDescriptor `
                        -SecurityDescriptor $Computer."msDS-AllowedToActOnBehalfOfOtherIdentity"
                )

                if ($Principals.Count -eq 0) {

                    $Results += [PSCustomObject]@{
                        TargetComputer           = $Computer.Name
                        TargetDNSHostName        = $Computer.DNSHostName
                        TargetOS                 = $Computer.OperatingSystem
                        TargetEnabled            = $Computer.Enabled
                        TargetIsDomainController = $TargetIsDC
                        DelegatedIdentity        = ""
                        DelegatedObjectClass     = ""
                        DelegatedEnabled         = ""
                        DelegatedAdminCount      = ""
                        DelegatedSID             = ""
                        DelegatedResolved        = $false
                        EffectiveSeverity        = "Info"
                        RiskSignals              = "RBCDConfiguredButSIDNotParsed"
                    }

                    continue
                }

                foreach ($Principal in $Principals) {

                    $RiskSignals = @()

                    if ($TargetIsDC) {
                        $RiskSignals += "TargetIsDomainController"
                    }

                    if ($Principal.ObjectClass -eq "user") {
                        $RiskSignals += "DelegatedUser"
                    }

                    if ($Principal.ObjectClass -eq "computer") {
                        $RiskSignals += "DelegatedComputer"
                    }

                    if ($Principal.AdminCount -eq "1") {
                        $RiskSignals += "DelegatedAdminCount1"
                    }

                    if ($Principal.Resolved -ne $true) {
                        $RiskSignals += "UnresolvedPrincipal"
                    }

                    $Severity = "Medium"

                    if ($Principal.ObjectClass -eq "user") {
                        $Severity = "High"
                    }

                    if ($Principal.AdminCount -eq "1") {
                        $Severity = "High"
                    }

                    if ($TargetIsDC) {
                        $Severity = "High"
                    }

                    if (
                        $TargetIsDC -and
                        (
                            $Principal.ObjectClass -eq "user" -or
                            $Principal.AdminCount -eq "1"
                        )
                    ) {
                        $Severity = "Critical"
                    }

                    $DelegatedIdentity = $Principal.NTAccount

                  if (-not $DelegatedIdentity) {
    $DelegatedIdentity = $Principal.SamAccountName
}

if (-not $DelegatedIdentity) {
    $DelegatedIdentity = $Principal.SID
}

                    $Results += [PSCustomObject]@{
                        TargetComputer           = $Computer.Name
                        TargetDNSHostName        = $Computer.DNSHostName
                        TargetOS                 = $Computer.OperatingSystem
                        TargetEnabled            = $Computer.Enabled
                        TargetIsDomainController = $TargetIsDC
                        DelegatedIdentity        = $DelegatedIdentity
                        DelegatedObjectClass     = $Principal.ObjectClass
                        DelegatedEnabled         = $Principal.Enabled
                        DelegatedAdminCount      = $Principal.AdminCount
                        DelegatedSID             = $Principal.SID
                        DelegatedResolved        = $Principal.Resolved
                        EffectiveSeverity        = $Severity
                        RiskSignals              = ($RiskSignals -join "; ")
                    }
                }
            }

            Add-WFLDetail `
                -Name "AD-RBCD-V2" `
                -Data $Results
				            $Critical = @(
                $Results |
                Where-Object { $_.EffectiveSeverity -eq "Critical" }
            ).Count

            $High = @(
                $Results |
                Where-Object { $_.EffectiveSeverity -eq "High" }
            ).Count

            $Medium = @(
                $Results |
                Where-Object { $_.EffectiveSeverity -eq "Medium" }
            ).Count

            $Info = @(
                $Results |
                Where-Object { $_.EffectiveSeverity -eq "Info" }
            ).Count

            $Severity = "Info"

            if ($Medium -gt 0) {
                $Severity = "Medium"
            }

            if ($High -gt 0) {
                $Severity = "High"
            }

            if ($Critical -gt 0) {
                $Severity = "Critical"
            }

            if (@($Results).Count -eq 0) {

                Add-WFLFinding `
                    -Title "RBCD V2 review passed" `
                    -Severity "Info" `
                    -Category "Active Directory" `
                    -MITRE "T1550" `
                    -Tactic "Lateral Movement" `
                    -Source "AD-RBCD-V2" `
                    -Evidence "No computers with msDS-AllowedToActOnBehalfOfOtherIdentity found." `
                    -Recommendation "No action required."

                return
            }

            Add-WFLFinding `
                -Title "RBCD V2 delegated access paths detected" `
                -Severity $Severity `
                -Category "Active Directory" `
                -MITRE "T1550" `
                -Tactic "Lateral Movement" `
                -Source "AD-RBCD-V2" `
                -Evidence "RBCDEntries=$(@($Results).Count); Critical=$Critical; High=$High; Medium=$Medium; Info=$Info" `
                -Recommendation "Review RBCD configuration. Prioritize entries targeting domain controllers, Tier-0 systems, user principals, privileged principals and unresolved delegated SIDs. Use Show-WFLDetails -Name AD-RBCD-V2 for details."
        }
        catch {

            Add-WFLFinding `
                -Title "RBCD V2 review failed" `
                -Severity "Info" `
                -Category "Active Directory" `
                -MITRE "T1550" `
                -Tactic "Lateral Movement" `
                -Source "AD-RBCD-V2" `
                -Evidence $_.Exception.Message `
                -Recommendation "Verify AD permissions and availability of msDS-AllowedToActOnBehalfOfOtherIdentity."
        }
    }


