Register-WFLModule `
    -Name "AD-DCSync-Rights" `
    -Category "Active Directory" `
    -Type "Check" `
    -MITRE "T1003.006" `
    -Tactic "Credential Access" `
    -Impact "POTENTIAL DOMAIN COMPROMISE" `
    -Description "Reviews DCSync-capable replication permissions and correlates them with risky account properties." `
        -Remediation @{
        Module        = 'AD-DCSync-Rights'
        Category      = 'Credential Access'
        Type          = 'Specific'
        Description   = 'Identifies and strips unauthorized accounts holding DS-Replication-Get-Changes and DS-Replication-Get-Changes-All rights (DCSync privileges) on the domain root.'
        Impact        = 'High. Stripping these rights breaks rogue replication tools and unauthorized security controls. Ensure only legitimate Domain Controllers and enterprise backup software retain replication rights.'
        VariableGuide = '$Identity: The principal account or group inappropriately holding replication rights.'
        Code          = @'
'@
    } -Run {

        if (-not $Global:WinFlesher.Context.ActiveDirectory.Available) {
            Add-WFLFinding `
                -Title "DCSync Rights review unavailable" `
                -Severity "Info" `
                -Category "Active Directory" `
                -MITRE "T1003.006" `
                -Tactic "Credential Access" `
                -Source "AD-DCSync-Rights" `
                -Evidence "Active Directory discovery unavailable." `
                -Recommendation "Run from a domain-joined host with RSAT ActiveDirectory module."
            return
        }

        function Test-WFLTrustedReplicationPrincipal {
            param(
                [string]$Identity,
                [string]$Sid
            )

            switch ($Sid) {
                "S-1-5-9"      { return $true }   # Enterprise Domain Controllers
                "S-1-5-18"     { return $true }   # Local System
                "S-1-5-32-544" { return $true }   # Builtin Administrators
            }

            if ($Sid -match "-512$") { return $true } # Domain Admins
            if ($Sid -match "-516$") { return $true } # Domain Controllers
            if ($Sid -match "-518$") { return $true } # Schema Admins
            if ($Sid -match "-519$") { return $true } # Enterprise Admins
            if ($Sid -match "-521$") { return $true } # Read-only Domain Controllers

            $TrustedPatterns = @(
                "Domain Controllers",
                "Enterprise Domain Controllers",
                "Enterprise Read-Only Domain Controllers",
                "Domain Admins",
                "Enterprise Admins",
                "Administrators",
                "SYSTEM",
                "CONTROLLER DI DOMINIO",
                "CONTROLLER DI DOMINIO ORGANIZZAZIONE"
            )

            foreach ($Pattern in $TrustedPatterns) {
                if ($Identity -like "*$Pattern*") {
                    return $true
                }
            }

            return $false
        }

        function Resolve-WFLADPrincipal {
            param(
                [string]$Identity,
                [string]$Sid
            )

            $Result = [PSCustomObject]@{
                Identity             = $Identity
                SamAccountName       = ""
                ObjectClass          = ""
                Enabled              = ""
                PasswordNeverExpires = ""
                PasswordLastSet      = ""
                AdminCount           = ""
                DistinguishedName    = ""
                Resolved             = $false
                ResolutionError      = ""
            }

            try {
                $Obj = $null

                if (-not [string]::IsNullOrWhiteSpace($Sid) -and $Sid -like "S-1-*") {
                    $Obj = Get-ADObject -Filter "objectSid -eq '$Sid'" `
                        -Properties samAccountName,objectClass,enabled,passwordNeverExpires,passwordLastSet,adminCount,distinguishedName `
                        -ErrorAction SilentlyContinue | Select-Object -First 1
                }

                if (-not $Obj -and -not [string]::IsNullOrWhiteSpace($Identity)) {
                    $Name = if ($Identity -match "\\") { ($Identity -split "\\")[-1] } else { $Identity.Trim() }
                    
                    if (-not [string]::IsNullOrWhiteSpace($Name)) {
                        try { $Obj = Get-ADUser -Identity $Name -Properties * -ErrorAction Stop } catch {}

                        if (-not $Obj) {
                            try { $Obj = Get-ADComputer -Identity $Name -Properties * -ErrorAction Stop } catch {}
                        }

                        if (-not $Obj) {
                            $Escaped = $Name.Replace("'", "''")
                            $Obj = Get-ADObject `
                                -LDAPFilter "(|(samAccountName=$Escaped)(cn=$Escaped)(name=$Escaped))" `
                                -Properties samAccountName,objectClass,enabled,passwordNeverExpires,passwordLastSet,adminCount,distinguishedName `
                                -ErrorAction SilentlyContinue | Select-Object -First 1
                        }
                    }
                }

                if ($Obj) {
                    $Result.SamAccountName       = [string]$Obj.samAccountName
                    $Result.ObjectClass          = [string]$Obj.objectClass
                    $Result.Enabled              = [string]$Obj.enabled
                    $Result.PasswordNeverExpires = [string]$Obj.passwordNeverExpires
                    $Result.PasswordLastSet      = [string]$Obj.passwordLastSet
                    $Result.AdminCount           = [string]$Obj.adminCount
                    $Result.DistinguishedName    = [string]$Obj.distinguishedName
                    $Result.Resolved             = $true
                }
            }
            catch {
                $Result.ResolutionError = $_.Exception.Message
            }

            return $Result
        }

        try {
            $DomainDN = (Get-ADDomain -ErrorAction Stop).DistinguishedName

            $ReplicationRights = @{
                "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2" = "Replicating Directory Changes"
                "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2" = "Replicating Directory Changes All"
                "89e95b76-444d-4c62-991a-0facbeda640c" = "Replicating Directory Changes In Filtered Set"
            }

            $Entry = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$DomainDN")
            $Rules = $Entry.ObjectSecurity.GetAccessRules($true, $true, [System.Security.Principal.NTAccount])

            $PrincipalRightsMap = @{}

            foreach ($Rule in $Rules) {
                if ([string]$Rule.AccessControlType -ne "Allow") { continue }

                $ObjectType = [string]$Rule.ObjectType
                if (-not $ReplicationRights.ContainsKey($ObjectType)) { continue }

                $Identity = [string]$Rule.IdentityReference
                $IdentitySid = ""

                try {
                    $TranslatedSid = $Rule.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier])
                    if ($TranslatedSid) { $IdentitySid = [string]$TranslatedSid.Value }
                }
                catch {
                    $IdentitySid = ""
                }

                $Key = if (-not [string]::IsNullOrWhiteSpace($IdentitySid)) { $IdentitySid } else { $Identity }

                if (-not $PrincipalRightsMap.ContainsKey($Key)) {
                    $PrincipalRightsMap[$Key] = @{
                        Identity    = $Identity
                        IdentitySid = $IdentitySid
                        Guids       = [System.Collections.Generic.HashSet[string]]::new()
                        RightsNames = [System.Collections.Generic.HashSet[string]]::new()
                    }
                }

                [void]$PrincipalRightsMap[$Key].Guids.Add($ObjectType)
                [void]$PrincipalRightsMap[$Key].RightsNames.Add($ReplicationRights[$ObjectType])
            }

            $Results = @()

            foreach ($Key in $PrincipalRightsMap.Keys) {
                $EntryData   = $PrincipalRightsMap[$Key]
                $Identity    = $EntryData.Identity
                $IdentitySid = $EntryData.IdentitySid
                $Guids       = $EntryData.Guids

                $IsTrusted = Test-WFLTrustedReplicationPrincipal -Identity $Identity -Sid $IdentitySid
                $Principal = Resolve-WFLADPrincipal -Identity $Identity -Sid $IdentitySid

                $HasGetChanges    = $Guids.Contains("1131f6aa-9c07-11d1-f79f-00c04fc2dcd2")
                $HasGetChangesAll = $Guids.Contains("1131f6ad-9c07-11d1-f79f-00c04fc2dcd2")
                $HasFilteredSet = $Guids.Contains(
    "89e95b76-444d-4c62-991a-0facbeda640c"
)
                $CanDCSync = (
    $HasGetChangesAll -or
    ($HasGetChanges -and $HasGetChangesAll)
)
				

                $RiskSignals = @()

                if (-not $IsTrusted) { $RiskSignals += "NonTrustedPrincipal" }
                if ($CanDCSync)      { $RiskSignals += "FullDCSyncCapable" }

                if ($Principal.Resolved) {
                    if ($Principal.ObjectClass -eq "user") { $RiskSignals += "UserObject" }
                    if ($Principal.ObjectClass -eq "computer") { $RiskSignals += "ComputerObject" }
                    if ($Principal.Enabled -eq "False") { $RiskSignals += "DisabledObject" }
                    if ($Principal.PasswordNeverExpires -eq "True") { $RiskSignals += "PasswordNeverExpires" }
                    if ($Principal.AdminCount -eq "1") { $RiskSignals += "AdminCount1" }
                }
                else {
                    $RiskSignals += "UnresolvedPrincipal"
                }

                $EffectiveSeverity = "Info"

                if (-not $IsTrusted) {
                    if ($CanDCSync) {
                        $EffectiveSeverity = "Critical"
                    }
                    else {
                        $EffectiveSeverity = "High"
                    }
                }

                $Results += [PSCustomObject]@{
                    Identity              = $Identity
                    ObjectSid             = $IdentitySid
                    RightName             = ($EntryData.RightsNames -join "; ")
                    ObjectTypeGuid        = ($Guids -join "; ")
                    CanDCSync             = $CanDCSync
                    TrustedPrincipal      = $IsTrusted
                    Resolved              = $Principal.Resolved
                    SamAccountName        = $Principal.SamAccountName
                    ObjectClass           = $Principal.ObjectClass
                    Enabled               = $Principal.Enabled
                    PasswordNeverExpires  = $Principal.PasswordNeverExpires
                    PasswordLastSet       = $Principal.PasswordLastSet
                    AdminCount            = $Principal.AdminCount
                    DistinguishedName     = $Principal.DistinguishedName
                    RiskSignals           = ($RiskSignals -join "; ")
                    EffectiveSeverity     = $EffectiveSeverity
                }
            }

            Add-WFLDetail -Name "AD-DCSync-Rights" -Data $Results

            $NonTrusted = @($Results | Where-Object { $_.TrustedPrincipal -ne $true })
			$CriticalRisk = @(
    $Results | Where-Object {
        $_.EffectiveSeverity -eq "Critical"
    }
)
            $HighRisk   = @($Results | Where-Object { $_.EffectiveSeverity -eq "High" })
            $MediumRisk = @($Results | Where-Object { $_.EffectiveSeverity -eq "Medium" })

            $FullDCSync = @($Results | Where-Object { $_.CanDCSync -eq $true })
            $PartialReplication = @($Results | Where-Object { $_.CanDCSync -ne $true })

            $Severity = "Info"

if ($MediumRisk.Count -gt 0)
{
    $Severity = "High"
}

if ($HighRisk.Count -gt 0)
{
    $Severity = "Critical"
}

if ($CriticalRisk.Count -gt 0)
{
    $Severity = "Critical"
}

            Add-WFLFinding `
                -Title "DCSync replication permissions review" `
                -Severity $Severity `
                -Category "Active Directory" `
                -MITRE "T1003.006" `
                -Tactic "Credential Access" `
                -Source "AD-DCSync-Rights" `
                -Evidence "PrincipalsReviewed=$($Results.Count); FullDCSyncPrincipals=$($FullDCSync.Count); PartialReplicationPrincipals=$($PartialReplication.Count); NonTrustedPrincipals=$($NonTrusted.Count); HighRisk=$($HighRisk.Count); MediumRisk=$($MediumRisk.Count)" `
                -Recommendation "Review non-standard principals with directory replication rights. Remove unnecessary Replicating Directory Changes permissions. Use Show-WFLDetails -Name AD-DCSync-Rights for details."
        }
        catch {
            Add-WFLFinding `
                -Title "DCSync Rights review failed" `
                -Severity "Info" `
                -Category "Active Directory" `
                -MITRE "T1003.006" `
                -Tactic "Credential Access" `
                -Source "AD-DCSync-Rights" `
                -Evidence $_.Exception.Message `
                -Recommendation "Verify AD permissions, RSAT module, and LDAP access to the domain root."
        }
    }


