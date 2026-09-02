Register-WFLModule `
    -Name "Exchange-APT-PrivEsc-Persistence-Audit" `
    -Category "Exchange" `
    -Type "Check" `
    -MITRE "T1505.003, T1505.004, T1098" `
    -Tactic "Persistence / Privilege Escalation" `
    -Impact "POTENTIAL DOMAIN COMPROMISE / REMOTE CODE EXECUTION / WEBSHELL PERSISTENCE" `
    -Description "Performs a deep, low-false-positive audit of Microsoft Exchange persistence, WebShell artifacts with content heuristics, RBAC role assignments, and validated Exchange-to-AD privilege escalation vectors." `
    -Remediation @{
        Module        = 'Exchange-APT-PrivEsc-Persistence-Audit'
        Category      = 'Persistence / Privilege Escalation'
        Type          = 'Specific'
        Description   = 'Removes unauthorized Exchange Transport Agents, deletes verified malicious WebShells (.aspx) from OWA/ECP paths, strips unapproved rogue RBAC role members, and cleans up unauthorized accounts from the Exchange Windows Permissions group.'
        Impact        = 'Critical. Improper management or lingering backdoors can lead directly to total domain compromise and remote code execution.'
        VariableGuide = '$Identity: The transport agent name, suspicious file path, RBAC member, or security principal holding validated dangerous AD integration rights.'
        Code          = @'
# Remove-Item -Path "C:\Program Files\Microsoft\Exchange Server\V15\FrontEnd\HttpProxy\owa\auth\webshell.aspx" -Force
# Uninstall-TransportAgent -Identity "NomeAgentSospetto"
# Remove-RoleGroupMember -Identity "Organization Management" -Member "UserName" -Confirm:$false
# Remove-ADGroupMember -Identity "Exchange Windows Permissions" -Member "UserName" -Confirm:$false
'@
    } -Run {
    try {
       
        $ExchangeModuleAvailable = $false
        try {
            if (Get-Command Get-TransportAgent -ErrorAction SilentlyContinue) {
                $ExchangeModuleAvailable = $true
            }
            elseif (Test-Path "$($env:ExchangeInstallPath)bin\RemotePowerShell\Sdk") {
                Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn* -ErrorAction SilentlyContinue
                if (Get-Command Get-TransportAgent -ErrorAction SilentlyContinue) {
                    $ExchangeModuleAvailable = $true
                }
            }
        }
        catch {
            $ExchangeModuleAvailable = $false
        }

        if (-not $ExchangeModuleAvailable) {
            Add-WFLFinding `
                -Title "Exchange APT Audit unavailable" `
                -Severity "Info" `
                -Category "Exchange" `
                -MITRE "T1505.003" `
                -Tactic "Persistence" `
                -Source "Exchange-APT-PrivEsc-Persistence-Audit" `
                -Evidence "Exchange Management Shell cmdlets not found or execution context not on an Exchange server/management host." `
                -Recommendation "Run this module directly on a Microsoft Exchange Server or with the Exchange Management Tools installed."
            return
        }

 
        $AgentResults = @()
        try {
            $Agents = Get-TransportAgent -ErrorAction Stop
            foreach ($Agent in $Agents) {
                $Name = $Agent.Name
                $Priority = $Agent.Priority
                $Enabled = $Agent.Enabled
                $AssemblyPath = $Agent.AssemblyPath

                $EffectiveSeverity = "Low"
                $RiskSignals = @()
                $IsTrusted = $false
                $SignatureStatus = "NotChecked"
                $SignerSubject = $null

                # Verifica firma Authenticode reale anziché semplice match sul percorso
                if (-not [string]::IsNullOrWhiteSpace($AssemblyPath) -and (Test-Path $AssemblyPath)) {
                    $FileSig = Get-AuthenticodeSignature -FilePath $AssemblyPath -ErrorAction SilentlyContinue
                    $SignatureStatus = $FileSig.Status.ToString()
                    if ($FileSig.SignerCertificate) {
                        $SignerSubject = $FileSig.SignerCertificate.Subject
                    }

                    $IsMicrosoftSigned = ($FileSig.Status -eq "Valid" -and $SignerSubject -match "Microsoft Corporation")
                    
                    if ($IsMicrosoftSigned) {
                        $IsTrusted = $true
                        $RiskSignals += "MicrosoftSignedAssembly"
                        $EffectiveSeverity = "Info"
                    }
                    elseif ($FileSig.Status -eq "Valid") {
                        $IsTrusted = $true
                        $RiskSignals += "ValidThirdPartySignedAssembly"
                        $EffectiveSeverity = "Low"
                    }
                    else {
                        $RiskSignals += "InvalidOrUnsignedAssembly"
                        $EffectiveSeverity = "High"
                    }
                }
                else {
                    $RiskSignals += "AssemblyPathNotFoundOrRemote"
                    $EffectiveSeverity = "Medium"
                }

                if (-not $Enabled) {
                    $RiskSignals += "AgentDisabled"
                }

                $AgentResults += [PSCustomObject]@{
                    Vector            = "TransportAgent"
                    Identity          = $Name
                    Details           = "Priority: $Priority | Enabled: $Enabled | Path: $AssemblyPath | Signer: $SignerSubject"
                    Trusted           = $IsTrusted
                    SignatureStatus   = $SignatureStatus
                    RiskSignals       = ($RiskSignals -join "; ")
                    EffectiveSeverity = $EffectiveSeverity
                    AssessmentStatus  = "Completed"
                }
            }
        }
        catch {
            $AgentResults += [PSCustomObject]@{
                Vector            = "TransportAgent"
                Identity          = "Error"
                Details           = $_.Exception.Message
                Trusted           = $false
                SignatureStatus   = "Error"
                RiskSignals       = "EnumerationFailed"
                EffectiveSeverity = "Info"
                AssessmentStatus  = "Failed"
            }
        }

        $WebShellResults = @()
        try {
            $ExchangeInstallPath = $env:ExchangeInstallPath
            if (-not $ExchangeInstallPath) {
                $ExchangeInstallPath = "C:\Program Files\Microsoft\Exchange Server\V15\"
            }

            $TargetPaths = @(
                "$ExchangeInstallPath\FrontEnd\HttpProxy\owa\auth",
                "$ExchangeInstallPath\FrontEnd\HttpProxy\ecp\auth",
                "$ExchangeInstallPath\ClientAccess\Owa\auth"
            )

            $WebShellPatterns = @(
                "System\.Diagnostics\.Process",
                "cmd\.exe",
                "powershell",
                "FromBase64String",
                "Assembly\.Load",
                "eval\s*\(",
                "Request\[(.*?)\]",
                "Server\.CreateObject"
            )

            foreach ($BasePath in $TargetPaths) {
                if (Test-Path $BasePath) {
                    $AspxFiles = Get-ChildItem -Path $BasePath -Filter "*.aspx" -Recurse -ErrorAction SilentlyContinue
                    foreach ($File in $AspxFiles) {
                        $FileName = $File.Name
                        $FilePath = $File.FullName
                        $LastWrite = $File.LastWriteTime

                        $KnownDefaultFiles = @("error.aspx", "logon.aspx", "expiredpassword.aspx", "signout.aspx", "accessibility.aspx", "usingwindowsauth.aspx", "ping.aspx")
                        $IsKnownDefault = $KnownDefaultFiles -contains $FileName.ToLower()

                        $EffectiveSeverity = "Info"
                        $RiskSignals = @()
                        $ContentSignals = @()
                        $FileHash = $null

                        try {
                            $FileHash = (Get-FileHash -Path $FilePath -Algorithm SHA256 -ErrorAction SilentlyContinue).Hash
                        } catch {
                            $FileHash = "HashCalculationFailed"
                        }

                        if ($IsKnownDefault) {
                            $RiskSignals += "StandardExchangeAuthFile"
                            $EffectiveSeverity = "Info"
                        }
                        else {
                            $RiskSignals += "UnknownOrNonStandardAspx"
                            $EffectiveSeverity = "Medium"

                            try {
                                $FileContent = Get-Content -Path $FilePath -Raw -ErrorAction SilentlyContinue
                                foreach ($Pattern in $WebShellPatterns) {
                                    if ($FileContent -match $Pattern) {
                                        $ContentSignals += $Pattern
                                    }
                                }
                            }
                            catch {
                                $ContentSignals += "ContentReadFailed"
                            }

                            if ($ContentSignals.Count -gt 0) {
                                $RiskSignals += "ExecutionPrimitivesDetected"
                                $EffectiveSeverity = "Critical"
                            }
                            elseif ((Get-Date) - $LastWrite -lt [TimeSpan]::FromDays(7)) {
                                $RiskSignals += "RecentlyModifiedOrCreated"
                                $EffectiveSeverity = "High"
                            }
                        }

                        $WebShellResults += [PSCustomObject]@{
                            Vector            = "WebShellArtifact"
                            Identity          = $FilePath
                            Details           = "File: $FileName | LastModified: $LastWrite | Hash: $FileHash"
                            Trusted           = $IsKnownDefault
                            ContentSignals    = ($ContentSignals -join ", ")
                            RiskSignals       = ($RiskSignals -join "; ")
                            EffectiveSeverity = $EffectiveSeverity
                            AssessmentStatus  = "Completed"
                        }
                    }
                }
            }
        }
        catch {
            $WebShellResults += [PSCustomObject]@{
                Vector            = "WebShellArtifact"
                Identity          = "Error"
                Details           = $_.Exception.Message
                Trusted           = $false
                ContentSignals    = ""
                RiskSignals       = "WebShellScanFailed"
                EffectiveSeverity = "Info"
                AssessmentStatus  = "Failed"
            }
        }

  
        $RbacResults = @()
        try {
            $CriticalRoleGroups = @(
                "Organization Management",
                "Recipient Management",
                "Server Management"
            )

            $BaselineConfigured = $false 

            foreach ($Group in $CriticalRoleGroups) {
                $Members = Get-RoleGroupMember -Identity $Group -ErrorAction SilentlyContinue
                foreach ($Member in $Members) {
                    $MemberName = $Member.Name
                    $MemberClass = $Member.RecipientTypeDetails

                    $EffectiveSeverity = "Info"
                    $RiskSignals = @()
                    $IsTrusted = $true

                    if (-not $BaselineConfigured) {
                        $RiskSignals += "BaselineNotConfigured"
                        if ($Group -eq "Organization Management" -and $MemberName -notmatch "Administrator|System") {
                            $EffectiveSeverity = "Medium"
                            $IsTrusted = $false
                            $RiskSignals += "NonStandardPrivilegedAccount"
                        } else {
                            $EffectiveSeverity = "Info"
                            $RiskSignals += "StandardOrExpectedMember"
                        }
                    }

                    $RbacResults += [PSCustomObject]@{
                        Vector            = "RBACRoleGroup"
                        Identity          = "$Group -> $MemberName"
                        Details           = "RoleGroup: $Group | MemberType: $MemberClass"
                        Trusted           = $IsTrusted
                        RiskSignals       = ($RiskSignals -join "; ")
                        EffectiveSeverity = $EffectiveSeverity
                        AssessmentStatus  = "Completed"
                    }
                }
            }
        }
        catch {
            $RbacResults += [PSCustomObject]@{
                Vector            = "RBACRoleGroup"
                Identity          = "Error"
                Details           = $_.Exception.Message
                Trusted           = $false
                RiskSignals       = "EnumerationFailed"
                EffectiveSeverity = "Info"
                AssessmentStatus  = "Failed"
            }
        }

      
        $AdPrivEscResults = @()
        try {
            if (Get-Command Get-ADGroup -ErrorAction SilentlyContinue) {
                $EwpGroup = Get-ADGroup -Filter "Name -like '*Exchange Windows Permissions*'" -Properties Members -ErrorAction SilentlyContinue
                if ($EwpGroup) {
                    $DomainRootDN = (Get-ADDomain).DistinguishedName
                    $RootAcl = Get-Acl -Path "AD:\$DomainRootDN" -ErrorAction SilentlyContinue
                    $EwpHasWriteDacl = $false

                    if ($RootAcl) {
                        foreach ($Access in $RootAcl.Access) {
                            if ($Access.IdentityReference -match $EwpGroup.Name -and $Access.AccessControlType -eq "Allow") {
                                if ($Access.ActiveDirectoryRights -match "WriteDacl" -or $Access.ActiveDirectoryRights -match "GenericAll") {
                                    $EwpHasWriteDacl = $true
                                }
                            }
                        }
                    }

                    $EwpMembers = Get-ADGroupMember -Identity $EwpGroup.DistinguishedName -ErrorAction SilentlyContinue
                    foreach ($Member in $EwpMembers) {
                        $MemberName = $Member.Name
                        $MemberClass = $Member.objectClass

                        $EffectiveSeverity = "Info"
                        $RiskSignals = @()
                        $IsTrusted = $true

                        if ($EwpHasWriteDacl) {
                            $RiskSignals += "EwpHasActiveWriteDaclOnDomainRoot"
                            if ($MemberName -notmatch "Exchange|Domain Controllers|System|Administrator") {
                                $RiskSignals += "UnauthorizedPrincipalInVulnerableEwpGroup"
                                $EffectiveSeverity = "Critical"
                                $IsTrusted = $false
                            } else {
                                $RiskSignals += "ExpectedEwpMemberWithPrivilegedAccess"
                                $EffectiveSeverity = "High"
                            }
                        } else {
                            $RiskSignals += "EwpGroupWithoutDirectDomainRootWriteDacl"
                            $EffectiveSeverity = "Info"
                        }

                        $AdPrivEscResults += [PSCustomObject]@{
                            Vector            = "ExchangeWindowsPermissionsGroup"
                            Identity          = "Exchange Windows Permissions -> $MemberName"
                            Details           = "ObjectClass: $MemberClass | DomainRootWriteDaclVerified: $EwpHasWriteDacl"
                            Trusted           = $IsTrusted
                            RiskSignals       = ($RiskSignals -join "; ")
                            EffectiveSeverity = $EffectiveSeverity
                            AssessmentStatus  = "Completed"
                        }
                    }
                }
            }
        }
        catch {
            $AdPrivEscResults += [PSCustomObject]@{
                Vector            = "ExchangeWindowsPermissionsGroup"
                Identity          = "Error"
                Details           = $_.Exception.Message
                Trusted           = $false
                RiskSignals       = "ADEnumerationFailed"
                EffectiveSeverity = "Info"
                AssessmentStatus  = "Failed"
            }
        }

      
        $CombinedResults = $AgentResults + $WebShellResults + $RbacResults + $AdPrivEscResults
        Add-WFLDetail -Name "Exchange-APT-PrivEsc-Persistence-Audit" -Data $CombinedResults

 
        $CriticalRisk = @($CombinedResults | Where-Object { $_.EffectiveSeverity -eq "Critical" })
        $HighRisk     = @($CombinedResults | Where-Object { $_.EffectiveSeverity -eq "High" })
        $MediumRisk   = @($CombinedResults | Where-Object { $_.EffectiveSeverity -eq "Medium" })

        $Severity = "Info"
        if ($MediumRisk.Count -gt 0)   { $Severity = "Medium" }
        if ($HighRisk.Count -gt 0)     { $Severity = "High" }
        if ($CriticalRisk.Count -gt 0) { $Severity = "Critical" }

        $NonTrustedAgentsCount = @($AgentResults | Where-Object { $_.Trusted -eq $false }).Count
        $SuspiciousWebShellCount = @($WebShellResults | Where-Object { $_.Trusted -eq $false }).Count
        $AnomalousRbacCount    = @($RbacResults | Where-Object { $_.Trusted -eq $false }).Count
        $AnomalousEwpCount     = @($AdPrivEscResults | Where-Object { $_.Trusted -eq $false }).Count

        Add-WFLFinding `
            -Title "Exchange APT Privilege Escalation, WebShell & Persistence Audit" `
            -Severity $Severity `
            -Category "Exchange" `
            -MITRE "T1505.003, T1505.004, T1098" `
            -Tactic "Privilege Escalation / Persistence" `
            -Source "Exchange-APT-PrivEsc-Persistence-Audit" `
            -Evidence "SuspiciousWebShells=$SuspiciousWebShellCount; NonTrustedAgents=$NonTrustedAgentsCount; AnomalousRbacMembers=$AnomalousRbacCount; AnomalousEwpMembers=$AnomalousEwpCount; CriticalRisk=$($CriticalRisk.Count); HighRisk=$($HighRisk.Count)" `
            -Recommendation "Review all high-risk findings immediately. Inspect non-trusted transport agents, verify WebShell content signals in OWA/ECP auth directories, and audit RBAC and Exchange Windows Permissions group memberships. Use Show-WFLDetails -Name Exchange-APT-PrivEsc-Persistence-Audit for complete details."
    }
    catch {
        Add-WFLFinding `
            -Title "Exchange APT PrivEsc audit failed" `
            -Severity "Info" `
            -Category "Exchange" `
            -MITRE "T1505.003" `
            -Tactic "Privilege Escalation" `
            -Source "Exchange-APT-PrivEsc-Persistence-Audit" `
            -Evidence $_.Exception.Message `
            -Recommendation "Ensure Exchange PowerShell, file system access, and RSAT Active Directory modules are available."
    }
}
