Register-WFLModule `
    -Name "SEC-DNSDynamicUpdates" `
    -Category "Network Security" `
    -Type "Check" `
    -MITRE "T1557" `
    -Tactic "Credential Access" `
    -Impact "POTENTIAL DNS HIJACKING AND MAN-IN-THE-MIDDLE" `
    -Description "Reviews DNS zones hosted on Domain Controllers and identifies zones that accept non-secure dynamic updates." `
    -Remediation @{
        Module        = 'SEC-DNSDynamicUpdates'
        Category      = 'Credential Access / Man-in-the-Middle'
        Type          = 'Specific'
        Description   = 'Disables non-secure DNS dynamic updates. Active Directory-integrated zones are configured to accept secure updates only, while non-AD-integrated zones are configured to reject dynamic updates.'
        Impact        = 'Medium. Incorrect changes may prevent clients or DHCP servers from dynamically registering DNS records.'
        VariableGuide = 'Review the DNS server and zone name before applying the remediation. Secure dynamic updates require an Active Directory-integrated zone.'
        Code          = @'
$DnsServer = "DC01.contoso.local"
$ZoneName  = "contoso.local"

$Zone = Get-DnsServerZone `
    -ComputerName $DnsServer `
    -Name $ZoneName `
    -ErrorAction Stop

if ($Zone.IsDsIntegrated) {
    Set-DnsServerPrimaryZone `
        -ComputerName $DnsServer `
        -Name $ZoneName `
        -DynamicUpdate Secure `
        -ErrorAction Stop
}
else {
    Set-DnsServerPrimaryZone `
        -ComputerName $DnsServer `
        -Name $ZoneName `
        -DynamicUpdate None `
        -ErrorAction Stop
}
'@
    } -Run {

        try {

            $Results = @()
            $Errors = @()
            $DnsServers = @()

            if (
                $Global:WinFlesher.Context.ActiveDirectory.Available -and
                (Get-Command Get-ADDomainController -ErrorAction SilentlyContinue)
            ) {
                try {
                    $DnsServers = @(
                        Get-ADDomainController `
                            -Filter * `
                            -ErrorAction Stop |
                        Where-Object {
                            $_.HostName
                        } |
                        Select-Object -ExpandProperty HostName -Unique
                    )
                }
                catch {
                    $Errors += [PSCustomObject]@{
                        Target = "ActiveDirectory"
                        Stage  = "DomainControllerDiscovery"
                        Error  = $_.Exception.Message
                    }
                }
            }

            if ($DnsServers.Count -eq 0) {
                $LocalTarget = $env:COMPUTERNAME

                if (-not [string]::IsNullOrEmpty($env:USERDNSDOMAIN)) {
                    $LocalTarget = "$env:COMPUTERNAME.$env:USERDNSDOMAIN"
                }

                $DnsServers = @(
                    $LocalTarget
                )
            }

            foreach ($DnsServer in $DnsServers) {

                if ([string]::IsNullOrEmpty($DnsServer)) {
                    continue
                }

                try {
                   
                    $Zones = @(
                        Get-CimInstance `
                            -ComputerName $DnsServer `
                            -Namespace "root\MicrosoftDNS" `
                            -ClassName "MicrosoftDNS_Zone" `
                            -ErrorAction Stop
                    )

                    foreach ($Zone in $Zones) {

                        try {
                            $ZoneName = [string]$Zone.ContainerName
                            
                           
                            $RawZoneType = [int]$Zone.ZoneType
                            $ZoneType = switch ($RawZoneType) {
                                1 { "Primary" }
                                2 { "Secondary" }
                                3 { "Stub" }
                                4 { "Forwarder" }
                                default { "Primary" }
                            }

                           
                            $RawAllowUpdate = [int]$Zone.AllowUpdate
                            $DynamicUpdate = switch ($RawAllowUpdate) {
                                0 { "None" }
                                1 { "Nonsecure and secure" }
                                2 { "Secure" }
                                default { "None" }
                            }

                           
                            $IsDsIntegrated = [bool]$Zone.DsIntegrated
                            
                          
                            $IsReverseLookupZone = $false
                            if ($ZoneName -like "*.in-addr.arpa" -or $ZoneName -like "*.ip6.arpa") {
                                $IsReverseLookupZone = $true
                            }

                            $IsAutoCreated = $false
                            if ($ZoneName -eq "TrustAnchors" -or $ZoneName -eq "RootDNSServers") {
                                $IsAutoCreated = $true
                            }

                            $Severity = "Info"
                            $Exploitability = "Informational"
                            $RiskReasons = @()
                            $IsVulnerable = $false
                            $AcceptsNonSecureUpdates = $false

                            if (
                                $DynamicUpdate -eq "NonsecureAndSecure" -or
                                $DynamicUpdate -eq "Nonsecure and secure"
                            ) {
                                $AcceptsNonSecureUpdates = $true
                            }

                            if (
                                $ZoneType -eq "Primary" -and
                                $AcceptsNonSecureUpdates
                            ) {
                                $Severity = "High"
                                $Exploitability = "Likely"
                                $IsVulnerable = $true

                                $RiskReasons += "The primary DNS zone accepts unauthenticated dynamic updates"

                                if ($IsDsIntegrated) {
                                    $RiskReasons += "The Active Directory-integrated zone is not restricted to secure dynamic updates"
                                }
                                else {
                                    $RiskReasons += "The non-AD-integrated primary zone permits non-secure record registration"
                                }

                                if ($IsReverseLookupZone) {
                                    $RiskReasons += "An attacker may create or manipulate PTR records in the reverse lookup zone"
                                }
                                else {
                                    $RiskReasons += "An attacker may create or manipulate forward lookup records and redirect name resolution"
                                }
                            }
                            elseif (
                                $ZoneType -eq "Primary" -and
                                $DynamicUpdate -eq "Secure"
                            ) {
                                $RiskReasons += "The primary zone accepts secure dynamic updates only"
                            }
                            elseif (
                                $ZoneType -eq "Primary" -and
                                $DynamicUpdate -eq "None"
                            ) {
                                $RiskReasons += "Dynamic updates are disabled for the primary zone"
                            }
                            elseif ($ZoneType -ne "Primary") {
                                $RiskReasons += "The zone is not primary and does not directly process authoritative dynamic updates"
                            }
                            else {
                                $RiskReasons += "No insecure dynamic update configuration was detected"
                            }

                            if ($IsAutoCreated) {
                                $RiskReasons += "The zone is automatically created by the DNS service"
                            }

                            $Results += [PSCustomObject]@{
                                DnsServer                = [string]$DnsServer
                                ZoneName                 = $ZoneName
                                ZoneType                 = $ZoneType
                                DynamicUpdate            = $DynamicUpdate
                                IsDsIntegrated           = $IsDsIntegrated
                                IsReverseLookupZone      = $IsReverseLookupZone
                                IsAutoCreated            = $IsAutoCreated
                                AcceptsNonSecureUpdates  = $AcceptsNonSecureUpdates
                                IsVulnerable             = $IsVulnerable
                                Severity                 = $Severity
                                Exploitability           = $Exploitability
                                RiskReason               = ($RiskReasons -join "; ")
                            }
                        }
                        catch {
                            $Errors += [PSCustomObject]@{
                                Target = "$DnsServer\$($Zone.ContainerName)"
                                Stage  = "ZoneAnalysis"
                                Error  = $_.Exception.Message
                            }
                        }
                    }
                }
                catch {
                    $Errors += [PSCustomObject]@{
                        Target = [string]$DnsServer
                        Stage  = "DnsZoneEnumeration"
                        Error  = $_.Exception.Message
                    }
                }
            }

            Add-WFLDetail `
                -Name "SEC-DNSDynamicUpdates" `
                -Data $Results

            Add-WFLDetail `
                -Name "SEC-DNSDynamicUpdates-Errors" `
                -Data $Errors

            $ReviewedServers = @(
                $Results |
                Select-Object -ExpandProperty DnsServer -Unique
            ).Count

            $ReviewedZones = @(
                $Results
            ).Count

            $VulnerableZones = @(
                $Results |
                Where-Object {
                    $_.IsVulnerable -eq $true
                }
            )

            $VulnerableZoneCount = $VulnerableZones.Count

            $VulnerableForwardZones = @(
                $VulnerableZones |
                Where-Object {
                    $_.IsReverseLookupZone -eq $false
                }
            ).Count

            $VulnerableReverseZones = @(
                $VulnerableZones |
                Where-Object {
                    $_.IsReverseLookupZone -eq $true
                }
            ).Count

            $VulnerableAdIntegratedZones = @(
                $VulnerableZones |
                Where-Object {
                    $_.IsDsIntegrated -eq $true
                }
            ).Count

            $VulnerableZoneNames = @(
                $VulnerableZones |
                ForEach-Object {
                    "$($_.DnsServer):$($_.ZoneName)"
                } |
                Select-Object -Unique
            )

            if (
                $Results.Count -eq 0 -and
                $Errors.Count -gt 0
            ) {
                Add-WFLFinding `
                    -Title "DNS dynamic update review incomplete" `
                    -Severity "Low" `
                    -Category "Network Security" `
                    -MITRE "T1557" `
                    -Tactic "Credential Access" `
                    -Source "SEC-DNSDynamicUpdates" `
                    -Evidence "DnsServersReviewed=0; ZonesReviewed=0; Errors=$($Errors.Count)" `
                    -Recommendation "Review SEC-DNSDynamicUpdates-Errors. Verify WMI/RPC network connectivity and permissions on the DNS servers."

                return
            }

            if ($VulnerableZoneCount -eq 0) {
                Add-WFLFinding `
                    -Title "DNS dynamic update security review passed" `
                    -Severity "Info" `
                    -Category "Network Security" `
                    -MITRE "T1557" `
                    -Tactic "Credential Access" `
                    -Source "SEC-DNSDynamicUpdates" `
                    -Evidence "DnsServersReviewed=$ReviewedServers; ZonesReviewed=$ReviewedZones; ZonesAcceptingNonSecureUpdates=0; Errors=$($Errors.Count)" `
                    -Recommendation "No primary DNS zones accepting non-secure dynamic updates were detected. Maintain secure-only updates for AD-integrated zones and periodically review DNS zone permissions."

                return
            }

            $Evidence = @(
                "DnsServersReviewed=$ReviewedServers"
                "ZonesReviewed=$ReviewedZones"
                "ZonesAcceptingNonSecureUpdates=$VulnerableZoneCount"
                "ForwardZones=$VulnerableForwardZones"
                "ReverseZones=$VulnerableReverseZones"
                "ADIntegratedZones=$VulnerableAdIntegratedZones"
                "Errors=$($Errors.Count)"
            ) -join "; "

            if ($VulnerableZoneNames.Count -gt 0) {
                $Evidence += "; AffectedZones=$($VulnerableZoneNames -join ', ')"
            }

            Add-WFLFinding `
                -Title "DNS zones accept non-secure dynamic updates" `
                -Severity "High" `
                -Category "Network Security" `
                -MITRE "T1557" `
                -Tactic "Credential Access" `
                -Source "SEC-DNSDynamicUpdates" `
                -Evidence $Evidence `
                -Recommendation "Configure AD-integrated primary zones to use Secure dynamic updates only. Disable dynamic updates on non-AD-integrated zones unless explicitly required. Review DHCP DNS credentials, DNS record ownership and zone ACLs before enforcing the change."

        }
        catch {
            Add-WFLFinding `
                -Title "DNS dynamic update review failed" `
                -Severity "Info" `
                -Category "Network Security" `
                -MITRE "T1557" `
                -Tactic "Credential Access" `
                -Source "SEC-DNSDynamicUpdates" `
                -Evidence $_.Exception.Message `
                -Recommendation "Verify that WMI service is running on the target DNS servers and that the executing account has rights to query the root\MicrosoftDNS namespace."
        }
    }