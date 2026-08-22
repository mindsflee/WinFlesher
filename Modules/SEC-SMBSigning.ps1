Register-WFLModule `
    -Name "SEC-SMBSigning" `
    -Category "Network Security" `
    -Type "Check" `
    -MITRE "T1557" `
    -Tactic "Credential Access" `
    -Impact "POTENTIAL LATERAL MOVEMENT" `
    -Description "Reviews SMB signing configuration on Domain Controllers and the local host." `
        -Remediation @{
        Module        = 'SEC-SMBSigning'
        Category      = 'Credential Access / Lateral Movement'
        Type          = 'Specific'
        Description   = 'Enforces SMB packet signing on local systems and domain controllers to prevent NTLM relay and adversary-in-the-middle attacks.'
        Impact        = 'Low. Enforces cryptographic validation of SMB data packets.'
        VariableGuide = 'Registry keys under LanmanWorkstation and LanmanServer.'
        Code          = @'
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" -Name "RequireSecuritySignature" -Value 1
'@
    } -Run {

        try {

            $Results = @()
            $Errors = @()

            $DomainControllers = @()

            if ($Global:WinFlesher.Context.ActiveDirectory.Available) {
                try {
                    $DomainControllers = @(
                        Get-ADDomainController -Filter * -ErrorAction Stop
                    )
                }
                catch {
                    $Errors += [PSCustomObject]@{
                        Target = "ActiveDirectory"
                        Error  = $_.Exception.Message
                    }
                }
            }

            if ($DomainControllers.Count -eq 0) {
                $DomainControllers = @(
                    [PSCustomObject]@{
                        HostName = $env:COMPUTERNAME
                        Name     = $env:COMPUTERNAME
                    }
                )
            }

            foreach ($DC in $DomainControllers) {

                $Target = [string]$DC.HostName

                if ([string]::IsNullOrWhiteSpace($Target)) {
                    $Target = [string]$DC.Name
                }

                try {

                    $Config = $null

                    if (
                        $Target -eq $env:COMPUTERNAME -or
                        $Target -eq "$env:COMPUTERNAME.$env:USERDNSDOMAIN"
                    ) {
                        $Config = Get-SmbServerConfiguration -ErrorAction Stop
                    }
                    else {
                        $Config = Invoke-Command `
                            -ComputerName $Target `
                            -ScriptBlock {
                                Get-SmbServerConfiguration
                            } `
                            -ErrorAction Stop
                    }

                    $RequireSigning = [bool]$Config.RequireSecuritySignature
                    $EnableSigning  = [bool]$Config.EnableSecuritySignature
                    $EnableSMB1     = [bool]$Config.EnableSMB1Protocol

                    $Severity = "Info"
                    $Exploitability = "Informational"
                    $RiskReasons = @()

                    if (-not $RequireSigning) {
                        $Severity = "High"
                        $Exploitability = "Likely"
                        $RiskReasons += "SMB server signing is not required"
                    }

                    if (-not $EnableSigning) {
                        if ($Severity -eq "Info") {
                            $Severity = "Medium"
                        }
                        $RiskReasons += "SMB server signing is not enabled"
                    }

                    if ($EnableSMB1) {
                        if ($Severity -eq "Info") {
                            $Severity = "Medium"
                        }
                        $RiskReasons += "SMBv1 is enabled"
                    }

                    if ($RiskReasons.Count -eq 0) {
                        $RiskReasons += "SMB signing baseline appears enforced"
                    }

                    $Results += [PSCustomObject]@{
                        Target                   = $Target
                        RequireSecuritySignature = $RequireSigning
                        EnableSecuritySignature  = $EnableSigning
                        EnableSMB1Protocol       = $EnableSMB1
                        Severity                 = $Severity
                        Exploitability           = $Exploitability
                        RiskReason               = ($RiskReasons -join "; ")
                    }
                }
                catch {
                    $Errors += [PSCustomObject]@{
                        Target = $Target
                        Error  = $_.Exception.Message
                    }
                }
            }

            Add-WFLDetail `
                -Name "SEC-SMBSigning" `
                -Data $Results

            Add-WFLDetail `
                -Name "SEC-SMBSigning-Errors" `
                -Data $Errors

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

            $Severity = "Info"

            if ($MediumCount -gt 0) {
                $Severity = "Medium"
            }

            if ($HighCount -gt 0) {
                $Severity = "High"
            }

            if ($Results.Count -eq 0 -and $Errors.Count -gt 0) {
                Add-WFLFinding `
                    -Title "SMB signing review incomplete" `
                    -Severity "Low" `
                    -Category "Network Security" `
                    -MITRE "T1557" `
                    -Tactic "Credential Access" `
                    -Source "SEC-SMBSigning" `
                    -Evidence "TargetsReviewed=0; Errors=$($Errors.Count)" `
                    -Recommendation "Review SEC-SMBSigning-Errors. Verify WinRM permissions or run locally on Domain Controllers."
                return
            }

            if ($HighCount -eq 0 -and $MediumCount -eq 0) {
                Add-WFLFinding `
                    -Title "SMB signing review passed" `
                    -Severity "Info" `
                    -Category "Network Security" `
                    -MITRE "T1557" `
                    -Tactic "Credential Access" `
                    -Source "SEC-SMBSigning" `
                    -Evidence "TargetsReviewed=$($Results.Count); SMBSigningNotRequired=0; SMB1Enabled=0; Errors=$($Errors.Count)" `
                    -Recommendation "No SMB signing baseline gaps detected on reviewed targets."
                return
            }

            Add-WFLFinding `
                -Title "SMB signing baseline gaps detected" `
                -Severity $Severity `
                -Category "Network Security" `
                -MITRE "T1557" `
                -Tactic "Credential Access" `
                -Source "SEC-SMBSigning" `
                -Evidence "TargetsReviewed=$($Results.Count); High=$HighCount; Medium=$MediumCount; Errors=$($Errors.Count)" `
                -Recommendation "Require SMB signing on Domain Controllers and disable SMBv1. Prioritize DCs where RequireSecuritySignature is False."

        }
        catch {
            Add-WFLFinding `
                -Title "SMB signing review failed" `
                -Severity "Info" `
                -Category "Network Security" `
                -MITRE "T1557" `
                -Tactic "Credential Access" `
                -Source "SEC-SMBSigning" `
                -Evidence $_.Exception.Message `
                -Recommendation "Verify PowerShell SMB cmdlets and permissions."
        }
    }


