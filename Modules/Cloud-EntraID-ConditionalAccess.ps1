Register-WFLModule `
    -Name "Cloud-EntraID-ConditionalAccess" `
    -Category "Cloud / Hybrid Identity" `
    -Type "Check" `
    -MITRE "T1562" `
    -Tactic "Defense Evasion" `
    -Impact "POTENTIAL DOMAIN COMPROMISE" `
    -Description "Reviews Conditional Access policies for critical gaps, including privileged accounts excluded from MFA or risky named locations." `
        -Remediation @{
        Module        = 'Cloud-EntraID-ConditionalAccess'
        Category      = 'Defense Evasion'
        Type          = 'Specific'
        Description   = 'Removes risky exclusions (such as privileged accounts bypassed from MFA) and closes security gaps in Entra ID Conditional Access policies.'
        Impact        = 'High. Enforces strict authentication baselines across all administrative roles.'
        VariableGuide = 'Conditional Access policy identifiers.'
        Code          = @'
Connect-MgGraph; Update-MgConditionalAccessPolicy -PolicyId <PolicyID> -State "enabled"
'@
		} -Run {
        
        $Policies = @($Global:WinFlesher.Context.EntraIDConditionalAccessPolicies)

      
        if (($null -eq $Policies -or$Policies.Count -eq 0) -and (Get-Command Get-MgConditionalAccessPolicy -ErrorAction SilentlyContinue)) {
            try {
                $mgCtx = Get-MgContext -ErrorAction SilentlyContinue
                if ($mgCtx) {
                    Import-Module Microsoft.Graph.Identity.SignIns -ErrorAction SilentlyContinue
                    $rawPolicies = Get-MgConditionalAccessPolicy -ErrorAction Stop
                    if ($rawPolicies) {
                        $Policies = @($rawPolicies | ForEach-Object {
                                $hasPrivExclusions =$false
                                if ($_.Conditions.Users.ExcludeUsers -or$_.Conditions.Users.ExcludeRoles) {
                                    $hasPrivExclusions =$true
                                }

                                [PSCustomObject]@{
                                    Id                      = $_.Id
                                    DisplayName             = $_.DisplayName
                                    State                   = $_.State
                                    HasPrivilegedExclusions = $hasPrivExclusions
                                    RawPolicy               = $_
                                }
                            }
                        )
                    }
                }
            }
            catch {}
        }

     
        if (-not $Policies -or$Policies.Count -eq 0) {
            Add-WFLFinding `
                -Title "Conditional Access policies review unavailable" `
                -Severity "Info" `
                -Category "Cloud / Hybrid Identity" `
                -Source "Cloud-EntraID-ConditionalAccess" `
                -Evidence "No active Microsoft Graph session found or zero Conditional Access policies retrieved."

            return
        }

        $Policies = @($Global:WinFlesher.Context.EntraIDConditionalAccessPolicies)

        Add-WFLDetail `
            -Name "Cloud-EntraID-ConditionalAccess" `
            -Data $Policies

        if($Policies.Count -eq 0)
        {
            Add-WFLFinding `
                -Title "Conditional Access review warning" `
                -Severity "High" `
                -Category "Cloud / Hybrid Identity" `
                -Source "Cloud-EntraID-ConditionalAccess" `
                -Evidence "No Conditional Access policies found or policy enforcement disabled."

            return
        }

        $ExcludedPrivileged = @(
            $Policies | Where-Object {
                $_.HasPrivilegedExclusions -eq $true
            }
        )

        $DisabledPolicies = @(
            $Policies | Where-Object {
                $_.State -eq "disabled"
            }
        )

        $Severity = "Low"

        if($DisabledPolicies.Count -gt 0)
        {
            $Severity = "Medium"
        }

        if($ExcludedPrivileged.Count -gt 0)
        {
            $Severity = "Critical"
        }

        Add-WFLFinding `
            -Title "Conditional Access gaps and exclusions review" `
            -Severity $Severity `
            -Category "Cloud / Hybrid Identity" `
            -MITRE "T1562" `
            -Tactic "Defense Evasion" `
            -Source "Cloud-EntraID-ConditionalAccess" `
            -Evidence "TotalPolicies=$($Policies.Count); DisabledPolicies=$($DisabledPolicies.Count); PrivilegedExclusions=$($ExcludedPrivileged.Count)" `
            -Recommendation "Ensure zero privileged accounts are excluded from core security baselines like MFA and compliant device requirements in Conditional Access."
    }


