Register-WFLModule `
    -Name "AD-TrustSecurity" `
    -Category "Active Directory" `
    -Type "Check" `
    -MITRE "T1484" `
    -Tactic "Lateral Movement" `
    -Impact "POTENTIAL LATERAL MOVEMENT" `
    -Description "Reviews Active Directory domain and forest trust configurations, SID filtering, and selective authentication." `
        -Remediation @{
        Module        = 'AD-TrustSecurity'
        Category      = 'Lateral Movement'
        Type          = 'Specific'
        Description   = 'Enforces SID filtering and selective authentication on forest and domain trusts to prevent inter-domain privilege escalation.'
        Impact        = 'Moderate. May impact cross-forest resource access if selective authentication rules are misconfigured.'
        VariableGuide = '$TrustName: The target domain or forest trust relationship.'
        Code          = @'
Set-ADTrust -Identity "TargetDomain.local" -SidFilteringEnabled $true
'@
    } -Run {
        if (-not $Global:WinFlesher.Context.ActiveDirectory.Available) { return }

        try {
            $Trusts = Get-ADTrust -Filter * -ErrorAction SilentlyContinue
            $RiskyTrusts = @()

            foreach ($Trust in $Trusts) {
                if ($Trust.TrustType -eq "Uplevel" -or $Trust.TrustType -eq "Forest") {
                    if (-not $Trust.SidFilteringForestAware -or -not $Trust.SelectiveAuthentication) {
                        $RiskyTrusts += [PSCustomObject]@{
                            TargetDomain = $Trust.Name
                            TrustDirection = $Trust.TrustDirection
                            SIDFiltering = $Trust.SidFilteringForestAware
                            SelectiveAuth = $Trust.SelectiveAuthentication
                        }
                    }
                }
            }

            Add-WFLDetail -Name "AD-TrustSecurity" -Data $RiskyTrusts
            $Severity = if ($RiskyTrusts.Count -gt 0) { "Medium" } else { "Info" }

            Add-WFLFinding `
                -Title "AD Forest Trust Hardening Review" `
                -Severity $Severity `
                -Category "Active Directory" `
                -MITRE "T1484" `
                -Tactic "Lateral Movement" `
                -Source "AD-TrustSecurity" `
                -Evidence "Found $($RiskyTrusts.Count) trust relationship(s) lacking SID Filtering or Selective Authentication enforcement." `
                -Recommendation "Enable SID Filtering on all external/forest trusts and enforce Selective Authentication where domain boundaries strictly require it."
        }
        catch {
            Add-WFLFinding -Title "Trust security check failed" -Severity "Info" -Category "Active Directory" -Source "AD-TrustSecurity" -Evidence $_.Exception.Message
        }
    }


