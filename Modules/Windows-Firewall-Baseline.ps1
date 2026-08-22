Register-WFLModule `
    -Name "Windows-Firewall-Baseline" `
    -Category "Network Security" `
    -Type "Check" `
    -MITRE "" `
    -Tactic "Defense" `
    -Impact "NO ATTACK PATH IMPACT" `
    -Description "Checks Windows Firewall profile status and default inbound policy." `
        -Remediation @{
        Module        = 'Windows-Firewall-Baseline'
        Category      = 'Defense'
        Type          = 'Specific'
        Description   = 'Enforces Windows Firewall profiles (Domain, Private, Public) and sets default inbound blocking policy.'
        Impact        = 'Moderate. Ensure required inbound application firewall rules are pre-configured.'
        VariableGuide = 'Profile targets: Domain, Private, Public.'
        Code          = @'
Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled True -DefaultInboundAction Block
'@
    } -Run {
        $Profiles = $Global:WinFlesher.Context.Firewall

        if (-not $Profiles) {
            Add-WFLFinding `
                -Title "Firewall profile data unavailable" `
                -Severity "Info" `
                -Category "Network Security" `
                -Source "Windows-Firewall-Baseline" `
                -Evidence "Firewall context not found." `
                -Recommendation "Run Invoke-WFLDiscovery first."
            return
        }

        $Disabled = $Profiles | Where-Object { $_.Enabled -ne $true }
        $InboundNotBlock = $Profiles | Where-Object { $_.DefaultInboundAction -ne "Block" }

        Add-WFLDetail -Name "Windows-Firewall-Baseline" -Data $Profiles

        if (@($Disabled).Count -gt 0) {
            $Severity = "Medium"
        }
        elseif (@($InboundNotBlock).Count -gt 0) {
            $Severity = "Low"
        }
        else {
            $Severity = "Info"
        }

        Add-WFLFinding `
            -Title "Windows Firewall baseline review" `
            -Severity $Severity `
            -Category "Network Security" `
            -Source "Windows-Firewall-Baseline" `
            -Evidence "Profiles=$(@($Profiles).Count); Disabled=$(@($Disabled).Count); InboundNotBlock=$(@($InboundNotBlock).Count)" `
            -Recommendation "Enable firewall profiles and prefer default inbound Block with explicit allow rules where compatible."
    }



