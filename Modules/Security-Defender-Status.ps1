Register-WFLModule `
    -Name "Security-Defender-Status" `
    -Category "Endpoint Security" `
    -Type "Check" `
    -MITRE "" `
    -Tactic "Defense" `
    -Impact "NO ATTACK PATH IMPACT" `
    -Description "Checks Microsoft Defender status where available." `
        -Remediation @{
        Module        = 'Security-Defender-Status'
        Category      = 'Defense'
        Type          = 'Specific'
        Description   = 'Ensures Microsoft Defender Real-Time Protection, behavior monitoring, and cloud-delivered protection are fully enabled.'
        Impact        = 'Low. Ensures core endpoint defense mechanisms are active.'
        VariableGuide = 'No variables required.'
        Code          = @'
Set-MpPreference -DisableRealtimeMonitoring $false -DisableBehaviorMonitoring $false
'@
    } -Run {
        Write-Verbose "Checking Microsoft Defender status..."
        $Def = $Global:WinFlesher.Context.Defender

        Add-WFLDetail -Name "Security-Defender-Status" -Data $Def

        $isAvailable = $false
        if ($Def -and ($Def.Available -eq $true -or $Def.Available -eq 1 -or $Def.Available -eq "True")) {
            $isAvailable = $true
        }

        if (-not $isAvailable) {
            Write-Verbose "Defender status is unavailable or Defender is not installed."
            Add-WFLFinding `
                -Title "Microsoft Defender status unavailable" `
                -Severity "Info" `
                -Category "Endpoint Security" `
                -Source "Security-Defender-Status" `
                -Evidence "Get-MpComputerStatus unavailable or Defender not present." `
                -Recommendation "Verify whether Defender is disabled, unavailable, or intentionally secondary behind another EDR."
            return
        }

        $Issues = @()

        $realTime = [bool]($Def.RealTimeProtectionEnabled -eq $true -or $Def.RealTimeProtectionEnabled -eq 1 -or $Def.RealTimeProtectionEnabled -eq "True")
        if (-not $realTime) {
            Write-Verbose "Real-Time Protection is disabled or inactive."
            $Issues += "Real-Time Protection not enabled."
        }

        $tamper = [bool]($Def.IsTamperProtected -eq $true -or $Def.IsTamperProtected -eq 1 -or $Def.IsTamperProtected -eq 2 -or $Def.IsTamperProtected -eq "True")
        if (-not $tamper) {
            Write-Verbose "Tamper Protection is disabled or unavailable."
            $Issues += "Tamper Protection not enabled or unavailable."
        }

        if ($Issues.Count -gt 0) {
            Write-Verbose "Defender protection gaps detected: $($Issues -join ' | ')"
            Add-WFLFinding `
                -Title "Microsoft Defender protection gaps detected" `
                -Severity "Low" `
                -Category "Endpoint Security" `
                -Source "Security-Defender-Status" `
                -Evidence ($Issues -join " | ") `
                -Recommendation "Enable Defender protections where compatible or verify equivalent coverage from the primary EDR."
        }
        else {
            Write-Verbose "Microsoft Defender status review passed with all core protections active."
            Add-WFLFinding `
                -Title "Microsoft Defender status review passed" `
                -Severity "Info" `
                -Category "Endpoint Security" `
                -Source "Security-Defender-Status" `
                -Evidence "RealTimeProtection=$($Def.RealTimeProtectionEnabled); TamperProtection=$($Def.IsTamperProtected)" `
                -Recommendation "Keep protections enabled and monitored."
        }
    }


