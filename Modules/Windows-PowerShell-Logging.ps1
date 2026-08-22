Register-WFLModule `
    -Name "Windows-PowerShell-Logging" `
    -Category "Logging" `
    -Type "Check" `
    -MITRE "T1059.001" `
    -Tactic "Execution" `
    -Impact "NO ATTACK PATH IMPACT" `
    -Description "Checks PowerShell Script Block Logging and Module Logging policy indicators." `
        -Remediation @{
        Module        = 'Windows-PowerShell-Logging'
        Category      = 'Execution'
        Type          = 'Specific'
        Description   = 'Enables PowerShell Script Block Logging (Event ID 4104) and Module Logging via Group Policy / Registry.'
        Impact        = 'Low. Increases security telemetry and log generation volume.'
        VariableGuide = 'Registry path: HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell'
        Code          = @'
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Force; Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Name "EnableScriptBlockLogging" -Value 1
'@
    } -Run {
        Write-Verbose "Executing PowerShell logging configuration check..."
        $Logging = $Global:WinFlesher.Context.Logging

        if (-not $Logging) {
            Write-Verbose "PowerShell logging context is missing or null."
            Add-WFLFinding `
                -Title "PowerShell logging data unavailable" `
                -Severity "Info" `
                -Category "Logging" `
                -MITRE "T1059.001" `
                -Tactic "Execution" `
                -Source "Windows-PowerShell-Logging" `
                -Evidence "Logging context not found." `
                -Recommendation "Run Invoke-WFLDiscovery first."
            return
        }

        Add-WFLDetail -Name "Windows-PowerShell-Logging" -Data $Logging

        $Issues = @()

        if ($Logging.PowerShellScriptBlockLogging -ne 1) {
            Write-Verbose "Script Block Logging is not enabled via GPO/Registry policy."
            $Issues += "Script Block Logging not enabled by policy."
        }

        if ($Logging.PowerShellModuleLogging -ne $true) {
            Write-Verbose "Module Logging is not detected on the target."
            $Issues += "Module Logging not detected."
        }

        if ($Issues.Count -gt 0) {
            Write-Verbose "PowerShell logging gaps found: $($Issues -join ' | ')"
            Add-WFLFinding `
                -Title "PowerShell logging coverage gaps detected" `
                -Severity "Low" `
                -Category "Logging" `
                -MITRE "T1059.001" `
                -Tactic "Execution" `
                -Source "Windows-PowerShell-Logging" `
                -Evidence ($Issues -join " | ") `
                -Recommendation "Enable PowerShell Script Block Logging and consider Module Logging via GPO."
        }
        else {
            Write-Verbose "PowerShell logging checks passed successfully."
            Add-WFLFinding `
                -Title "PowerShell logging review passed" `
                -Severity "Info" `
                -Category "Logging" `
                -MITRE "T1059.001" `
                -Tactic "Execution" `
                -Source "Windows-PowerShell-Logging" `
                -Evidence "ScriptBlockLogging=$($Logging.PowerShellScriptBlockLogging); ModuleLogging=$($Logging.PowerShellModuleLogging)" `
                -Recommendation "Keep logging enabled and forward events to SIEM/EDR."
        }
    }


