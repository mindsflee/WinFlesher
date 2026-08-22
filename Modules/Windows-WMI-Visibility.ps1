Register-WFLModule `
    -Name "Windows-WMI-Visibility" `
    -Category "Logging" `
    -Type "Check" `
    -MITRE "T1047" `
    -Tactic "Execution" `
    -Impact "NO ATTACK PATH IMPACT" `
    -Description "Checks WMI Activity logging and permanent WMI event subscriptions." `
        -Remediation @{
        Module        = 'Windows-WMI-Visibility'
        Category      = 'Execution'
        Type          = 'Specific'
        Description   = 'Enables WMI Activity logging and sweeps for unauthorized permanent WMI event subscriptions used for persistence.'
        Impact        = 'Low. Improves visibility into WMI execution vectors.'
        VariableGuide = 'No variables required.'
        Code          = @'
Get-CimInstance -Namespace root\subscription -ClassName __EventFilter | Remove-CimInstance -Confirm:$false
'@
    } -Run {
        $Logging = $Global:WinFlesher.Context.Logging

        $FindingSeverity = "Info"
        $Evidence = @()

        if ($Logging.WMIActivityOperational -ne $true) {
            $FindingSeverity = "Medium"
            $Evidence += "WMI Activity Operational log not enabled."
        }

        try {
            $Filters = Get-CimInstance -Namespace root\subscription -ClassName __EventFilter -ErrorAction SilentlyContinue
            $Consumers = Get-CimInstance -Namespace root\subscription -ClassName __EventConsumer -ErrorAction SilentlyContinue
            $Bindings = Get-CimInstance -Namespace root\subscription -ClassName __FilterToConsumerBinding -ErrorAction SilentlyContinue

            $Details = [PSCustomObject]@{
                Filters   = @($Filters)
                Consumers = @($Consumers)
                Bindings  = @($Bindings)
            }

            Add-WFLDetail -Name "Windows-WMI-Visibility" -Data $Details

            $Total = @($Filters).Count + @($Consumers).Count + @($Bindings).Count

            if ($Total -gt 0) {
                $FindingSeverity = "Medium"
                $Evidence += "Permanent WMI subscription objects found. Filters=$(@($Filters).Count); Consumers=$(@($Consumers).Count); Bindings=$(@($Bindings).Count)."
            }
        }
        catch {
            $Evidence += "Unable to query WMI subscriptions: $($_.Exception.Message)"
        }

        if ($Evidence.Count -eq 0) {
            $Evidence += "WMI Activity Operational=$($Logging.WMIActivityOperational); no permanent subscription objects detected."
        }

        Add-WFLFinding `
            -Title "WMI visibility review" `
            -Severity $FindingSeverity `
            -Category "Logging" `
            -MITRE "T1047" `
            -Tactic "Execution" `
            -Source "Windows-WMI-Visibility" `
            -Evidence ($Evidence -join " | ") `
            -Recommendation "Enable and forward WMI Activity logs. Review permanent WMI subscriptions where present."
    }



