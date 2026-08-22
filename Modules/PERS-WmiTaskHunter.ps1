Register-WFLModule `
    -Name "PERS-WmiTaskHunter" `
    -Category "Persistence" `
    -Type "Check" `
    -MITRE "T1546.003" `
    -Tactic "Persistence" `
    -Impact "POTENTIAL PERSISTENCE" `
    -Description "Audits WMI Event Subscriptions and Scheduled Tasks running elevated scripts for persistence." `
        -Remediation @{
        Module        = 'PERS-WmiTaskHunter'
        Category      = 'Persistence'
        Type          = 'Specific'
        Description   = 'Audits and cleans up unauthorized WMI Event Subscriptions and suspicious scheduled tasks running elevated scripts.'
        Impact        = 'Moderate. Review scheduled task scripts before deletion to ensure legitimate automation is not disrupted.'
        VariableGuide = 'Task paths and WMI event filters.'
		  Code          = @'
'@
    } -Run {
  try {
            $PersistenceFindings = @()

            $WmiConsumers = Get-CimInstance -Namespace "root\subscription" -ClassName __EventConsumer -ErrorAction SilentlyContinue
            foreach ($Consumer in $WmiConsumers) {
                $PersistenceFindings += [PSCustomObject]@{
                    Type        = "WMI Event Consumer"
                    Name        = $Consumer.Name
                    Detail      = $Consumer.CommandLineTemplate
                    Location    = "root\subscription"
                }
            }

            $Tasks = Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object { 
                $_.State -ne "Disabled" -and 
                $_.Principal.RunLevel -eq "HighestAvailable" -and
                $_.Actions.Execute -match "powershell|cmd|wscript|cscript"
            }

            foreach ($Task in $Tasks) {
                if ($Task.TaskPath -like "\Microsoft\Windows\*") { continue }

                $Exec = $Task.Actions | ForEach-Object { "$($_.Execute) $($_.Arguments)" } -join " | "
                $PersistenceFindings += [PSCustomObject]@{
                    Type     = "Elevated Scheduled Task"
                    Name     = $Task.TaskName
                    Detail   = $Exec
                    Location = $Task.TaskPath
                }
            }

            Add-WFLDetail -Name "PERS-WmiTaskHunter" -Data $PersistenceFindings

            $Severity = if ($PersistenceFindings.Count -gt 0) { "Medium" } else { "Info" }

            Add-WFLFinding `
                -Title "Persistence Mechanisms Review (WMI & Scheduled Tasks)" `
                -Severity $Severity `
                -Category "Persistence" `
                -MITRE "T1546.003" `
                -Tactic "Persistence" `
                -Source "PERS-WmiTaskHunter" `
                -Evidence "Found $($PersistenceFindings.Count) potential persistence entries (WMI Consumers or custom elevated tasks)." `
                -Recommendation "Review custom WMI subscriptions and non-standard elevated Scheduled Tasks to confirm legitimacy."
        }
        catch {
            Add-WFLFinding -Title "Persistence hunter failed" -Severity "Info" -Category "Persistence" -Source "PERS-WmiTaskHunter" -Evidence $_.Exception.Message
        }
    }


