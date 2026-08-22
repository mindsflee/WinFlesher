Register-WFLModule `
    -Name "AD-CoercionPrimitives" `
    -Category "Active Directory" `
    -Type "Check" `
    -MITRE "T1187" `
    -Tactic "Credential Access" `
    -Impact "POTENTIAL LATERAL MOVEMENT" `
    -Description "Audits Active Directory DCs for exposed coercion primitives (Spooler and EFS RPC interfaces)." `
        -Remediation @{
        Module        = 'AD-CoercionPrimitives'
        Category      = 'Credential Access / Lateral Movement'
        Type          = 'Specific'
        Description   = 'Audits and disables vulnerable or exposed coercion primitives (such as the Print Spooler service and legacy EFS RPC interfaces) on Domain Controllers.'
        Impact        = 'High on functionality for legacy print servers. Disabling Print Spooler on DCs stops NTLM coercion vectors (PrinterBug/PetitPotam), but ensure network printing dependencies are managed.'
        VariableGuide = 'No variables required. Operates directly on target domain controller services via administrative CimSessions.'
        Code          = @'
Stop-Service Spooler -Force; Set-Service Spooler -StartupType Disabled
'@
    } -Run {

        if (-not $Global:WinFlesher.Context.ActiveDirectory.Available) {
            Add-WFLFinding -Title "Coercion review unavailable" -Severity "Info" -Category "Active Directory" -Source "AD-CoercionPrimitives" -Evidence "AD unavailable."
            return
        }

        try {
            $DCs = Get-ADDomainController -Filter *
            $VulnerableDCs = @()

            foreach ($DC in $DCs) {
                $DCName = $DC.HostName

                $SpoolerService = Get-CimInstance -ComputerName $DCName -ClassName Win32_Service -Filter "Name='Spooler'" -ErrorAction SilentlyContinue
                $IsSpoolerRunning = ($null -ne $SpoolerService -and $SpoolerService.State -eq "Running")

                $EfsService = Get-CimInstance -ComputerName $DCName -ClassName Win32_Service -Filter "Name='EFS'" -ErrorAction SilentlyContinue
                $IsEfsActive = ($null -ne $EfsService -and $EfsService.StartMode -ne "Disabled")

                if ($IsSpoolerRunning -or $IsEfsActive) {
                    $VulnerableDCs += [PSCustomObject]@{
                        DomainController = $DCName
                        PrintSpoolerActive = $IsSpoolerRunning
                        EFSServiceActive   = $IsEfsActive
                        Risk               = "NTLM Relaying Coercion Target"
                    }
                }
            }

            Add-WFLDetail -Name "AD-CoercionPrimitives" -Data $VulnerableDCs

            $Severity = if ($VulnerableDCs.Count -gt 0) { "High" } else { "Info" }

            Add-WFLFinding `
                -Title "DC Coercion Primitives Audit" `
                -Severity $Severity `
                -Category "Active Directory" `
                -MITRE "T1187" `
                -Tactic "Credential Access" `
                -Source "AD-CoercionPrimitives" `
                -Evidence "Found $($VulnerableDCs.Count) DC(s) with active Print Spooler or EFS interfaces." `
                -Recommendation "Disable the Print Spooler service on Domain Controllers and disable EFS RPC methods if not strictly required."
        }
        catch {
            Add-WFLFinding -Title "Coercion primitives check failed" -Severity "Info" -Category "Active Directory" -Source "AD-CoercionPrimitives" -Evidence $_.Exception.Message
        }
    }


