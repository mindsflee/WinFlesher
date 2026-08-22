Register-WFLModule `
    -Name "LPE-TokenHijack" `
    -Category "Privilege Escalation" `
    -Type "Check" `
    -MITRE "T1134.001" `
    -Tactic "Privilege Escalation" `
    -Impact "POTENTIAL PRIVILEGE ESCALATION" `
    -Description "Fast audit of active processes owned by Domain Admin / Tier-0 accounts suitable for token theft." `
-Remediation @{
        Module        = 'LPE-TokenHijack.ps1'
        Category      = 'Local Privilege Escalation'
        Type          = 'Specific'
        Description   = 'Restrict debugging permissions and user rights auditing to prevent Token Impersonation techniques.'
        Impact        = 'Reduces the risk of access token theft (e.g., SeDebugPrivilege) by unauthorized processes.'
        VariableGuide = 'No variables required (modifies local security policy via secedit).'
        Code          = @'
$secFile = "$env:TEMP\secpol.cfg"
secedit /export /cfg $secFile
(Get-Content $secFile) -replace "SeDebugPrivilege =.*", "SeDebugPrivilege = *S-1-5-32-544" | Set-Content $secFile
secedit /configure /db "$env:windir\security\local.sdb" /cfg $secFile /areas USER_RIGHTS
Remove-Item $secFile -Force
Write-Host "[+] Debug privileges restricted to the Administrators group." -ForegroundColor Green
'@
    } -Run {

        $IsAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
        if (-not $IsAdmin) {
            Add-WFLFinding `
                -Title "Token hijack review skipped" `
                -Severity "Info" `
                -Category "Privilege Escalation" `
                -MITRE "T1134.001" `
                -Tactic "Privilege Escalation" `
                -Source "LPE-TokenHijack" `
                -Evidence "Execution requires elevated privileges (Run as Administrator) to inspect process owners." `
                -Recommendation "Re-run WinFlesher inside an elevated PowerShell prompt."
            return
        }

        if (-not $Global:WinFlesher.Context.ActiveDirectory.Available) {
            Add-WFLFinding -Title "Token hijack review unavailable" -Severity "Info" -Category "Privilege Escalation" -Source "LPE-TokenHijack" -Evidence "AD unavailable."
            return
        }

        try {
            $TargetGroups = @("Domain Admins", "Enterprise Admins", "Schema Admins")
            $HighPrivUsers = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)

            foreach ($Group in $TargetGroups) {
                $Members = Get-ADGroupMember -Identity $Group -Recursive -ErrorAction SilentlyContinue | Select-Object -ExpandProperty SamAccountName
                if ($Members) { 
                    foreach ($M in $Members) { [void]$HighPrivUsers.Add($M) }
                }
            }

            if ($HighPrivUsers.Count -eq 0) {
                Add-WFLFinding -Title "High-Privilege Session Token Exposure" -Severity "Info" -Category "Privilege Escalation" -MITRE "T1134.001" -Tactic "Privilege Escalation" -Source "LPE-TokenHijack" -Evidence "No active Tier-0 accounts identified in target groups."
                return
            }

            $ExposedTokens = @()
            $Processes = Get-Process -IncludeUserName -ErrorAction SilentlyContinue

            foreach ($Proc in $Processes) {
                if ($null -ne $Proc.UserName) {
                    $UserOnly = $Proc.UserName.Split('\')[-1]

                    if ($HighPrivUsers.Contains($UserOnly)) {
                        $ExposedTokens += [PSCustomObject]@{
                            ProcessName = $Proc.ProcessName
                            PID         = $Proc.Id
                            Account     = $Proc.UserName
                            Path        = $Proc.Path
                        }
                    }
                }
            }

            Add-WFLDetail -Name "LPE-TokenHijack" -Data $ExposedTokens

            $Severity = if ($ExposedTokens.Count -gt 0) { "High" } else { "Info" }

            Add-WFLFinding `
                -Title "High-Privilege Session Token Exposure" `
                -Severity $Severity `
                -Category "Privilege Escalation" `
                -MITRE "T1134.001" `
                -Tactic "Privilege Escalation" `
                -Source "LPE-TokenHijack" `
                -Evidence "Found $($ExposedTokens.Count) active process(es) owned by Tier-0 / Domain Admin accounts on this host." `
                -Recommendation "Enforce Restricted Admin mode for RDP sessions and ensure Tier-0 accounts do not log into lower-tier systems."
        }
        catch {
            Add-WFLFinding -Title "Token hijack review failed" -Severity "Info" -Category "Privilege Escalation" -Source "LPE-TokenHijack" -Evidence $_.Exception.Message
        }
    }


