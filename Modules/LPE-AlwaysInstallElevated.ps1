Register-WFLModule `
    -Name "LPE-AlwaysInstallElevated" `
    -Category "Privilege Escalation" `
    -Type "Check" `
    -MITRE "T1546.015" `
    -Tactic "Privilege Escalation" `
    -Impact "POTENTIAL PRIVILEGE ESCALATION" `
    -Description "Audits AlwaysInstallElevated registry keys to detect potential MSI-based privilege escalation vectors." `
     -Remediation @{
        Module        = 'LPE-AlwaysInstallElevated.ps1'
        Category      = 'Local Privilege Escalation'
        Type          = 'Specific'
        Description   = 'Remove Windows registry keys that allow MSI package installation with SYSTEM privileges.'
        Impact        = 'Blocks a classic local privilege escalation vector leveraging Microsoft installer files.'
        VariableGuide = 'No variables required (standard policy registry keys).'
        Code          = @'
$paths = "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer", "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer"
foreach ($path in $paths) {
    if (-not (Test-Path $path)) { New-Item -Path $path -Force | Out-Null }
    Set-ItemProperty -Path $path -Name "AlwaysInstallElevated" -Value 0 -Type DWord
}
Write-Host "[+] AlwaysInstallElevated policy disabled successfully." -ForegroundColor Green
'@
    } -Run {

        $RegistryFindings = @()
        
        $Paths = @(
            "Registry::HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\Windows\Installer",
            "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Installer"
        )

        foreach ($path in $Paths) {
            try {
                if (Test-Path $path -ErrorAction SilentlyContinue) {
                    $val = Get-ItemProperty -Path $path -Name "AlwaysInstallElevated" -ErrorAction SilentlyContinue
                    if ($val -and $val.AlwaysInstallElevated -eq 1) {
                        $RegistryFindings += [PSCustomObject]@{
                            RegistryPath = $path
                            Setting      = "AlwaysInstallElevated"
                            Value        = 1
                        }
                    }
                }
            }
            catch {
            }
        }

        Add-WFLDetail `
            -Name "LPE-AlwaysInstallElevated" `
            -Data $RegistryFindings

        if($RegistryFindings.Count -eq 0)
        {
            Add-WFLFinding `
                -Title "AlwaysInstallElevated review passed" `
                -Severity "Info" `
                -Category "Privilege Escalation" `
                -Source "LPE-AlwaysInstallElevated" `
                -Evidence "AlwaysInstallElevated policies are not enabled."

            return
        }

        $Severity = "High"

        Add-WFLFinding `
            -Title "AlwaysInstallElevated privilege escalation exposure" `
            -Severity $Severity `
            -Category "Privilege Escalation" `
            -MITRE "T1546.015" `
            -Tactic "Privilege Escalation" `
            -Source "LPE-AlwaysInstallElevated" `
            -Evidence "VulnerableRegistryKeysCount=$($RegistryFindings.Count)" `
            -Recommendation "Disable AlwaysInstallElevated policies in both HKCU and HKLM registry hives to prevent unauthorized MSI privilege escalation."
    }


