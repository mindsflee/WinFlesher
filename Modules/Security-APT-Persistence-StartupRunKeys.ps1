Register-WFLModule `
    -Name "Security-APT-Persistence-StartupRunKeys" `
    -Category "Persistence" `
    -Type "Check" `
    -MITRE "T1547.001" `
    -Tactic "Persistence" `
    -Impact "POTENTIAL PERSISTENCE" `
    -Description "Scans Registry Run/RunOnce keys, Winlogon hijack locations, and Startup folders for suspicious persistence." `
  -Remediation @{
        Module        = 'Security-APT-Persistence-StartupRunKeys.ps1'
        Category      = 'Threat Hunting & Persistence'
        Type          = 'Specific'
        Description   = 'Remove anomalous or unauthorized startup registry execution keys (Run / RunOnce).'
        Impact        = 'Interrupts persistence mechanisms commonly exploited by malware and APTs.'
        VariableGuide = 'Replace [Nome_Chiave_Anomala] with the key identified by the analysis.'
        Code          = @'
$registryPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
$entryName = "[Nome_Chiave_Anomala]"
if (Get-ItemProperty -Path $registryPath -Name $entryName -ErrorAction SilentlyContinue) {
    Remove-ItemProperty -Path $registryPath -Name $entryName
    Write-Host "[!] Persistence key $entryName successfully removed." -ForegroundColor Yellow
}
'@
    } -Run {
        Write-Verbose "Scanning registry autostart keys and startup locations..."
        $Issues = @()
        $SuspiciousEntries = @()

        $regLocations = @(
            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run",
            "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
            "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
            "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run"
        )

        foreach ($loc in $regLocations) {
            if (Test-Path $loc) {
                $props = Get-ItemProperty -Path $loc -ErrorAction SilentlyContinue
                $propNames = $props.PSObject.Properties | Where-Object { $_.Name -notmatch "^PS" }

                foreach ($p in $propNames) {
                    $val = [string]$p.Value
                    Write-Verbose "Auditing registry autorun: [$loc] $($p.Name) -> $val"

                    if ($val -match "powershell.*-e|mshta|wscript|cscript|cmd.*\/c|AppData|Local\\Temp|Public") {
                        Write-Verbose "Suspicious autorun pattern identified: $val"
                        $SuspiciousEntries += [PSCustomObject]@{ Location = $loc; Name = $p.Name; Value = $val }
                        $Issues += "Suspicious autorun command at [$loc] '$($p.Name)': $val"
                    }
                }
            }
        }

        try {
            $winlogonShell = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "Shell" -ErrorAction SilentlyContinue
            if ($winlogonShell -and $winlogonShell -ne "explorer.exe") {
                Write-Verbose "Winlogon Shell hijacked: $winlogonShell"
                $Issues += "Winlogon Shell registry entry is modified: $winlogonShell (Expected: explorer.exe)"
            }
        } catch {}

        Add-WFLDetail -Name "Security-APT-Persistence-StartupRunKeys" -Data $SuspiciousEntries

      if ($Issues.Count -gt 0) {
        Write-Verbose "Persistence risks detected in Registry Run keys / Winlogon."
        
        $Global:WinFlesher.Details["Security-APT-Persistence-StartupRunKeys"] = $Issues

        Add-WFLFinding `
            -Title "Suspicious autostart persistence mechanisms detected" `
            -Severity "Medium" `
            -Category "Persistence" `
            -MITRE "T1547.001" `
            -Tactic "Persistence" `
            -Source "Security-APT-Persistence-StartupRunKeys" `
            -Evidence "$($Issues.Count) suspicious autostart entry(ies) detected in Registry Run keys / Winlogon." `
            -Recommendation "Inspect flagged registry paths, remove untrusted autorun values, and analyze associated binaries or scripts."
    } else {
        Write-Verbose "Startup Run Keys and Winlogon integrity check passed."
        Add-WFLFinding `
            -Title "Registry autostart persistence review passed" `
            -Severity "Info" `
            -Category "Persistence" `
            -MITRE "T1547.001" `
            -Tactic "Persistence" `
            -Source "Security-APT-Persistence-StartupRunKeys" `
            -Evidence "Checked standard HKLM/HKCU Run keys and Winlogon Shell configuration. No suspicious entries found." `
            -Recommendation "Continue monitoring autostart registry keys using EDR or Sysmon Event ID 13."
    }
    }


