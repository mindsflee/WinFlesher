Register-WFLModule `
    -Name "Security-APT-AMSI-RegistryHooks" `
    -Category "Defense Evasion" `
    -Type "Check" `
    -MITRE "T1562.001" `
    -Tactic "Defense Evasion" `
    -Impact "NO ATTACK PATH IMPACT" `
    -Description "Audits AMSI (Antimalware Scan Interface) registry integrity and provider hijacking indicators." `
        -Remediation @{
        Module        = 'Security-APT-AMSI-RegistryHooks'
        Category      = 'Defense Evasion'
        Type          = 'Specific'
        Description   = 'Audits and restores AMSI (Antimalware Scan Interface) registry integrity and provider configurations to prevent security bypasses.'
        Impact        = 'Low. Restores native script scanning telemetry.'
        VariableGuide = 'Registry paths under HKLM:\SOFTWARE\Microsoft\AMSI'
        Code          = @'
Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\AMSIProviders" -Name "BadProvider" -ErrorAction SilentlyContinue
'@
    } -Run {
        Write-Verbose "Checking AMSI configuration and provider registry keys..."
        $Issues = @()
        $AmsiDetails = @{}

        $pathsToScan = @(
            "HKLM:\SOFTWARE\Microsoft\AMSI",
            "HKLM:\SOFTWARE\Policies\Microsoft\Windows\ScriptedDiagnostics",
            "HKCU:\SOFTWARE\Microsoft\AMSI"
        )

        foreach ($path in $pathsToScan) {
            if (Test-Path $path) {
                try {
                    $item = Get-Item -Path $path -ErrorAction SilentlyContinue
                    if ($null -ne $item -and $null -ne $item.GetValue("AmsiEnable", $null)) {
                        $amsiState = $item.GetValue("AmsiEnable")
                        if ([int]$amsiState -eq 0) {
                            Write-Verbose "AMSI explicitly disabled via registry at: $path"
                            $Issues += "AMSI explicitly disabled (AmsiEnable=0) at $path"
                        }
                    }
                } catch {
                    Write-Verbose "Could not read AmsiEnable property at $path"
                }
            }
        }

        $providerPath = "HKLM:\SOFTWARE\Microsoft\AMSI\Providers"
        if (Test-Path $providerPath) {
            $providers = Get-ChildItem -Path $providerPath -ErrorAction SilentlyContinue
            $AmsiDetails["ProviderCount"] = if ($providers) { $providers.Count } else { 0 }
            Write-Verbose "Registered AMSI Providers count: $($AmsiDetails['ProviderCount'])"

            foreach ($prov in $providers) {
                $clsid = $prov.PSChildName
                $clsidPath = "HKLM:\SOFTWARE\Classes\CLSID\$clsid\InprocServer32"
                if (Test-Path $clsidPath) {
                    try {
                        $item = Get-Item -Path $clsidPath -ErrorAction SilentlyContinue
                        $dllPath = $item.GetValue("", $null)
                        Write-Verbose "AMSI Provider CLSID $clsid points to: $dllPath"
                        
                        if ($dllPath -and $dllPath -notmatch "System32|Program Files|Windows Defender") {
                            $Issues += "Non-standard AMSI Provider DLL detected: $dllPath (CLSID: $clsid)"
                        }
                    } catch {}
                }
            }
        } else {
            $AmsiDetails["ProviderCount"] = 0
            Write-Verbose "AMSI Provider registry key does not exist."
        }

        Add-WFLDetail -Name "Security-APT-AMSI-RegistryHooks" -Data $AmsiDetails

        if ($Issues.Count -gt 0) {
            Write-Verbose "AMSI tampering or bypass indicators found: $($Issues -join ' | ')"
            Add-WFLFinding `
                -Title "AMSI Defense Evasion or registry tampering detected" `
                -Severity "High" `
                -Category "Defense Evasion" `
                -MITRE "T1562.001" `
                -Tactic "Defense Evasion" `
                -Source "Security-APT-AMSI-RegistryHooks" `
                -Evidence ($Issues -join " | ") `
                -Recommendation "Re-enable AMSI via Registry/GPO, audit non-standard AMSI provider DLLs, and check endpoint for memory injection tools."
        } else {
            Write-Verbose "AMSI configuration check passed with no tampering detected."
            Add-WFLFinding `
                -Title "AMSI registry integrity review passed" `
                -Severity "Info" `
                -Category "Defense Evasion" `
                -MITRE "T1562.001" `
                -Tactic "Defense Evasion" `
                -Source "Security-APT-AMSI-RegistryHooks" `
                -Evidence "AmsiEnable policies valid; Registered Providers count: $($AmsiDetails['ProviderCount'])" `
                -Recommendation "Ensure AMSI enforcement remains active and non-default AMSI providers are monitored."
        }
    }


