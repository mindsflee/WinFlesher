Register-WFLModule `
    -Name "Security-APT-Network-InsecureProtocols" `
    -Category "Network Security" `
    -Type "Check" `
    -MITRE "T1557" `
    -Tactic "Credential Access" `
    -Impact "POTENTIAL LATERAL MOVEMENT" `
    -Description "Audits local host broadcast name resolution risks (LLMNR and NetBIOS over TCP/IP)." `
        -Remediation @{
        Module        = 'Security-APT-Network-InsecureProtocols'
        Category      = 'Credential Access / Lateral Movement'
        Type          = 'Specific'
        Description   = 'Disables legacy name resolution protocols (LLMNR and NetBIOS over TCP/IP) to mitigate local spoofing and credential relay vectors.'
        Impact        = 'Low in modern networks. May affect legacy workgroup name resolution.'
        VariableGuide = 'Network adapter NetBIOS settings.'
        Code          = @'
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces\*" -Name "NetbiosOptions" -Value 2
'@
    } -Run {
        Write-Verbose "Auditing LLMNR and NetBIOS broadcast protocols status..."
        $Issues = @()

        try {
            $llmnrPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient"
            $enableLlmnr = $null
            if (Test-Path $llmnrPath) {
                $enableLlmnr = Get-ItemPropertyValue -Path $llmnrPath -Name "EnableMultiCast" -ErrorAction SilentlyContinue
            }

            if ($null -eq $enableLlmnr -or [int]$enableLlmnr -eq 1) {
                Write-Verbose "LLMNR is enabled (EnableMultiCast != 0 or missing GPO policy)."
                $Issues += "LLMNR enabled [Exposed to Responder / NTLM Relay attacks]"
            } else {
                Write-Verbose "LLMNR is disabled via GPO Policy."
            }
        } catch {
            $Issues += "Unable to query LLMNR policy registry setting"
        }

        try {
            $adapters = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces\Tcpip_*" -ErrorAction SilentlyContinue
            $nbtEnabledCount = 0

            foreach ($adapter in $adapters) {
                if ($adapter.NetbiosOptions -ne 2) {
                    $nbtEnabledCount++
                }
            }

            if ($nbtEnabledCount -gt 0) {
                Write-Verbose "NetBIOS over TCP/IP is active or set to default on $nbtEnabledCount interface(s)."
                $Issues += "NetBIOS over TCP/IP active on $nbtEnabledCount network interface(s) [LLMNR/NBT-NS poisoning risk]"
            }
        } catch {
            Write-Verbose "Could not enumerate NetBT interface settings."
        }

        Add-WFLDetail -Name "Security-APT-Network-InsecureProtocols" -Data @{ LLMNR_Enabled = ($null -eq $enableLlmnr -or $enableLlmnr -eq 1); ActiveNetBTInterfaces = $nbtEnabledCount }

        if ($Issues.Count -gt 0) {
            Write-Verbose "Broadcast protocol security risks detected: $($Issues -join ' | ')"
            Add-WFLFinding `
                -Title "LLMNR or NetBIOS name resolution protocols enabled" `
                -Severity "Medium" `
                -Category "Network Security" `
                -MITRE "T1557" `
                -Tactic "Credential Access" `
                -Source "Security-APT-Network-InsecureProtocols" `
                -Evidence ($Issues -join " | ") `
                -Recommendation "Disable LLMNR via Group Policy ('Turn off multicast name resolution' = Enabled) and disable NetBIOS over TCP/IP on all network adapters."
        } else {
            Write-Verbose "LLMNR and NetBIOS checks passed. Both protocols are properly disabled."
            Add-WFLFinding `
                -Title "LLMNR and NetBIOS broadcast protocol review passed" `
                -Severity "Info" `
                -Category "Network Security" `
                -MITRE "T1557" `
                -Tactic "Credential Access" `
                -Source "Security-APT-Network-InsecureProtocols" `
                -Evidence "LLMNR disabled via GPO policy; NetBIOS disabled across active adapters." `
                -Recommendation "Maintain GPO enforcement to keep broadcast protocols disabled."
        }
    }


