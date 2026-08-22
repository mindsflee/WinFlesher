Register-WFLModule `
    -Name "SEC-LSASS" `
    -Category "Windows Security" `
    -Type "Check" `
    -MITRE "T1003.001" `
    -Tactic "Credential Access" `
    -Impact "POTENTIAL CREDENTIAL COMPROMISE" `
    -Description "Checks if LSASS process protection (RunAsPPL) and Credential Guard are enforced." `
-Remediation @{
        Module        = 'SEC-LSASS.ps1'
        Category      = 'Host Security Hardening'
        Type          = 'Specific'
        Description   = 'Enable RunAsPPL (Protected Process Light) protection for the LSASS subsystem.'
        Impact        = 'Prevents read access to LSASS memory by credential dumping tools.'
        VariableGuide = 'No variables required (system reboot required to take effect).'
        Code          = @'
$path = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
if (-not (Test-Path $path)) { New-Item -Path $path -Force | Out-Null }
Set-ItemProperty -Path $path -Name "RunAsPPL" -Value 1 -Type DWord
Write-Host "[+] LSASS protection (RunAsPPL) enabled. System restart required." -ForegroundColor Green
'@
    } -Run {

        try {
            $LsaPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
            $RunAsPPL = 0
            $LsaCfgFlags = 0

            if (Test-Path $LsaPath) {
                $LsaProps = Get-ItemProperty -Path $LsaPath -ErrorAction SilentlyContinue
                if ($null -ne $LsaProps.RunAsPPL) { $RunAsPPL = [int]$LsaProps.RunAsPPL }
                if ($null -ne $LsaProps.LsaCfgFlags) { $LsaCfgFlags = [int]$LsaProps.LsaCfgFlags }
            }

            $LsassProc = Get-Process -Name lsass -ErrorAction SilentlyContinue
            $IsProtected = $false

            $LsassWmi = Get-CimInstance -ClassName Win32_Process -Filter "Name = 'lsass.exe'" -ErrorAction SilentlyContinue

            $Details = [PSCustomObject]@{
                ProcessId       = $LsassProc.Id
                RunAsPPLRegistry = $RunAsPPL
                LsaCfgFlags     = $LsaCfgFlags
                IsPPLActive     = ($RunAsPPL -ge 1)
            }

            Add-WFLDetail -Name "SEC-LSASS" -Data $Details

            $Severity = "High"
            $Evidence = "RunAsPPL Registry Key = $RunAsPPL; LsaCfgFlags = $LsaCfgFlags."

            if ($RunAsPPL -ge 1) {
                $Severity = "Info"
                $Evidence += " LSASS process protection (RunAsPPL) is enabled."
            } else {
                $Evidence += " LSASS process is NOT running as PPL. Memory dumping via SeDebugPrivilege is possible."
            }

            Add-WFLFinding `
                -Title "LSASS Process Protection (RunAsPPL) Audit" `
                -Severity $Severity `
                -Category "Windows Security" `
                -MITRE "T1003.001" `
                -Tactic "Credential Access" `
                -Source "SEC-LSASS" `
                -Evidence $Evidence `
                -Recommendation "Enable LSASS protection by setting HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\RunAsPPL to 1 (or 2 for PPL Audit/Enabled) via GPO."
        }
        catch {
            Add-WFLFinding `
                -Title "LSASS protection check failed" `
                -Severity "Info" `
                -Category "Windows Security" `
                -Source "SEC-LSASS" `
                -Evidence $_.Exception.Message
        }
    }


