Register-WFLModule `
    -Name "Windows-LSA" `
    -Category "Windows Security" `
    -Type "Check" `
    -MITRE "T1003.001" `
    -Tactic "Credential Access" `
    -Impact "POTENTIAL CREDENTIAL COMPROMISE" `
    -Description "Checks LSASS protection and WDigest credential exposure settings." `
 -Remediation @{
        Module        = 'Windows-LSA.ps1'
        Category      = 'Host Security Hardening'
        Type          = 'Specific'
        Description   = 'Disable the legacy WDigest authentication protocol to prevent plaintext passwords in memory.'
        Impact        = 'Mitigates the risk of plaintext credential theft via process memory extraction.'
        VariableGuide = 'No variables required.'
        Code          = @'
$path = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest"
if (-not (Test-Path $path)) { New-Item -Path $path -Force | Out-Null }
Set-ItemProperty -Path $path -Name "UseLogonCredential" -Value 0 -Type DWord
Write-Host "[+] WDigest authentication disabled successfully." -ForegroundColor Green
'@
    } -Run {
        $LSA = $Global:WinFlesher.Context.LSA

        if (-not $LSA) {
            Add-WFLFinding `
                -Title "LSA discovery data unavailable" `
                -Severity "Info" `
                -Category "Windows Security" `
                -MITRE "T1003.001" `
                -Tactic "Credential Access" `
                -Source "Windows-LSA" `
                -Evidence "LSA context not found." `
                -Recommendation "Run discovery with sufficient local permissions."
            return
        }

        $Issues = @()

        if ($LSA.RunAsPPL -ne 1 -and $LSA.RunAsPPL -ne 2) {
            $Issues += "LSASS protection not enabled. RunAsPPL=$($LSA.RunAsPPL)"
        }

        if ($LSA.WDigestUseLogonCredential -eq 1) {
            $Issues += "WDigest plaintext credential caching enabled."
        }

        Add-WFLDetail -Name "Windows-LSA" -Data $LSA

        if ($Issues.Count -gt 0) {
            Add-WFLFinding `
                -Title "LSA / LSASS protection review" `
                -Severity "High" `
                -Category "Windows Security" `
                -MITRE "T1003.001" `
                -Tactic "Credential Access" `
                -Source "Windows-LSA" `
                -Evidence ($Issues -join " | ") `
                -Recommendation "Enable LSA protection / RunAsPPL and ensure WDigest UseLogonCredential is disabled unless explicitly required."
        }
        else {
            Add-WFLFinding `
                -Title "LSA / LSASS protection review passed" `
                -Severity "Info" `
                -Category "Windows Security" `
                -MITRE "T1003.001" `
                -Tactic "Credential Access" `
                -Source "Windows-LSA" `
                -Evidence "RunAsPPL=$($LSA.RunAsPPL); WDigestUseLogonCredential=$($LSA.WDigestUseLogonCredential)" `
                -Recommendation "Keep current protection settings and monitor LSASS access events."
        }
    }



