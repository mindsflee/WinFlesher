Register-WFLModule `
    -Name "Windows-Unquoted-Service-Paths" `
    -Category "Windows Services" `
    -Type "Check" `
    -MITRE "T1574.009" `
    -Tactic "Privilege Escalation" `
    -Impact "POTENTIAL PRIVILEGE ESCALATION" `
    -Description "Reviews unquoted service paths and dynamically evaluates parent folder ACLs for privilege escalation." `
-Remediation @{
        Module        = 'Windows-Unquoted-Service-Paths.ps1'
        Category      = 'Host Security Hardening'
        Type          = 'Specific'
        Description   = 'Fix unquoted Windows service paths containing spaces.'
        Impact        = 'Prevents arbitrary code execution via service path binary hijacking.'
        VariableGuide = 'Set [Nome_Servizio] to the vulnerable service identified.'
        Code          = @'
$serviceName = "[Nome_Servizio]"
$service = Get-WmiObject Win32_Service -Filter "Name='$serviceName'"
$fixedPath = "`"" + $service.PathName.Trim('"') + "`""
Set-WmiInstance -Class Win32_Service -Filter "Name='$serviceName'" -Arguments @{PathName = $fixedPath}
Write-Host "[+] Service path for $serviceName corrected with quotes." -ForegroundColor Green
'@
    } -Run {

        $Services = @($Global:WinFlesher.Context.Services)

        if ($Services.Count -eq 0) {
            Add-WFLFinding `
                -Title "Service review unavailable" `
                -Severity "Info" `
                -Category "Windows Services" `
                -MITRE "T1574.009" `
                -Tactic "Privilege Escalation" `
                -Source "Windows-Unquoted-Service-Paths" `
                -Evidence "No service information available." `
                -Recommendation "Run discovery before assessment."
            return
        }

        function Test-WFLWritableDirectory {
            param([string]$FolderPath)

            $WeakIdentities  = @("Users", "BUILTIN\Users", "Authenticated Users", "Everyone", "S-1-1-0", "S-1-5-32-545", "S-1-5-11")
            $DangerousRights = @("FullControl", "Modify", "Write", "WriteData", "CreateFiles", "AppendData")

            $CurrDir = $FolderPath
            while (-not [string]::IsNullOrWhiteSpace($CurrDir)) {
                
                if ($CurrDir -match '^[A-Za-z]:\\?$') { break }

                if (Test-Path $CurrDir -ErrorAction SilentlyContinue) {
                    $Acl = Get-Acl -Path $CurrDir -ErrorAction SilentlyContinue
                    if ($Acl) {
                        foreach ($AccessRule in $Acl.Access) {
                            if ($AccessRule.AccessControlType -ne "Allow") { continue }
                            
                            $Identity = $AccessRule.IdentityReference.Value
                            $IsWeak = $false
                            foreach ($Weak in $WeakIdentities) {
                                if ($Identity -like "*$Weak*") {
                                    $IsWeak = $true
                                    break
                                }
                            }

                            if ($IsWeak) {
                                $RightsStr = $AccessRule.FileSystemRights.ToString()
                                foreach ($Right in $DangerousRights) {
                                    if ($RightsStr -like "*$Right*") {
                                        return @{ IsWritable = $true; Folder = $CurrDir }
                                    }
                                }
                            }
                        }
                    }
                }
                
                $Parent = Split-Path -Path $CurrDir -Parent
                if ($Parent -eq $CurrDir) { break }
                $CurrDir = $Parent
            }

            return @{ IsWritable = $false; Folder = "" }
        }

        $Interesting = @()
        $PrivilegedAccounts = @("LocalSystem", "NT AUTHORITY\SYSTEM", "LocalService", "NT AUTHORITY\LocalService", "NetworkService", "NT AUTHORITY\NetworkService")

        foreach ($Service in $Services) {

            $Path = [string]$Service.PathName
            if ([string]::IsNullOrWhiteSpace($Path)) { continue }

            $CleanPath = $Path.Trim()
            if ([string]::IsNullOrWhiteSpace($CleanPath) -or $CleanPath.StartsWith('"') -or $CleanPath -notmatch '\s' -or $CleanPath -notmatch '^[A-Za-z]:\\') {
                continue
            }

            if ($CleanPath -match '(?i)svchost\.exe' -or 
                $CleanPath -match '(?i)^c:\\windows\\system32\\' -or 
                $CleanPath -match '(?i)^c:\\windows\\syswow64\\' -or 
                $CleanPath -match '(?i)^c:\\windows\\' -or 
                $CleanPath -match '(?i)\\winsxs\\' -or 
                $CleanPath -match '(?i)\.sys(\s|$)') {
                continue
            }

            if ($CleanPath -match '^(?<exe>[A-Za-z]:\\.*?\.exe)(\s|$)') {
                $ExtractedExecutable = $Matches.exe
            } else {
                $ExtractedExecutable = $CleanPath.Split(' ')[0]
            }

            $ParentFolder = Split-Path -Path $ExtractedExecutable -Parent

            $CheckResult = Test-WFLWritableDirectory -FolderPath $ParentFolder
            $IsWritableByUsers = $CheckResult.IsWritable
            $WritableFolderFound = $CheckResult.Folder

            $StartName = [string]$Service.StartName
            $IsSystemAccount = ($StartName -in $PrivilegedAccounts) -or ($StartName -match 'LocalSystem')

            $ServiceSeverity = "Low"
            if ($IsWritableByUsers -and $IsSystemAccount) {
                $ServiceSeverity = "Critical"
            } elseif ($IsWritableByUsers) {
                $ServiceSeverity = "High"
            } elseif ($IsSystemAccount) {
                $ServiceSeverity = "Medium"
            }

            $Interesting += [PSCustomObject]@{
                ServiceName         = [string]$Service.Name
                DisplayName         = [string]$Service.DisplayName
                State               = [string]$Service.State
                StartMode           = [string]$Service.StartMode
                StartName           = $StartName
                PathName            = [string]$Service.PathName
                Executable          = [string]$ExtractedExecutable
                IsWritableByUsers   = $IsWritableByUsers
                WritableFolder      = $WritableFolderFound
                Severity            = $ServiceSeverity
            }
        }

        Add-WFLDetail `
            -Name "Windows-Unquoted-Service-Paths" `
            -Data $Interesting

        $ServiceCount = @($Interesting).Count

        if ($ServiceCount -eq 0) {
            Add-WFLFinding `
                -Title "Unquoted service path review passed" `
                -Severity "Info" `
                -Category "Windows Services" `
                -MITRE "T1574.009" `
                -Tactic "Privilege Escalation" `
                -Source "Windows-Unquoted-Service-Paths" `
                -Evidence "No potentially exploitable unquoted service paths detected after filtering System32, svchost, Windows folders, WinSxS and drivers." `
                -Recommendation "No action required."
            return
        }

        $CriticalCount = @($Interesting | Where-Object { $_.Severity -eq "Critical" }).Count
        $HighCount     = @($Interesting | Where-Object { $_.Severity -eq "High" }).Count
        $MediumCount   = @($Interesting | Where-Object { $_.Severity -eq "Medium" }).Count
        $LowCount      = @($Interesting | Where-Object { $_.Severity -eq "Low" }).Count

        $OverallSeverity = "Low"
        if ($MediumCount -gt 0)   { $OverallSeverity = "Medium" }
        if ($HighCount -gt 0)     { $OverallSeverity = "High" }
        if ($CriticalCount -gt 0) { $OverallSeverity = "Critical" }

        Add-WFLFinding `
            -Title "Potentially exploitable unquoted service paths detected" `
            -Severity $OverallSeverity `
            -Category "Windows Services" `
            -MITRE "T1574.009" `
            -Tactic "Privilege Escalation" `
            -Source "Windows-Unquoted-Service-Paths" `
            -Evidence "TotalServices=$ServiceCount; Critical=$CriticalCount; High=$HighCount; Medium=$MediumCount; Low=$LowCount" `
            -Recommendation "Review unquoted service paths and fix folder ACLs. Quote executable paths containing spaces, especially for paths writable by non-admin users."
    }


