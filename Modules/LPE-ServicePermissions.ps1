Register-WFLModule `
    -Name "LPE-ServicePermissions" `
    -Category "Privilege Escalation" `
    -Type "Check" `
    -MITRE "T1574.010" `
    -Tactic "Privilege Escalation" `
    -Impact "POTENTIAL PRIVILEGE ESCALATION" `
    -Description "Identifies privileged services whose binary folders allow write access to non-admin users and dynamically calculates risk." `
-Remediation @{
        Module        = 'LPE-ServicePermissions.ps1'
        Category      = 'Local Privilege Escalation'
        Type          = 'Specific'
        Description   = 'Restore secure NTFS permissions and inheritance on vulnerable Windows service directories.'
        Impact        = 'Prevents Service Hijacking attacks via binary replacement on weak write permissions.'
        VariableGuide = 'Set [Service_Directory_Path] to the path returned by the module.'
        Code          = @'
$servicePath = "[Service_Directory_Path]"
$acl = Get-Acl $servicePath
$acl.SetAccessRuleProtection($false, $true)
Set-Acl -Path $servicePath -AclObject $acl
Write-Host "[+] Permissions successfully restored on the service directory." -ForegroundColor Green
'@
    } -Run {

        try {
            $VulnerableServices = @()
            $Services = Get-CimInstance -ClassName Win32_Service | Where-Object { 
                $_.State -eq "Running" -and 
                [string]::IsNullOrWhiteSpace($_.PathName) -eq $false -and
                $_.StartMode -ne "Disabled"
            }

            $DangerousRights = @("FullControl", "Modify", "Write", "WriteData", "CreateFiles", "AppendData")
            $WeakIdentities  = @("Users", "BUILTIN\Users", "Authenticated Users", "Everyone", "S-1-1-0", "S-1-5-32-545", "S-1-5-11")
            $PrivilegedAccounts = @(
                "LocalSystem",
                "NT AUTHORITY\SYSTEM",
                "LocalService",
                "NT AUTHORITY\LocalService",
                "NetworkService",
                "NT AUTHORITY\NetworkService"
            )

            foreach ($Svc in $Services) {
                
                $StartName = [string]$Svc.StartName
                $IsSystemAccount = ($StartName -in $PrivilegedAccounts) -or ($StartName -match 'LocalSystem')

                if (-not $IsSystemAccount -and $StartName -notmatch "\\") {
                    continue
                }

                $RawPath = $Svc.PathName.Trim()
                if ($RawPath.StartsWith('"')) {
                    $ExecutablePath = $RawPath.Split('"')[1]
                } else {
                    $ExecutablePath = $RawPath.Split(' ')[0]
                }

                if (-not (Test-Path $ExecutablePath -ErrorAction SilentlyContinue)) { continue }

                $FolderPath = Split-Path -Path $ExecutablePath -Parent
                if (-not (Test-Path $FolderPath -ErrorAction SilentlyContinue)) { continue }

                $Acl = Get-Acl -Path $FolderPath -ErrorAction SilentlyContinue
                if ($null -eq $Acl) { continue }

                $IsWritable = $false
                $MatchedIdentity = ""
                $MatchedPermissions = ""

                foreach ($AccessRule in $Acl.Access) {
                    if ($AccessRule.AccessControlType -ne "Allow") { continue }

                    $Identity = $AccessRule.IdentityReference.Value
                    $FileSystemRights = $AccessRule.FileSystemRights.ToString()

                    $IsWeak = $false
                    foreach ($Weak in $WeakIdentities) {
                        if ($Identity -like "*$Weak*") {
                            $IsWeak = $true
                            break
                        }
                    }

                    if ($IsWeak) {
                        foreach ($Right in $DangerousRights) {
                            if ($FileSystemRights -like "*$Right*") {
                                $IsWritable = $true
                                $MatchedIdentity = $Identity
                                $MatchedPermissions = $FileSystemRights
                                break
                            }
                        }
                    }

                    if ($IsWritable) { break }
                }

                if ($IsWritable) {
                    $ServiceSeverity = "High"
                    if ($IsSystemAccount) {
                        $ServiceSeverity = "Critical"
                    }

                    $VulnerableServices += [PSCustomObject]@{
                        ServiceName    = $Svc.Name
                        DisplayName    = $Svc.DisplayName
                        StartName      = $Svc.StartName
                        ExecutablePath = $ExecutablePath
                        FolderPath     = $FolderPath
                        Identity       = $MatchedIdentity
                        Permissions    = $MatchedPermissions
                        Severity       = $ServiceSeverity
                    }
                }
            }

            Add-WFLDetail -Name "LPE-ServicePermissions" -Data $VulnerableServices

            $CriticalCount = @($VulnerableServices | Where-Object { $_.Severity -eq "Critical" }).Count
            $HighCount     = @($VulnerableServices | Where-Object { $_.Severity -eq "High" }).Count

            $Severity = "Info"
            if ($HighCount -gt 0)     { $Severity = "High" }
            if ($CriticalCount -gt 0) { $Severity = "Critical" }

            if ($VulnerableServices.Count -eq 0) {
                Add-WFLFinding `
                    -Title "Privileged Service Folder Permission Audit passed" `
                    -Severity "Info" `
                    -Category "Privilege Escalation" `
                    -MITRE "T1574.010" `
                    -Tactic "Privilege Escalation" `
                    -Source "LPE-ServicePermissions" `
                    -Evidence "No privileged service binary folders with non-admin write access were detected." `
                    -Recommendation "No action required."
                return
            }

            Add-WFLFinding `
                -Title "Privileged Service Folder Permission Audit" `
                -Severity $Severity `
                -Category "Privilege Escalation" `
                -MITRE "T1574.010" `
                -Tactic "Privilege Escalation" `
                -Source "LPE-ServicePermissions" `
                -Evidence "VulnerableFolders=$($VulnerableServices.Count); Critical=$CriticalCount; High=$HighCount" `
                -Recommendation "Restrict NTFS permissions on vulnerable binary directories immediately. Remove Write/Modify permissions for non-admin groups."
        }
        catch {
            Add-WFLFinding `
                -Title "Service permission audit failed" `
                -Severity "Info" `
                -Category "Privilege Escalation" `
                -Source "LPE-ServicePermissions" `
                -Evidence $_.Exception.Message
        }
    }


