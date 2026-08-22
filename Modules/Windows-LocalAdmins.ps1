Register-WFLModule `
    -Name "Windows-LocalAdmins" `
    -Category "Windows Security" `
    -Type "Check" `
    -MITRE "T1078" `
    -Tactic "Persistence" `
    -Impact "POTENTIAL PRIVILEGE ESCALATION" `
    -Description "Reviews local Administrators group." `
 -Remediation @{
        Module        = 'Windows-LocalAdmins.ps1'
        Category      = 'Host Security Hardening'
        Type          = 'Specific'
        Description   = 'Remove unauthorized accounts present in the local "Administrators" group.'
        Impact        = 'Reduces the local attack surface by restricting administrative privileges to legitimate users.'
        VariableGuide = 'Replace [Nome_Account] with the unauthorized user detected.'
        Code          = @'
$localGroup = "Administrators"
$unauthorizedAccount = "[Nome_Account]"
Remove-LocalGroupMember -Group $localGroup -Member $unauthorizedAccount -ErrorAction SilentlyContinue
Write-Host "[!] Account $unauthorizedAccount removed from the local Administrators group." -ForegroundColor Yellow
'@
    } -Run {
        Write-Verbose "Enumerating local Administrators group members via ADSI..."
        $Admins = @()

        try {
            $Group = [ADSI]"WinNT://./Administrators,group"
            $Members = $Group.psbase.Invoke("Members")

            foreach ($Member in $Members) {
                $Path = $Member.GetType().InvokeMember("ADsPath", 'GetProperty', $null, $Member, $null)
                $Name = $Member.GetType().InvokeMember("Name", 'GetProperty', $null, $Member, $null)
                
                $Domain = ($Path -split '/')[2]
                $Class  = $Member.GetType().InvokeMember("Class", 'GetProperty', $null, $Member, $null)

                $Admins += [PSCustomObject]@{
                    Name            = "$Domain\$Name"
                    ObjectClass     = $Class
                    PrincipalSource = if ($Domain -eq $env:COMPUTERNAME) { "Local" } else { "Domain" }
                }
            }
        }
        catch {
            Write-Verbose "ADSI enumeration failed, falling back to Get-LocalGroupMember..."
            try {
                $Admins = Get-LocalGroupMember -Group "Administrators" -ErrorAction Stop |
                    Select-Object Name, ObjectClass, PrincipalSource
            }
            catch {
                Write-Verbose "Failed to enumerate local administrators via all methods: $_"
            }
        }

        Add-WFLDetail `
            -Name "Windows-LocalAdmins" `
            -Data $Admins

        $AdminCount = @($Admins).Count

        if ($AdminCount -gt 0) {
            $DomainAdminsCount = @($Admins | Where-Object { $_.PrincipalSource -eq "Domain" }).Count
            
            $Severity = "Info"
            if ($AdminCount -gt 10 -or $DomainAdminsCount -gt 3) {
                $Severity = "Medium"
            }

            $EvidenceText = "Members=$AdminCount (Local: $($AdminCount - $DomainAdminsCount), Domain: $DomainAdminsCount)"

            Add-WFLFinding `
                -Title "Local Administrators membership review" `
                -Severity $Severity `
                -Category "Windows Security" `
                -MITRE "T1078" `
                -Tactic "Persistence" `
                -Source "Windows-LocalAdmins" `
                -Evidence $EvidenceText `
                -Recommendation "Review local admin membership, remove unnecessary domain users/groups, and enforce LAPS for local admin accounts."
        }
        else {
            Add-WFLFinding `
                -Title "Unable to enumerate local administrators" `
                -Severity "Low" `
                -Category "Windows Security" `
                -MITRE "T1078" `
                -Tactic "Persistence" `
                -Source "Windows-LocalAdmins" `
                -Evidence "Access Denied or Administrators group empty/unreachable." `
                -Recommendation "Verify user permissions running the assessment framework."
        }
    }


