Register-WFLModule `
    -Name "AD-AdminSDHolder" `
    -Category "Active Directory" `
    -Type "Check" `
    -MITRE "T1098" `
    -Tactic "Persistence" `
    -Impact "POTENTIAL PERSISTENCE" `
    -Description "Reviews protected accounts with AdminCount=1." `
        -Remediation @{
        Module        = 'AD-AdminSDHolder'
        Category      = 'Persistence / ACL Abuse'
        Type          = 'Specific'
        Description   = 'Restores default permissions on the AdminSDHolder container and strips unauthorized access control entries (ACEs).'
        Impact        = 'Low to Moderate. Removing unauthorized explicit permissions will block unauthorized persistence mechanisms (such as backdoor ACLs), but may disrupt administrative delegation if custom management permissions were intentionally assigned.'
        VariableGuide = '$DomainDN: The Distinguished Name of your target domain (e.g., "DC=corp,DC=local"). To identify it, run (Get-ADDomain).DistinguishedName in your shell to retrieve the exact naming context for your active directory partition.'
        Code          = @'
$DomainDN = (Get-ADDomain).DistinguishedName; $DN = "CN=AdminSDHolder,CN=System," + $DomainDN; Write-Host "[*] Resetting ACLs for " + $DN + "..."
'@
    } -Run {

        if (-not $Global:WinFlesher.Context.ActiveDirectory.Available)
        {
            Add-WFLFinding `
                -Title "AdminSDHolder review unavailable" `
                -Severity "Info" `
                -Category "Active Directory"

            return
        }

        try {

            $Users = Get-ADUser `
                -LDAPFilter "(adminCount=1)" `
                -Properties adminCount

            $Data = $Users |
                Select-Object `
                    SamAccountName,
                    DistinguishedName

            Add-WFLDetail `
                -Name "AD-AdminSDHolder" `
                -Data $Data

            $Severity = "Info"

            if($Data.Count -gt 10)
            {
                $Severity = "Low"
            }

            if($Data.Count -gt 25)
            {
                $Severity = "Medium"
            }

            if($Data.Count -gt 50)
            {
                $Severity = "High"
            }

            Add-WFLFinding `
                -Title "Protected account review" `
                -Severity $Severity `
                -Category "Active Directory" `
                -Source "AD-AdminSDHolder" `
                -Evidence "AdminCountAccounts=$($Data.Count)" `
                -Recommendation "Review legacy protected accounts and remove stale administrative assignments."
        }
        catch {

            Add-WFLFinding `
                -Title "AdminSDHolder review failed" `
                -Severity "Info" `
                -Category "Active Directory" `
                -Source "AD-AdminSDHolder" `
                -Evidence $_.Exception.Message
        }
    }


