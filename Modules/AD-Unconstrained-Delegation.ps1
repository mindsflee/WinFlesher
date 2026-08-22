Register-WFLModule `
    -Name "AD-Unconstrained-Delegation" `
    -Category "Active Directory" `
    -Type "Check" `
    -MITRE "T1558" `
    -Tactic "Credential Access" `
    -Impact "POTENTIAL DOMAIN COMPROMISE" `
    -Description "Reviews unconstrained delegation." `
        -Remediation @{
        Module        = 'AD-Unconstrained-Delegation'
        Category      = 'Credential Access'
        Type          = 'Specific'
        Description   = 'Removes unconstrained delegation rights from domain computers and user accounts where not strictly required.'
        Impact        = 'High for legacy apps. Eliminates the risk of TGT caching and subsequent domain compromise if the host is compromised.'
        VariableGuide = '$ComputerName: The server instance configured with unconstrained delegation.'
        Code          = @'
Set-ADComputer -Identity "ServerName" -TrustedForDelegation $false
'@
    } -Run {

        if (-not $Global:WinFlesher.Context.ActiveDirectory.Available)
        {
            Add-WFLFinding `
                -Title "Delegation review unavailable" `
                -Severity "Info" `
                -Category "Active Directory"

            return
        }

        try {

            $Computers = Get-ADComputer `
                -LDAPFilter "(userAccountControl:1.2.840.113556.1.4.803:=524288)" `
                -Properties DNSHostName

           $Computers = Get-ADComputer `
    -LDAPFilter "(userAccountControl:1.2.840.113556.1.4.803:=524288)" `
    -Properties DNSHostName,OperatingSystem,PrimaryGroupID

            $Results = @()

           foreach($Computer in $Computers)
{
    $SeverityRank  = "Medium"
    $Exploitability = "Potential"

    if ($Computer.PrimaryGroupID -eq 516)
    {
        $SeverityRank  = "Medium"
        $Exploitability = "Expected"
    }
    elseif ($Computer.OperatingSystem -match "Server")
    {
        $SeverityRank  = "High"
        $Exploitability = "Potential"
    }

    $Results += [PSCustomObject]@{
        Type            = "Computer"
        Name            = $Computer.Name
        OperatingSystem = $Computer.OperatingSystem
        PrimaryGroupID  = $Computer.PrimaryGroupID
        Severity        = $SeverityRank
        Exploitability  = $Exploitability
    }
}

           foreach($User in $Users)
{
    $Results += [PSCustomObject]@{
        Type           = "User"
        Name           = $User.SamAccountName
        Severity       = "High"
        Exploitability = "Likely"
    }
}

            Add-WFLDetail `
                -Name "AD-Unconstrained-Delegation" `
                -Data $Results

          $Severity = "Info"

if (($Results | Where-Object {$_.Severity -eq "High"}).Count -gt 0)
{
    $Severity = "High"
}
elseif (($Results | Where-Object {$_.Severity -eq "Medium"}).Count -gt 0)
{
    $Severity = "Medium"
}

            Add-WFLFinding `
                -Title "Unconstrained delegation review" `
                -Severity $Severity `
                -Category "Active Directory" `
                -Source "AD-Unconstrained-Delegation" `
                -Evidence "Objects=$($Results.Count)" `
                -Recommendation "Reduce or eliminate unconstrained delegation where possible."

        }
        catch {

            Add-WFLFinding `
                -Title "Unconstrained delegation review failed" `
                -Severity "Info" `
                -Category "Active Directory" `
                -Source "AD-Unconstrained-Delegation" `
                -Evidence $_.Exception.Message
        }
    }


