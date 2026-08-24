Register-WFLModule `
    -Name "Security-APT-ShadowCredentials" `
    -Category "Active Directory" `
    -Type "Check" `
    -MITRE "T1556.001, T1098" `
    -Tactic "Credential Access, Persistence" `
    -Impact "POTENTIAL DOMAIN COMPROMISE" `
    -Description "Detects active usage and potential exploitation of Shadow Credentials (msDS-KeyCredentialLink attribute)." `
        -Remediation @{
        Module        = 'Security-APT-ShadowCredentials'
        Category      = 'Credential Access / Persistence'
        Type          = 'Specific'
        Description   = 'Detects and purges unauthorized public key certificates bound to the msDS-KeyCredentialLink attribute used in Shadow Credentials attacks.'
        Impact        = 'Low. Revokes unauthorized key credentials mapped to high-value accounts.'
        VariableGuide = '$Identity: Target user or computer object.'
        Code          = @'
Set-ADUser -Identity "TargetUser" -Clear "msDS-KeyCredentialLink"
'@
    } -Run {
        Write-Verbose "Executing Shadow Credentials (msDS-KeyCredentialLink) audit..."

        $Issues = @()
        $ShadowCredentialTargets = @()

        try {
            $filter = "(msDS-KeyCredentialLink=*)"
            
            $searcher = [ADSISearcher]$filter
            $searcher.PageSize = 1000
            $searcher.PropertiesToLoad.AddRange(@(
    "sAMAccountName",
    "distinguishedName",
    "objectClass",
    "msDS-KeyCredentialLink",
    "whenModified",
    "adminCount",
    "userAccountControl"
)) | Out-Null

            $results = $searcher.FindAll()

            if ($results.Count -gt 0) {
                Write-Verbose "Found $($results.Count) object(s) with populated msDS-KeyCredentialLink attributes."

        foreach ($res in $results) {

    $account = [string]$res.Properties["samaccountname"][0]
    $dn      = [string]$res.Properties["distinguishedname"][0]

    $objectClasses = @($res.Properties["objectclass"])
    $objectClass   = [string]$objectClasses[-1]

    $modified = $null
    if ($res.Properties["whenmodified"].Count -gt 0) {
        $modified = $res.Properties["whenmodified"][0]
    }

    $keyCount = $res.Properties["msds-keycredentiallink"].Count

    $adminCount = 0
    if ($res.Properties["admincount"].Count -gt 0) {
        $adminCount = [int]$res.Properties["admincount"][0]
    }

    $userAccountControl = 0
    if ($res.Properties["useraccountcontrol"].Count -gt 0) {
        $userAccountControl = [int]$res.Properties["useraccountcontrol"][0]
    }

    $enabled = ($userAccountControl -band 2) -eq 0

    $isComputer = (
        $objectClass -eq "computer" -or
        $account.EndsWith('$')
    )

    $isUser = (
        $objectClass -eq "user" -and
        -not $isComputer
    )

    $isKrbtgt = (
        $account -eq "krbtgt" -or
        $dn -like "CN=krbtgt,*"
    )

    $isDomainController = (
        $dn -like "*OU=Domain Controllers,*"
    )

    $isPrivileged = (
        $adminCount -eq 1 -or
        $isKrbtgt -or
        $isDomainController
    )

    $severity       = "Info"
    $classification = "Expected or unvalidated Key Credential"
    $riskReasons    = @()

    if ($isComputer -and -not $isPrivileged) {

        $severity = "Info"
        $classification = "Computer Key Credential inventory"
        $riskReasons += "Computer object with populated msDS-KeyCredentialLink"

    }
    elseif (-not $enabled) {

        $severity = "Low"
        $classification = "Disabled account with retained Key Credential"
        $riskReasons += "Account is disabled"
        $riskReasons += "Retained Key Credential requires lifecycle validation"

    }
    elseif ($isKrbtgt) {

        $severity = "Critical"
        $classification = "Unexpected Key Credential on KRBTGT"
        $riskReasons += "KRBTGT must not normally possess interactive Key Credentials"

    }
    elseif ($isDomainController) {

        $severity = "High"
        $classification = "Key Credential on Domain Controller"
        $riskReasons += "Domain Controller is a Tier-0 object"

    }
    elseif ($isPrivileged) {

        $severity = "Medium"
        $classification = "Privileged account Key Credential requiring validation"
        $riskReasons += "adminCount=1"
        $riskReasons += "Legitimate WHfB/FIDO2 usage must be confirmed"

    }
    elseif ($isUser) {

        $severity = "Info"
        $classification = "User Key Credential inventory"
        $riskReasons += "May be generated legitimately by WHfB or FIDO2"
        $riskReasons += "Presence alone does not demonstrate Shadow Credentials abuse"

    }
    else {

        $severity = "Low"
        $classification = "Non-standard object with Key Credential"
        $riskReasons += "Unexpected object class requires manual validation"

    }

    if ($keyCount -gt 1) {
        $riskReasons += "Multiple Key Credentials present: $keyCount"
    }

    $ShadowCredentialTargets += [PSCustomObject]@{
        sAMAccountName = $account
        ObjectClass    = $objectClass
        DN             = $dn
        KeyCount       = $keyCount
        Enabled        = $enabled
        AdminCount     = $adminCount
        IsPrivileged   = $isPrivileged
        LastModified   = $modified
        Classification = $classification
        Severity       = $severity
        RiskReason     = ($riskReasons -join "; ")
    }

    if ($severity -in @("Critical", "High", "Medium")) {
        $Issues += [PSCustomObject]@{
            Account        = $account
            DistinguishedName = $dn
            Severity       = $severity
            Classification = $classification
            RiskReason     = ($riskReasons -join "; ")
        }
    }

    Write-Verbose "Key Credential found on '$account': Severity=$severity; Classification=$classification"
}
            } else {
                Write-Verbose "No objects found with populated msDS-KeyCredentialLink attributes."
            }
        }
        catch {
            Write-Verbose "Failed to search Active Directory for msDS-KeyCredentialLink. Ensure execution in a Domain context: $_"
            Add-WFLFinding `
                -Title "Shadow Credentials check unavailable" `
                -Severity "Info" `
                -Category "Active Directory" `
                -MITRE "T1556.001" `
                -Tactic "Persistence" `
                -Source "Security-APT-ShadowCredentials" `
                -Evidence "Unable to query AD via ADSI/LDAP: $($_.Exception.Message)" `
                -Recommendation "Verify domain connectivity and LDAP privileges."
            return
        }

        Add-WFLDetail -Name "Security-APT-ShadowCredentials" -Data $ShadowCredentialTargets

 if ($Issues.Count -gt 0) {
    $CriticalCount = @(
    $ShadowCredentialTargets |
        Where-Object { $_.Severity -eq "Critical" }
).Count

$HighCount = @(
    $ShadowCredentialTargets |
        Where-Object { $_.Severity -eq "High" }
).Count

$MediumCount = @(
    $ShadowCredentialTargets |
        Where-Object { $_.Severity -eq "Medium" }
).Count

$LowCount = @(
    $ShadowCredentialTargets |
        Where-Object { $_.Severity -eq "Low" }
).Count

$InfoCount = @(
    $ShadowCredentialTargets |
        Where-Object { $_.Severity -eq "Info" }
).Count

$UserCount = @(
    $ShadowCredentialTargets |
        Where-Object { $_.ObjectClass -eq "user" }
).Count

$ComputerCount = @(
    $ShadowCredentialTargets |
        Where-Object { $_.ObjectClass -eq "computer" }
).Count

$Severity = "Info"

if ($MediumCount -gt 0) {
    $Severity = "Medium"
}

if ($HighCount -gt 0) {
    $Severity = "High"
}

if ($CriticalCount -gt 0) {
    $Severity = "Critical"
}

if ($ShadowCredentialTargets.Count -gt 0) {

    $Global:WinFlesher.Details["Security-APT-ShadowCredentials"] = $ShadowCredentialTargets

    Add-WFLFinding `
        -Title "Key Credential Link exposure review" `
        -Severity $Severity `
        -Category "Active Directory" `
        -MITRE "T1556.001, T1098" `
        -Tactic "Credential Access, Persistence" `
        -Source "Security-APT-ShadowCredentials" `
        -Evidence "Objects=$($ShadowCredentialTargets.Count); Users=$UserCount; Computers=$ComputerCount; Critical=$CriticalCount; High=$HighCount; Medium=$MediumCount; Low=$LowCount; Informational=$InfoCount" `
        -Recommendation "Validate Medium, High and Critical results first. Confirm legitimate Windows Hello for Business, FIDO2 or certificate-based authentication usage before removing any msDS-KeyCredentialLink value. Presence alone must not be treated as evidence of compromise."
}
else {

    Add-WFLFinding `
        -Title "Key Credential Link review completed" `
        -Severity "Info" `
        -Category "Active Directory" `
        -MITRE "T1556.001, T1098" `
        -Tactic "Persistence" `
        -Source "Security-APT-ShadowCredentials" `
        -Evidence "No domain objects currently possess msDS-KeyCredentialLink attributes." `
        -Recommendation "Monitor Directory Service changes to msDS-KeyCredentialLink and investigate unexpected modifications on Tier-0 identities."
}
 }
    }


