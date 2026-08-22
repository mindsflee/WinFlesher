Register-WFLModule `
    -Name "AD-ManagedAccountsACL" `
    -Category "Active Directory" `
    -Type "Check" `
    -MITRE "T1552.001" `
    -Tactic "Credential Access" `
    -Impact "POTENTIAL CREDENTIAL COMPROMISE" `
    -Description "Audits Read permissions on LAPS password attributes and gMSA retrieval rights." `
        -Remediation @{
        Module        = 'AD-ManagedAccountsACL'
        Category      = 'Credential Access'
        Type          = 'Specific'
        Description   = 'Restricts unauthorized read access permissions over LAPS password attributes and gMSA secret retrieval attributes in Active Directory.'
        Impact        = 'Low. Securing managed password attributes prevents unauthorized extraction of local administrator and service credentials.'
        VariableGuide = 'Scans object access control lists for excessive read rights.'
        Code          = @'
'@
    } -Run {
        if (-not $Global:WinFlesher.Context.ActiveDirectory.Available) { return }

        try {
			
	
function Get-WFLManagedAccountPrincipalRisk {

    param(
        [string]$Principal
    )

   if ([string]::IsNullOrEmpty($Principal))
{
    return "Unknown"
}

    if ($Principal -match 'Authenticated Users|Domain Users|Everyone')
    {
        return "Broad"
    }

    if ($Principal -match '^S-1-5-')
    {
        return "UnresolvedSid"
    }

    if ($Principal.EndsWith('$'))
    {
        return "ComputerAccount"
    }

    return "SpecificPrincipal"
}
	
	

function Get-WFLManagedAccountSeverity {
    param(
        [string]$PrincipalRisk
    )

    switch ($PrincipalRisk)
    {
        "Broad"             { return "Critical" }
        "UnresolvedSid"     { return "High" }
        "SpecificPrincipal" { return "Medium" }
        "ComputerAccount"   { return "Low" }
        default             { return "Medium" }
    }
}

function Get-WFLManagedAccountExploitability {
    param(
        [string]$PrincipalRisk
    )

    switch ($PrincipalRisk)
    {
        "Broad"             { return "Likely" }
        "UnresolvedSid"     { return "Potential" }
        "SpecificPrincipal" { return "Potential" }
        "ComputerAccount"   { return "Expected" }
        default             { return "Potential" }
    }
}
            $gMSAs = Get-ADServiceAccount -Filter * -Properties PrincipalsAllowedToRetrieveManagedPassword -ErrorAction SilentlyContinue
            $OverexposedGMSAs = @()

          foreach ($gMSA in $gMSAs)
{
    if ($null -ne $gMSA.PrincipalsAllowedToRetrieveManagedPassword)
    {
        foreach ($Principal in @($gMSA.PrincipalsAllowedToRetrieveManagedPassword))
        {
            $PrincipalText = [string]$Principal
            $PrincipalRisk = Get-WFLManagedAccountPrincipalRisk -Principal $PrincipalText
            $SeverityRank = Get-WFLManagedAccountSeverity -PrincipalRisk $PrincipalRisk
            $Exploitability = Get-WFLManagedAccountExploitability -PrincipalRisk $PrincipalRisk

            $OverexposedGMSAs += [PSCustomObject]@{
                gMSAName        = $gMSA.SamAccountName
                AllowedPrincipal = $PrincipalText
                PrincipalRisk   = $PrincipalRisk
                Severity        = $SeverityRank
                Exploitability  = $Exploitability
            }
        }
    }
}

            Add-WFLDetail -Name "AD-ManagedAccountsACL" -Data $OverexposedGMSAs
            
			$Severity = "Info"

if (($OverexposedGMSAs | Where-Object { $_.Severity -eq "Critical" }).Count -gt 0)
{
    $Severity = "Critical"
}
elseif (($OverexposedGMSAs | Where-Object { $_.Severity -eq "High" }).Count -gt 0)
{
    $Severity = "High"
}
elseif (($OverexposedGMSAs | Where-Object { $_.Severity -eq "Medium" }).Count -gt 0)
{
    $Severity = "Medium"
}
elseif (($OverexposedGMSAs | Where-Object { $_.Severity -eq "Low" }).Count -gt 0)
{
    $Severity = "Low"
}

            Add-WFLFinding `
                -Title "gMSA & LAPS ACL Exposure Audit" `
                -Severity $Severity `
                -Category "Active Directory" `
                -MITRE "T1552.001" `
                -Tactic "Credential Access" `
                -Source "AD-ManagedAccountsACL" `
                -Evidence "Reviewed gMSA retrieval permissions. Findings=$($OverexposedGMSAs.Count); Critical=$(($OverexposedGMSAs | Where-Object { $_.Severity -eq 'Critical' }).Count); High=$(($OverexposedGMSAs | Where-Object { $_.Severity -eq 'High' }).Count); Medium=$(($OverexposedGMSAs | Where-Object { $_.Severity -eq 'Medium' }).Count); Low=$(($OverexposedGMSAs | Where-Object { $_.Severity -eq 'Low' }).Count)" `
                -Recommendation "Restrict gMSA password retrieval rights to the minimum required computer accounts or tightly controlled service groups. Remove broad principals, unresolved SIDs, user accounts, or non-operational groups where not explicitly required."
        }
        catch {
            Add-WFLFinding -Title "Managed accounts ACL check failed" -Severity "Info" -Category "Active Directory" -Source "AD-ManagedAccountsACL" -Evidence $_.Exception.Message
        }
    } 


