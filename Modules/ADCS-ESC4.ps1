Register-WFLModule `
    -Name "ADCS-ESC4" `
    -Category "Active Directory Certificate Services" `
    -Type "Check" `
    -MITRE "T1649" `
    -Tactic "Credential Access" `
    -Impact "POTENTIAL DOMAIN COMPROMISE" `
    -Description "Audits Active Directory Certificate Templates for dangerous write/control ACLs (ESC4 exposure)." `
	-Remediation @{
           Module        = "ADCS-ESC4"
            Category      = "Credential Access"
            Type          = "Specific"
            Description   = "Strips dangerous write and control ACLs held by non-admin principals over certificate template objects in Active Directory."
            Impact        = "Low. Prevents attackers from modifying template security settings to enable escalation paths."
            VariableGuide = '$TemplateDN: Distinguished Name of the vulnerable certificate template.'
            Code          = '# Remove explicit Write/FullControl ACEs for non-admin principals on certificate templates.'
    } `
    -Run {
        if (-not $Global:WinFlesher.Context.ActiveDirectory.Available) {
            Add-WFLFinding -Title "AD CS ESC4 review unavailable" -Severity "Info" -Category "Active Directory Certificate Services" -Source "ADCS-ESC4" -Evidence "AD unavailable."
            return
        }

        try {
            $ConfigDN = (Get-ADRootDSE).ConfigurationNamingContext
            $TemplatesContainer = "CN=Certificate Templates,CN=Public Key Services,CN=Services,$ConfigDN"
            
            $ExposedTemplates = @()
            $Templates = Get-ADObject -SearchBase $TemplatesContainer -Filter * -Properties nTSecurityDescriptor, displayName -ErrorAction SilentlyContinue

            $DangerousRights = "GenericAll|FullControl|WriteDacl|WriteOwner|GenericWrite"
$BuiltInExclusions = "Domain Admins|Enterprise Admins|Administrator|Administrators|SYSTEM|Key Admins|Enterprise Key Admins|Domain Controllers|Enterprise Domain Controllers|Organization Management|Cert Publishers|S-1-5-32-544|NT AUTHORITY\\SYSTEM"
            foreach ($Tpl in $Templates) {
				if ($Tpl.DistinguishedName -match "CNF:") { continue }
                $Acl = $Tpl.nTSecurityDescriptor
                if ($null -eq $Acl) { continue }
                
                foreach ($Access in $Acl.Access) {
                    if ($Access.AccessControlType -eq "Allow" -and ($Access.ActiveDirectoryRights -match $DangerousRights)) {
                        
                   $Identity = $Access.IdentityReference.Value
$Rights   = $Access.ActiveDirectoryRights.ToString()

if ($Identity -notmatch $BuiltInExclusions -and $Identity -notmatch "S-1-5-18") {

    $SeverityRank = "Medium"
    $Exploitability = "Potential"

    if ($Rights -match "GenericAll|FullControl")
    {
        $SeverityRank = "Critical"
        $Exploitability = "Likely"
    }
 elseif ($Rights -match "WriteDacl|WriteOwner")
{
    $SeverityRank = "High"
    $Exploitability = "Likely"

    if (
        $Identity -match "Authenticated Users|Domain Users|Everyone"
    )
    {
        $SeverityRank = "Critical"
        $Exploitability = "Likely"
    }
}

    elseif ($Rights -match "GenericWrite")
    {
        $SeverityRank = "High"
        $Exploitability = "Potential"
    }
    elseif ($Rights -match "WriteProperty")
    {
        $SeverityRank = "Medium"
        $Exploitability = "Potential"
    }

    $ExposedTemplates += [PSCustomObject]@{
        TemplateName   = if ($Tpl.displayName) { $Tpl.displayName } else { $Tpl.Name }
        Principal      = $Identity
        GrantedRights  = $Rights
        Severity       = $SeverityRank
        Exploitability = $Exploitability
        DN             = $Tpl.DistinguishedName
    }
}
                }
            }
			}

            Add-WFLDetail -Name "ADCS-ESC4" -Data $ExposedTemplates # Manteniamo coerenza dettaglio

          $Severity = "Info"

if (($ExposedTemplates | Where-Object { $_.Severity -eq "Critical" }).Count -gt 0)
{
    $Severity = "Critical"
}
elseif (($ExposedTemplates | Where-Object { $_.Severity -eq "High" }).Count -gt 0)
{
    $Severity = "High"
}
elseif (($ExposedTemplates | Where-Object { $_.Severity -eq "Medium" }).Count -gt 0)
{
    $Severity = "Medium"
}

            Add-WFLFinding `
                -Title "AD CS ESC4 Template Misconfiguration Review" `
                -Severity $Severity `
                -Category "Active Directory Certificate Services" `
                -MITRE "T1649" `
                -Tactic "Credential Access" `
                -Source "ADCS-ESC4" `
                -Evidence "Found $($ExposedTemplates.Count) certificate template ACL misconfiguration(s) allowing non-privileged control." `
                -Recommendation "Restrict WriteOwner, WriteDacl, and WriteProperty permissions on Certificate Templates to Enterprise/Domain Admins only."
        }
        catch {
            Add-WFLFinding -Title "ADCS ESC4 review failed" -Severity "Info" -Category "Active Directory Certificate Services" -Source "ADCS-ESC4" -Evidence $_.Exception.Message
        }
    }

