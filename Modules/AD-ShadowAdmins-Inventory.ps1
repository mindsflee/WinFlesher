Register-WFLModule `
    -Name "AD-ShadowAdmins-Inventory" `
    -Category "Active Directory" `
    -Type "Check" `
    -MITRE "T1098" `
    -Tactic "Persistence" `
    -Impact "POTENTIAL DOMAIN COMPROMISE" `
    -Description "Reviews potentially delegated administrative identities." `
-Remediation @{
        Module        = 'AD-ShadowAdmins-Inventory.ps1'
        Category      = 'Active Directory Security'
        Type          = 'Specific'
        Description   = 'Remove dangerous effective control rights (e.g., GenericAll, WriteDACL) granted to standard users.'
        Impact        = 'Eliminates hidden privilege escalation paths (Shadow Admins) within the domain.'
        VariableGuide = 'Set [Rogue_Username] and the object DN path.'
        Code          = @'
$targetIdentity = "[Rogue_Username]"
$targetObjectDN = "OU=Tier0,DC=dominio,DC=local"
$acl = Get-Acl "AD:\$targetObjectDN"
$aceToRemove = $acl.Access | Where-Object { $_.IdentityReference -like "*$targetIdentity*" -and $_.AccessControlType -eq "Allow" }
foreach ($ace in $aceToRemove) { $acl.RemoveAccessRule($ace) | Out-Null }
Set-Acl -Path "AD:\$targetObjectDN" -AclObject $acl
Write-Host "[+] Shadow Admin rights removed for $targetIdentity on $targetObjectDN." -ForegroundColor Green
'@
    } -Run {

        try {

            $Groups = @(
                "Domain Admins",
                "Enterprise Admins",
                "Administrators"
            )

            $Results = foreach($Group in $Groups)
            {
                Get-ADGroupMember $Group -Recursive |
                Select-Object @{
                    N='ProtectedGroup'
                    E={$Group}
                },Name,ObjectClass
            }

            Add-WFLDetail `
                -Name "AD-ShadowAdmins-Inventory" `
                -Data $Results

            Add-WFLFinding `
                -Title "Shadow admin exposure review" `
                -Severity "Info" `
                -Category "Active Directory" `
                -Source "AD-ShadowAdmins-Inventory" `
                -Evidence "Baseline protected group inventory collected: $($Results.Count) entries." `
                -Recommendation "Extend module with ACL analysis using DirectoryServices."
        }
        catch {

            Add-WFLFinding `
                -Title "Shadow admin review failed" `
                -Severity "Info" `
                -Category "Active Directory" `
                -Source "AD-ShadowAdmins-Inventory" `
                -Evidence $_.Exception.Message
        }
    }



