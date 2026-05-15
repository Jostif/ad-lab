# 02_configure_ad.ps1 — Create users, groups, OUs, and ACL misconfigurations
# Run after DC promotion and reboot

Import-Module ActiveDirectory

$domain   = "lab.local"
$domainDN = "DC=lab,DC=local"
$password = ConvertTo-SecureString "Lab@12345!" -AsPlainText -Force

Write-Host "[*] Creating OUs..."
@("ServiceAccounts","Workstations","Servers","Lab") | ForEach-Object {
    New-ADOrganizationalUnit -Name $_ -Path $domainDN -ProtectedFromAccidentalDeletion $false
}

Write-Host "[*] Creating users..."
$users = @(
    @{ Name="svc_backup";   Description="Backup service account";  SPN="MSSQLSvc/db01.lab.local:1433" },
    @{ Name="svc_web";      Description="Web service account";     SPN="HTTP/web01.lab.local" },
    @{ Name="svc_adcs";     Description="ADCS enrollment account"; SPN="" },
    @{ Name="jdoe";         Description="Regular user";            SPN="" },
    @{ Name="jsmith";       Description="Help desk";               SPN="" },
    @{ Name="svc_nopreauth";Description="No preauth (AS-REP bait)";SPN="" }
)

foreach ($u in $users) {
    $ouPath = if ($u.Name.StartsWith("svc")) {
        "OU=ServiceAccounts,$domainDN"
    } else { "CN=Users,$domainDN" }

    New-ADUser `
        -Name $u.Name `
        -SamAccountName $u.Name `
        -UserPrincipalName "$($u.Name)@$domain" `
        -AccountPassword $password `
        -Enabled $true `
        -Description $u.Description `
        -Path $ouPath

    if ($u.SPN) {
        Set-ADUser $u.Name -ServicePrincipalNames @{Add=$u.SPN}
    }
    Write-Host "  [+] Created: $($u.Name)"
}

# AS-REP bait — disable pre-authentication
Set-ADAccountControl svc_nopreauth -DoesNotRequirePreAuth $true
Write-Host "[+] svc_nopreauth: pre-auth disabled (AS-REP roastable)"

Write-Host "[*] Creating vulnerable ACLs..."

# GenericWrite on svc_backup for jdoe (shadow creds target)
$jdoeSid = (Get-ADUser jdoe).SID
$svcBackupDN = (Get-ADUser svc_backup).DistinguishedName
$acl = Get-Acl "AD:$svcBackupDN"
$ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
    $jdoeSid,
    [System.DirectoryServices.ActiveDirectoryRights]::GenericWrite,
    [System.Security.AccessControl.AccessControlType]::Allow
)
$acl.AddAccessRule($ace)
Set-Acl "AD:$svcBackupDN" $acl
Write-Host "[+] GenericWrite: jdoe → svc_backup (shadow creds path)"

# WriteDacl on svc_web for jsmith
$jsmithSid = (Get-ADUser jsmith).SID
$svcWebDN  = (Get-ADUser svc_web).DistinguishedName
$acl2 = Get-Acl "AD:$svcWebDN"
$ace2 = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
    $jsmithSid,
    [System.DirectoryServices.ActiveDirectoryRights]::WriteDacl,
    [System.Security.AccessControl.AccessControlType]::Allow
)
$acl2.AddAccessRule($ace2)
Set-Acl "AD:$svcWebDN" $acl2
Write-Host "[+] WriteDacl: jsmith → svc_web"

# MachineAccountQuota = 10 (allows RBCD fake computer creation)
Set-ADDomain -Identity $domain -Replace @{"ms-DS-MachineAccountQuota"=10}
Write-Host "[+] MachineAccountQuota set to 10"

Write-Host "[+] AD configuration complete"
