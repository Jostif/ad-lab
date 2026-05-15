# 04_vulnerable_configs.ps1 — Additional vulnerable configurations
# Sets up: RBCD surface, dMSA (BadSuccessor), weak passwords, SMB shares

Import-Module ActiveDirectory

Write-Host "[*] Setting up additional vulnerable configurations..."

# -------------------------------------------------------------------
# RBCD surface — jdoe has GenericWrite on WS01$
# -------------------------------------------------------------------
$jdoeSid = (Get-ADUser jdoe).SID
$ws01DN  = (Get-ADComputer "WS01" -ErrorAction SilentlyContinue)?.DistinguishedName

if ($ws01DN) {
    $acl = Get-Acl "AD:$ws01DN"
    $ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
        $jdoeSid,
        [System.DirectoryServices.ActiveDirectoryRights]::GenericWrite,
        [System.Security.AccessControl.AccessControlType]::Allow
    )
    $acl.AddAccessRule($ace)
    Set-Acl "AD:$ws01DN" $acl
    Write-Host "[+] GenericWrite: jdoe → WS01$ (RBCD path)"
}

# -------------------------------------------------------------------
# BadSuccessor surface — jdoe has CreateChild on ServiceAccounts OU
# -------------------------------------------------------------------
$domainDN  = "DC=lab,DC=local"
$ouDN      = "OU=ServiceAccounts,$domainDN"
$jdoeSid   = (Get-ADUser jdoe).SID
$ouAcl     = Get-Acl "AD:$ouDN"

# CreateChild right for msDS-DelegatedManagedServiceAccount class
$dmsaSchemaGuid = [System.Guid]"b7eea5f5-4af3-4bc5-a9e7-6fd5b1f5d003"
$createChildAce = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
    $jdoeSid,
    [System.DirectoryServices.ActiveDirectoryRights]::CreateChild,
    [System.Security.AccessControl.AccessControlType]::Allow,
    $dmsaSchemaGuid,
    [System.DirectoryServices.ActiveDirectorySecurityInheritance]::None
)
$ouAcl.AddAccessRule($createChildAce)
Set-Acl "AD:$ouDN" $ouAcl
Write-Host "[+] CreateChild (dMSA): jdoe → ServiceAccounts OU (BadSuccessor path)"

# -------------------------------------------------------------------
# Weak passwords for cracking exercises
# -------------------------------------------------------------------
$weakPasswords = @{
    "svc_backup"    = "Password1"
    "svc_nopreauth" = "Summer2024!"
    "jsmith"        = "Welcome1"
}

foreach ($user in $weakPasswords.Keys) {
    $pass = ConvertTo-SecureString $weakPasswords[$user] -AsPlainText -Force
    Set-ADAccountPassword -Identity $user -NewPassword $pass -Reset
    Write-Host "[+] Weak password set: $user → $($weakPasswords[$user])"
}

# -------------------------------------------------------------------
# SMB share with sensitive files (recon surface)
# -------------------------------------------------------------------
New-Item -ItemType Directory -Path "C:\Shares\IT" -Force | Out-Null
@"
# IT Notes
DC01: 192.168.56.10
Admin: Administrator / Lab@12345
Backup SA: svc_backup / Password1
"@ | Out-File "C:\Shares\IT\notes.txt"

New-SmbShare -Name "IT" -Path "C:\Shares\IT" -FullAccess "Everyone"
Write-Host "[+] SMB share created: \\DC01\IT (world-readable, contains creds)"

# -------------------------------------------------------------------
# Disable SMB signing on WS01 (relay surface)
# -------------------------------------------------------------------
Set-SmbServerConfiguration -RequireSecuritySignature $false -Force
Set-SmbClientConfiguration -RequireSecuritySignature $false -Force
Write-Host "[+] SMB signing disabled — NTLM relay surface active"

Write-Host "[+] Vulnerable configurations complete"
Write-Host ""
Write-Host "=== Lab Attack Surface Summary ==="
Write-Host "  Kerberoasting   : svc_backup (MSSQLSvc SPN)"
Write-Host "  Kerberoasting   : svc_web (HTTP SPN)"
Write-Host "  AS-REP Roasting : svc_nopreauth"
Write-Host "  Shadow Creds    : jdoe has GenericWrite on svc_backup"
Write-Host "  ADCS ESC1       : VulnESC1 template (Domain Users can enroll)"
Write-Host "  ADCS ESC8       : http://DC01/certsrv (no HTTPS, no EPA)"
Write-Host "  RBCD            : jdoe has GenericWrite on WS01$"
Write-Host "  BadSuccessor    : jdoe has CreateChild (dMSA) on ServiceAccounts OU"
Write-Host "  SMB relay       : signing disabled on DC01"
Write-Host "  Credentials     : \\DC01\IT\notes.txt (world-readable)"
