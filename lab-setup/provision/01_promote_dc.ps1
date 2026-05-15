# 01_promote_dc.ps1 — Install AD DS and promote to DC
# Domain: lab.local | DC: DC01 | SafeMode PW: Lab@12345

$domain     = "lab.local"
$netbios    = "LAB"
$safeModePs = ConvertTo-SecureString "Lab@12345" -AsPlainText -Force

Write-Host "[*] Installing AD DS role..."
Install-WindowsFeature AD-Domain-Services -IncludeManagementTools -Restart:$false

Write-Host "[*] Promoting to Domain Controller..."
Import-Module ADDSDeployment

Install-ADDSForest `
    -DomainName $domain `
    -DomainNetbiosName $netbios `
    -SafeModeAdministratorPassword $safeModePs `
    -InstallDns `
    -Force `
    -NoRebootOnCompletion

Write-Host "[+] DC promotion complete — rebooting"
