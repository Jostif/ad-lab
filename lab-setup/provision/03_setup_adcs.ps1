# 03_setup_adcs.ps1 — Install ADCS and create vulnerable certificate templates
# ESC1: enrollee supplies SAN, low-priv enrollment
# ESC8: HTTP enrollment endpoint without HTTPS/EPA

Import-Module ActiveDirectory

Write-Host "[*] Installing ADCS..."
Install-WindowsFeature ADCS-Cert-Authority, ADCS-Web-Enrollment -IncludeManagementTools

Write-Host "[*] Configuring CA..."
Install-AdcsCertificationAuthority `
    -CAType EnterpriseRootCa `
    -CryptoProviderName "RSA#Microsoft Software Key Storage Provider" `
    -KeyLength 2048 `
    -HashAlgorithmName SHA256 `
    -CACommonName "lab-CA" `
    -Force

# Install web enrollment (creates HTTP endpoint — ESC8 surface)
Install-AdcsWebEnrollment -Force
Write-Host "[+] Web enrollment installed — ESC8 surface active at http://DC01/certsrv"

Write-Host "[*] Creating vulnerable ESC1 template..."

# Duplicate UserAuthentication template
$configDN = (Get-ADRootDSE).configurationNamingContext
$templatesDN = "CN=Certificate Templates,CN=Public Key Services,CN=Services,$configDN"
$srcTemplate = "CN=User,$templatesDN"

# Copy template via ADSI
$de = [ADSI]"LDAP://$srcTemplate"
$parent = [ADSI]"LDAP://$templatesDN"
$newTemplate = $parent.Create("pKICertificateTemplate", "CN=VulnESC1")

# Set vulnerable flags:
# CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT = 1 (allows SAN)
# msPKI-Certificate-Name-Flag
$newTemplate.Put("displayName", "VulnESC1")
$newTemplate.Put("msPKI-Certificate-Name-Flag", 1)    # Enrollee supplies subject
$newTemplate.Put("msPKI-Enrollment-Flag", 0)
$newTemplate.Put("msPKI-RA-Signature", 0)             # No manager approval
$newTemplate.Put("pKIExtendedKeyUsage", @("1.3.6.1.5.5.7.3.2","1.3.6.1.5.5.7.3.1"))  # Client + Server Auth
$newTemplate.SetInfo()

Write-Host "[+] ESC1 template created: VulnESC1"

# Grant Domain Users enrollment rights on VulnESC1
$domainUsersSid = (Get-ADGroup "Domain Users").SID.Value
$templateAcl = Get-Acl "AD:CN=VulnESC1,$templatesDN"
$enrollRight = [System.DirectoryServices.ActiveDirectoryAccessRule]::new(
    [System.Security.Principal.SecurityIdentifier]$domainUsersSid,
    [System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight,
    [System.Security.AccessControl.AccessControlType]::Allow,
    [System.Guid]"0e10c968-78fb-11d2-90d4-00c04f79dc55"  # Enroll OID
)
$templateAcl.AddAccessRule($enrollRight)
Set-Acl "AD:CN=VulnESC1,$templatesDN" $templateAcl
Write-Host "[+] Domain Users granted Enroll right on VulnESC1"

# Publish template to CA
certutil -setcatemplates +VulnESC1

Write-Host "[+] ADCS configuration complete"
Write-Host "[*] ESC1: VulnESC1 template — Domain Users can request cert with arbitrary SAN"
Write-Host "[*] ESC8: http://DC01/certsrv — HTTP enrollment, no EPA"
