### passwordapi
Python Password API that allows you to store rotated usernames and passwords via an API key.  This also is further locked down using hashes and an Organization Secret which can be pushed to the registry on allowed machines via GPO or script.

### Variables
#### .app.env
Update the following values:
1. API_KEY - Use a long secure value for this
2. DB_HOST - You can leave this db as it will use the service name.
3. DB_USER - Database User
4. DB_PASSWORD - Database Password
5. DB_NAME - Database Name
6. ORG_SECRET - See Script below to generate (This will be the registry stored value on computers to allow the API calls)
7. ALLOWED_HASHES - See Script below that generates the hash that can be used here.  Comma Seperated Hashes

#### .db.env
Update the following values:
1. MYSQL_DATABASE - Same as DB_NAME in .app.env
2. MYSQL_USER - Same as DB_USER in .app.env
3. MYSQL_PASSWORD - Same as DB_PASSWORD in .app.env
4. MYSQL_ROOT_PASSWORD - Generate a Random Password for Root

#### .env
Update the Base Path value which will be the path to the folder with these project files.
1. BASE_PATH - Path to Project Files

### Deploy Stack
```bash
git clone https://github.com/bryant7392/passwordapi

cd passwordapi

docker compose --file passwordapi.yml --project-name passwordapi up -d
```

### Scripts
#### Org Secret
Use Powershell to Generate Secret
```powershell
# 256-bit secret
$bytes = New-Object byte[] 32  # 256 bits
[System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
$orgSecret = ([Convert]::ToBase64String($bytes)).Trim()
```

#### Hash Generateor
This will need to be ran on the allowed machines that creates the hash value to be allowed to make API calls.  This value needs to be put into the ALLOWED_HASHES variable.
```powershell
# Generate fingerprint
function Get-DeviceFingerprint {
    $guid   = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Cryptography").MachineGuid
    $mac    = (Get-NetAdapter | Where-Object { $_.Status -eq 'Up' } | Sort-Object -Property Name | Select-Object -First 1).MacAddress

    # Only include values that exist, to avoid nulls breaking the hash
    @($guid, $mac) -join '|'
}

$fingerprint = Get-DeviceFingerprint
```

#### Registry Key for Secret
```powershell
This takes your generated Org Secret Value and installs it in the registry with Administrators and SYSTEM Access to the value.
$salt = 'GeneratedOrgSecretValue'

$regPath = "HKLM:\SOFTWARE\YourCo\DeviceAuth"

# Create key if it doesn't exist
if (-not (Test-Path $regPath)) {
    New-Item -Path $regPath -Force | Out-Null
}

# Store the salt
Set-ItemProperty -Path $regPath -Name "Secret" -Value $salt

$acl = Get-Acl $regPath
$acl.SetAccessRuleProtection($true, $false) # Disable inheritance
$acl.Access | ForEach-Object { $acl.RemoveAccessRule($_) }

$admins = New-Object System.Security.AccessControl.RegistryAccessRule("Administrators","FullControl","Allow")
$system = New-Object System.Security.AccessControl.RegistryAccessRule("SYSTEM","FullControl","Allow")

$acl.AddAccessRule($admins)
$acl.AddAccessRule($system)

Set-Acl -Path $regPath -AclObject $acl
```

#### API Calls
Powershell Call Examples.  this also includes a timestamp to prevent replay attacks and will expire if the timestamp isn't correct with the provided hmac at the time of API call.
```powershell
###################################################
############### Value calls for API ###############
###################################################

# Load secret from registry
$orgSecret = (Get-ItemProperty "HKLM:\SOFTWARE\YourCo\DeviceAuth").Secret

# Generate fingerprint
function Get-DeviceFingerprint {
    $guid   = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Cryptography").MachineGuid
    $mac    = (Get-NetAdapter | Where-Object { $_.Status -eq 'Up' } | Sort-Object -Property Name | Select-Object -First 1).MacAddress

    # Only include values that exist, to avoid nulls breaking the hash
    @($guid, $mac) -join '|'
}

$fingerprint = Get-DeviceFingerprint

# Unix timestamp
$ts = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()

# Build message
$message = "$fingerprint|$ts"

# Compute HMAC-SHA256 as lowercase hex
$hmacSha256 = [System.Security.Cryptography.HMACSHA256]::new(
    [Text.Encoding]::UTF8.GetBytes($orgSecret)
)
$hashBytes = $hmacSha256.ComputeHash([Text.Encoding]::UTF8.GetBytes($message))
$tagHex = ($hashBytes | ForEach-Object ToString x2) -join ''

###################################################
############ End Value calls for API ##############
###################################################

###################################################
################ Examples #########################
###################################################

# Store Password
Invoke-RestMethod -Uri "http://localhost:8000/store" `
    -Method POST `
    -Headers @{ "x-api-key" = "12345678" } `
    -Body (@{
        fingerprint = $fingerprint
        ts          = $ts
        hmac        = $tagHex
        "username" = "test"
        "password" = "test"
    } | ConvertTo-Json) `
    -ContentType "application/json"

# Grab Latest Password for User
Invoke-RestMethod -Uri "http://localhost:8000/latest" `
    -Method POST `
    -Headers @{ "x-api-key" = "12345678" } `
    -Body (@{
        fingerprint = $fingerprint
        ts          = $ts
        hmac        = $tagHex
        "username" = "test"
        "password" = "test"
    } | ConvertTo-Json) `
    -ContentType "application/json"

# Grab All Passwords for User (API Only Holds Last 5, and cleans older after container restart)
Invoke-RestMethod -Uri "http://dockerutil:8000/all" `
    -Method POST `
    -Headers @{ "x-api-key" = "12345678" } `
    -Body (@{
        fingerprint = $fingerprint
        ts          = $ts
        hmac        = $tagHex
        "username" = "test"
        "password" = "test"
    } | ConvertTo-Json) `
    -ContentType "application/json"
```