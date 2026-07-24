<#
.SYNOPSIS
    Tum kullanici profillerinde Chrome, Edge ve Firefox tarayicilarinda
    yukli olan extension'lari tespit eder ve JSON formatinda raporlar.

.NOTES
    CrowdStrike RTR Custom Script olarak calistirilmak uzere tasarlanmistir.
    Cikti tek satirlik JSON olarak stdout'a yazilir (RTR log/parse icin).
#>

$computerName = $env:COMPUTERNAME

function Get-ActiveUserFolders {
    # NTUSER.DAT tarih filtresi kaldirildi:
    # - Windows Hello/PIN/biyometrik ile oturum acan kullanicilarda
    #   NTUSER.DAT guncellenmeyebilir, bu yuzden aktif kullanicilar atlaniyordu.
    # - Python tarafindaki OSUser filtresi (hd.*, adm.*, Lenovo, HP) zaten
    #   help desk ve genel hesaplari eliyor, burada ek bir filtreye gerek yok.
    # Simdi tum gercek kullanici profilleri taraniyor.

    $allUserFolders = Get-ChildItem -Path "C:\Users" -Directory -ErrorAction SilentlyContinue
    $validFolders = New-Object System.Collections.ArrayList

    foreach ($folder in $allUserFolders) {
        # Sistem/servis profillerini disarida tut (gercek kullanici degil)
        if ($folder.Name -in @("Public", "Default", "Default User", "All Users")) { continue }

        # NTUSER.DAT yoksa bu gercek bir kullanici profili degil, atla
        $ntUserPath = Join-Path $folder.FullName "NTUSER.DAT"
        if (-not (Test-Path $ntUserPath)) { continue }

        [void]$validFolders.Add($folder)
    }

    return $validFolders
}

function Get-LocalizedName {
    param(
        [string]$RawName,
        [string]$ExtensionRootPath
    )

    # Eger isim "__MSG_xxx__" formatinda degilse direkt dondur
    if ($RawName -notmatch '^__MSG_(.+)__$') {
        return $RawName
    }

    $msgKey = $Matches[1]
    $localesPath = Join-Path $ExtensionRootPath "_locales"

    if (-not (Test-Path $localesPath)) {
        return $RawName  # cozemedik, ham degeri don
    }

    # Tercih sirasi: en, en_US, sonra mevcut olan ilk klasor
    $preferredLocales = @("en", "en_US", "en_GB")
    $localeDir = $null

    foreach ($loc in $preferredLocales) {
        $candidate = Join-Path $localesPath $loc
        if (Test-Path $candidate) {
            $localeDir = $candidate
            break
        }
    }

    if (-not $localeDir) {
        $localeDir = Get-ChildItem -Path $localesPath -Directory -ErrorAction SilentlyContinue | Select-Object -First 1 -ExpandProperty FullName
    }

    if (-not $localeDir) {
        return $RawName
    }

    $messagesFile = Join-Path $localeDir "messages.json"
    if (-not (Test-Path $messagesFile)) {
        return $RawName
    }

    $rawContent = $null
    try {
        $rawContent = Get-Content -Path $messagesFile -Raw -ErrorAction Stop
    }
    catch {
        return $RawName
    }

    # ONCELIKLI YONTEM: Regex ile dogrudan metin icinde anahtari ara.
    # Bazi extension'larin messages.json dosyalarinda PowerShell 5.1'in
    # ConvertFrom-Json'unun case-insensitive davranisi yuzunden "duplicate key"
    # hatasi veren anahtarlar olabilir (orn. Adobe Acrobat extension'i).
    # Regex bu sorunu yasamaz, dosyayi hic JSON olarak parse etmeden okur.
    $escapedKey = [regex]::Escape($msgKey)
    $pattern = '"' + $escapedKey + '"\s*:\s*\{\s*"message"\s*:\s*"([^"]*(?:\\.[^"]*)*)"'
    $regexMatch = [regex]::Match($rawContent, $pattern, [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)

    if ($regexMatch.Success) {
        $resolved = $regexMatch.Groups[1].Value
        # JSON escape karakterlerini geri cevir (\" -> ", \\ -> \)
        $resolved = $resolved -replace '\\"', '"' -replace '\\\\', '\'
        return $resolved
    }

    # YEDEK YONTEM: Regex bulamazsa normal JSON parse dene (duplicate key yoksa calisir)
    try {
        $messages = $rawContent | ConvertFrom-Json -ErrorAction Stop
        $prop = $messages.PSObject.Properties | Where-Object { $_.Name -ieq $msgKey } | Select-Object -First 1
        if ($prop -and $prop.Value.message) {
            return $prop.Value.message
        }
    }
    catch {
        return $RawName
    }

    return $RawName
}

function Get-ChromiumExtensions {
    param(
        [string]$BrowserLabel,
        [string]$DataPathSuffix   # orn: "Google\Chrome\User Data" veya "Microsoft\Edge\User Data"
    )

    $localResults = New-Object System.Collections.ArrayList
    $userFolders = Get-ActiveUserFolders

    foreach ($userFolder in $userFolders) {
        $basePath = Join-Path $userFolder.FullName "AppData\Local\$DataPathSuffix"
        if (-not (Test-Path $basePath)) { continue }

        # Default, Profile 1, Profile 2 vs. tum profilleri tara
        $profileDirs = Get-ChildItem -Path $basePath -Directory -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -eq "Default" -or $_.Name -like "Profile*" }

        foreach ($profileDir in $profileDirs) {
            $extensionsPath = Join-Path $profileDir.FullName "Extensions"
            if (-not (Test-Path $extensionsPath)) { continue }

            $extIdDirs = Get-ChildItem -Path $extensionsPath -Directory -ErrorAction SilentlyContinue

            foreach ($extIdDir in $extIdDirs) {
                # Her extension ID klasoru altinda versiyon klasoru var (orn 8.6_0)
                $versionDirs = Get-ChildItem -Path $extIdDir.FullName -Directory -ErrorAction SilentlyContinue
                foreach ($versionDir in $versionDirs) {
                    $manifestPath = Join-Path $versionDir.FullName "manifest.json"
                    if (-not (Test-Path $manifestPath)) { continue }

                    try {
                        $manifest = Get-Content -Path $manifestPath -Raw -ErrorAction Stop | ConvertFrom-Json
                        $rawName = $manifest.name
                        $resolvedName = Get-LocalizedName -RawName $rawName -ExtensionRootPath $versionDir.FullName

                        [void]$localResults.Add([PSCustomObject]@{
                            ComputerName    = $computerName
                            OSUser          = $userFolder.Name
                            Browser         = $BrowserLabel
                            Profile         = $profileDir.Name
                            ExtensionId     = $extIdDir.Name
                            ExtensionName   = $resolvedName
                            ExtensionVersion = $manifest.version
                            ManifestPath    = $manifestPath
                        })
                    }
                    catch {
                        # bozuk/okunamayan manifest, atla
                        continue
                    }
                }
            }
        }
    }

    return $localResults
}

function Get-FirefoxExtensions {
    $localResults = New-Object System.Collections.ArrayList
    $userFolders = Get-ActiveUserFolders

    foreach ($userFolder in $userFolders) {
        $profilesBase = Join-Path $userFolder.FullName "AppData\Roaming\Mozilla\Firefox\Profiles"
        if (-not (Test-Path $profilesBase)) { continue }

        $profileDirs = Get-ChildItem -Path $profilesBase -Directory -ErrorAction SilentlyContinue

        foreach ($profileDir in $profileDirs) {
            $extensionsPath = Join-Path $profileDir.FullName "extensions"
            if (-not (Test-Path $extensionsPath)) { continue }

            $extItems = Get-ChildItem -Path $extensionsPath -ErrorAction SilentlyContinue

            foreach ($extItem in $extItems) {
                $extId = $extItem.BaseName
                $rawName = $null
                $version = $null

                if ($extItem.PSIsContainer) {
                    # Acik klasor olarak kurulmus extension
                    $manifestPath = Join-Path $extItem.FullName "manifest.json"
                    if (Test-Path $manifestPath) {
                        try {
                            $manifest = Get-Content -Path $manifestPath -Raw -ErrorAction Stop | ConvertFrom-Json

                            # Firefox temalari manifest.json icinde 'theme' anahtari tasir.
                            # Bunlar gercek extension degil, gorsel/dekoratif paketler -
                            # raporda gurultu yaratiyorlar, atlayalim.
                            if ($manifest.PSObject.Properties.Name -contains "theme") {
                                continue
                            }

                            $rawName = $manifest.name
                            $version = $manifest.version
                            $rawName = Get-LocalizedName -RawName $rawName -ExtensionRootPath $extItem.FullName
                        }
                        catch { continue }
                    }
                }
                elseif ($extItem.Extension -eq ".xpi") {
                    # .xpi bir ZIP arsivi - manifest.json'u disari cikarmadan oku
                    try {
                        Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction SilentlyContinue
                        $zip = [System.IO.Compression.ZipFile]::OpenRead($extItem.FullName)
                        $manifestEntry = $zip.Entries | Where-Object { $_.Name -eq "manifest.json" } | Select-Object -First 1

                        if ($manifestEntry) {
                            $reader = New-Object System.IO.StreamReader($manifestEntry.Open())
                            $manifestContent = $reader.ReadToEnd()
                            $reader.Close()
                            $manifest = $manifestContent | ConvertFrom-Json

                            # Firefox temalari manifest.json icinde 'theme' anahtari tasir.
                            # Bunlar gercek extension degil, gorsel/dekoratif paketler - atlayalim.
                            if ($manifest.PSObject.Properties.Name -contains "theme") {
                                $zip.Dispose()
                                continue
                            }

                            $rawName = $manifest.name
                            $version = $manifest.version
                            # .xpi icindeki _locales icin regex tabanli arama (duplicate-key JSON
                            # sorunlarina karsi dayanikli, ConvertFrom-Json yerine)
                            if ($rawName -match '^__MSG_(.+)__$') {
                                $msgKey = $Matches[1]
                                $localeEntry = $zip.Entries | Where-Object { $_.FullName -like "_locales/en*/messages.json" } | Select-Object -First 1
                                if ($localeEntry) {
                                    $localeReader = New-Object System.IO.StreamReader($localeEntry.Open())
                                    $localeContent = $localeReader.ReadToEnd()
                                    $localeReader.Close()

                                    $escapedKey = [regex]::Escape($msgKey)
                                    $pattern = '"' + $escapedKey + '"\s*:\s*\{\s*"message"\s*:\s*"([^"]*(?:\\.[^"]*)*)"'
                                    $regexMatch = [regex]::Match($localeContent, $pattern, [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)

                                    if ($regexMatch.Success) {
                                        $resolved = $regexMatch.Groups[1].Value
                                        $resolved = $resolved -replace '\\"', '"' -replace '\\\\', '\'
                                        $rawName = $resolved
                                    }
                                    else {
                                        # Regex bulamazsa yedek olarak normal JSON parse dene
                                        try {
                                            $messages = $localeContent | ConvertFrom-Json -ErrorAction Stop
                                            $prop = $messages.PSObject.Properties | Where-Object { $_.Name -ieq $msgKey } | Select-Object -First 1
                                            if ($prop -and $prop.Value.message) {
                                                $rawName = $prop.Value.message
                                            }
                                        }
                                        catch {
                                            # cozemedik, ham __MSG_...__ degerini koru
                                        }
                                    }
                                }
                            }
                        }
                        $zip.Dispose()
                    }
                    catch {
                        continue
                    }
                }
                else {
                    continue
                }

                if ($rawName) {
                    [void]$localResults.Add([PSCustomObject]@{
                        ComputerName     = $computerName
                        OSUser           = $userFolder.Name
                        Browser          = "Firefox"
                        Profile          = $profileDir.Name
                        ExtensionId      = $extId
                        ExtensionName    = $rawName
                        ExtensionVersion = $version
                        ManifestPath     = $extItem.FullName
                    })
                }
            }
        }
    }

    return $localResults
}

# --- Calistir ---
$allResults = New-Object System.Collections.ArrayList

$chromeResults = Get-ChromiumExtensions -BrowserLabel "Chrome" -DataPathSuffix "Google\Chrome\User Data"
if ($chromeResults) { foreach ($item in $chromeResults) { [void]$allResults.Add($item) } }

$edgeResults = Get-ChromiumExtensions -BrowserLabel "Edge" -DataPathSuffix "Microsoft\Edge\User Data"
if ($edgeResults) { foreach ($item in $edgeResults) { [void]$allResults.Add($item) } }

$firefoxResults = Get-FirefoxExtensions
if ($firefoxResults) { foreach ($item in $firefoxResults) { [void]$allResults.Add($item) } }

# Cikti: tek satirlik JSON (RTR icin parse edilebilir, satir kirilmasi sorun cikarmaz)
$allResults | ConvertTo-Json -Compress -Depth 5
