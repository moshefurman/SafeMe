<#
.SYNOPSIS
    מתקין ורושם את סוכן SafeMe.

.DESCRIPTION
    מבצע פרסום (publish), מעתיק לתיקיית היעד, רושם את השירות,
    מגדיר פעולות התאוששות, מקשיח הרשאות, ויוצר משימה מתוזמנת כשכבת גיבוי.

    יש להריץ מחלון PowerShell עם הרשאות מנהל.

.EXAMPLE
    .\install.ps1 -ServerUrl "https://api.safeme.io" -EnrollToken "ENR-..."
#>

[CmdletBinding()]
param(
    [string] $InstallPath = "$env:ProgramFiles\SafeMe",
    [string] $ServerUrl   = "https://api.safeme.io",
    [string] $EnrollToken = "",
    # תיקייה עם קבצים בנויים. כשהיא ניתנת, אין בנייה מהמקור —
    # זה המסלול שהמתקין מהאתר משתמש בו, כי אין לו קוד מקור.
    [string] $SourcePath  = "",
    [switch] $SkipBuild
)

$ErrorActionPreference = 'Stop'

$ServiceName  = 'SafeMeAgent'
$DisplayName  = 'SafeMe Agent'
$Description  = 'סוכן SafeMe - אכיפת חיבור אינטרנט מסונן ומאושר.'
$RepoRoot     = Split-Path -Parent $PSScriptRoot

# ---------------------------------------------------------------- בדיקות מקדימות

$identity  = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)

if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "יש להריץ את הסקריפט כמנהל מערכת."
}

# שירות BFE הוא התשתית שעליה WFP רץ. בלעדיו אין אכיפה.
$bfe = Get-Service -Name 'BFE' -ErrorAction SilentlyContinue

if (-not $bfe) {
    throw "שירות Base Filtering Engine אינו קיים. לא ניתן להתקין."
}

if ($bfe.Status -ne 'Running') {
    Write-Host "מפעיל את שירות BFE..." -ForegroundColor Yellow
    Start-Service -Name 'BFE'
}

# ---------------------------------------------------------------- בנייה

if (-not $SkipBuild -and -not $SourcePath) {
    Write-Host "בונה את הפתרון..." -ForegroundColor Cyan

    $publishRoot = Join-Path $RepoRoot 'artifacts'
    Remove-Item -Recurse -Force $publishRoot -ErrorAction SilentlyContinue

    dotnet publish (Join-Path $RepoRoot 'src\SafeMe.Service\SafeMe.Service.csproj') `
        -c Release -r win-x64 --self-contained false -o $publishRoot | Out-Null

    dotnet publish (Join-Path $RepoRoot 'src\SafeMe.TrayApp\SafeMe.TrayApp.csproj') `
        -c Release -r win-x64 --self-contained false -o $publishRoot | Out-Null

    dotnet publish (Join-Path $RepoRoot 'src\SafeMe.Uninstaller\SafeMe.Uninstaller.csproj') `
        -c Release -r win-x64 --self-contained false -o $publishRoot | Out-Null

    if ($LASTEXITCODE -ne 0) { throw "הבנייה נכשלה." }
}

# ---------------------------------------------------------------- עצירת מופע קיים

$existing = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue

if ($existing) {
    Write-Host "עוצר מופע קיים של השירות..." -ForegroundColor Yellow

    Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 2

    & sc.exe delete $ServiceName | Out-Null
    Start-Sleep -Seconds 2
}

Get-Process -Name 'SafeMe.TrayApp' -ErrorAction SilentlyContinue | Stop-Process -Force

# ---------------------------------------------------------------- העתקת קבצים

Write-Host "מעתיק קבצים אל $InstallPath..." -ForegroundColor Cyan

New-Item -ItemType Directory -Force -Path $InstallPath | Out-Null
$copyFrom = if ($SourcePath) { $SourcePath } else { Join-Path $RepoRoot 'artifacts' }

if (-not (Test-Path $copyFrom)) { throw "תיקיית המקור לא נמצאה: $copyFrom" }

Copy-Item -Path (Join-Path $copyFrom '*') -Destination $InstallPath -Recurse -Force

# ---------------------------------------------------------------- קונפיגורציה

$configPath = Join-Path $InstallPath 'appsettings.json'
$config = Get-Content $configPath -Raw | ConvertFrom-Json

$config.Server.BaseUrl = $ServerUrl
$config.Server.AlwaysAllowHosts = @(([Uri]$ServerUrl).Host)

if ($EnrollToken) { $config.Server.EnrollToken = $EnrollToken }

$config | ConvertTo-Json -Depth 10 | Out-File $configPath -Encoding utf8

# ---------------------------------------------------------------- הקשחת הרשאות

Write-Host "מקשיח הרשאות על תיקיית ההתקנה..." -ForegroundColor Cyan

# הסרת ירושה, ואז הענקת שליטה ל-SYSTEM ולמנהלים בלבד.
# למשתמשים נשארת הרשאת קריאה והרצה, שנדרשת להפעלת אייקון המגש.
& icacls.exe $InstallPath /inheritance:r | Out-Null
& icacls.exe $InstallPath /grant:r "*S-1-5-18:(OI)(CI)F" | Out-Null
& icacls.exe $InstallPath /grant:r "*S-1-5-32-544:(OI)(CI)F" | Out-Null
& icacls.exe $InstallPath /grant:r "*S-1-5-32-545:(OI)(CI)RX" | Out-Null

# ---------------------------------------------------------------- רישום השירות

Write-Host "רושם את השירות..." -ForegroundColor Cyan

$exePath = Join-Path $InstallPath 'SafeMe.Service.exe'

& sc.exe create $ServiceName binPath= "`"$exePath`"" start= auto obj= "LocalSystem" DisplayName= "$DisplayName" | Out-Null
& sc.exe description $ServiceName "$Description" | Out-Null

# התאוששות אוטומטית: הפעלה מחדש בכל כשל, ללא איפוס מונה הכשלים
& sc.exe failure $ServiceName reset= 0 actions= restart/5000/restart/5000/restart/10000 | Out-Null
& sc.exe failureflag $ServiceName 1 | Out-Null

# הרצה גם ב-Safe Mode, כדי שאתחול למצב בטוח לא יעקוף את האכיפה
foreach ($mode in @('Minimal', 'Network')) {
    $key = "HKLM:\SYSTEM\CurrentControlSet\Control\SafeBoot\$mode\$ServiceName"
    New-Item -Path $key -Force | Out-Null
    Set-ItemProperty -Path $key -Name '(Default)' -Value 'Service'
}

# ---------------------------------------------------------------- משימת גיבוי

Write-Host "יוצר משימה מתוזמנת כשכבת גיבוי..." -ForegroundColor Cyan

$action    = New-ScheduledTaskAction -Execute 'sc.exe' -Argument "start $ServiceName"
$trigger   = New-ScheduledTaskTrigger -Once -At (Get-Date) `
                -RepetitionInterval (New-TimeSpan -Minutes 15) `
                -RepetitionDuration (New-TimeSpan -Days 3650)
$principalTask = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
$settings  = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries `
                -DontStopIfGoingOnBatteries -StartWhenAvailable -MultipleInstances IgnoreNew

Register-ScheduledTask -TaskName 'SafeMe\Guardian' -Action $action -Trigger $trigger `
    -Principal $principalTask -Settings $settings -Force | Out-Null

# ---------------------------------------------------------------- הפעלה

Write-Host "מפעיל את השירות..." -ForegroundColor Cyan

Start-Service -Name $ServiceName
Start-Sleep -Seconds 3

$service = Get-Service -Name $ServiceName

if ($service.Status -ne 'Running') {
    throw "השירות לא עלה. בדוק את יומן האירועים תחת המקור SafeMe."
}

Write-Host ""
Write-Host "ההתקנה הושלמה." -ForegroundColor Green
Write-Host "  שירות : $ServiceName ($($service.Status))"
Write-Host "  נתיב  : $InstallPath"
Write-Host "  שרת   : $ServerUrl"
Write-Host ""
Write-Host "אייקון המגש יעלה אוטומטית תוך כמה שניות בכל סשן משתמש מחובר."
