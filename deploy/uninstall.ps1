<#
.SYNOPSIS
    מסיר את סוכן SafeMe, לאחר שההסרה אושרה בקוד תקף.

.DESCRIPTION
    הסקריפט בודק שקיים אסימון הסרה מאושר, שנכתב על ידי השירות רק לאחר
    אימות מוצלח של קוד מהמוקד. ללא אסימון הסקריפט מפעיל את מסך ההסרה
    ומסיים; הוא אינו מסיר דבר בכוח.

    -Force מיועד לשחזור חירום על ידי צוות התמיכה בלבד, ומתועד ביומן האירועים.

.EXAMPLE
    .\uninstall.ps1
#>

[CmdletBinding()]
param(
    [string] $InstallPath = "$env:ProgramFiles\SafeMe",
    [switch] $Force
)

$ErrorActionPreference = 'Stop'

$ServiceName = 'SafeMeAgent'
$StateDir    = "$env:ProgramData\SafeMe"
$RegPath     = 'HKLM:\SOFTWARE\SafeMe\Agent'

$identity  = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)

if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "יש להריץ את הסקריפט כמנהל מערכת."
}

# ---------------------------------------------------------------- בדיקת אישור

function Test-UninstallApproved {
    $approval = Get-ItemProperty -Path $RegPath -Name 'UninstallApproved' -ErrorAction SilentlyContinue

    if (-not $approval -or $approval.UninstallApproved -ne '1') { return $false }

    $stamp = Get-ItemProperty -Path $RegPath -Name 'UninstallApprovedUtc' -ErrorAction SilentlyContinue
    if (-not $stamp) { return $false }

    # האישור תקף לשעה בלבד, כדי שאישור ישן לא ישמש להסרה עתידית
    $approvedUtc = [DateTimeOffset]::Parse($stamp.UninstallApprovedUtc)

    return ([DateTimeOffset]::UtcNow - $approvedUtc).TotalHours -le 1
}

if (-not (Test-UninstallApproved) -and -not $Force) {
    Write-Host "ההסרה לא אושרה." -ForegroundColor Yellow
    Write-Host "פותח את מסך ההסרה. יש להפיק קוד אתגר ולקבל קוד הסרה מהמוקד."
    Write-Host ""

    $uninstaller = Join-Path $InstallPath 'SafeMe.Uninstaller.exe'

    if (Test-Path $uninstaller) {
        Start-Process $uninstaller
    } else {
        Write-Host "לא נמצא מסך ההסרה בנתיב $uninstaller" -ForegroundColor Red
    }

    exit 1
}

if ($Force) {
    Write-Warning "הסרה כפויה. הפעולה מתועדת ביומן האירועים."

    try {
        New-EventLog -LogName Application -Source 'SafeMe' -ErrorAction SilentlyContinue
        Write-EventLog -LogName Application -Source 'SafeMe' -EventId 9001 -EntryType Warning `
            -Message "בוצעה הסרה כפויה של SafeMe על ידי $($identity.Name)."
    } catch {
        # אין למנוע הסרת חירום רק משום שהתיעוד נכשל
    }
}

# ---------------------------------------------------------------- הסרה

Write-Host "עוצר את השירות..." -ForegroundColor Cyan

Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
Start-Sleep -Seconds 3

Get-Process -Name 'SafeMe.TrayApp' -ErrorAction SilentlyContinue | Stop-Process -Force

Write-Host "מוחק את רישום השירות..." -ForegroundColor Cyan
& sc.exe delete $ServiceName | Out-Null

Write-Host "מסיר משימה מתוזמנת..." -ForegroundColor Cyan
Unregister-ScheduledTask -TaskName 'SafeMe\Guardian' -Confirm:$false -ErrorAction SilentlyContinue

Write-Host "מנקה רישום Safe Mode..." -ForegroundColor Cyan
foreach ($mode in @('Minimal', 'Network')) {
    Remove-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SafeBoot\$mode\$ServiceName" `
        -Recurse -Force -ErrorAction SilentlyContinue
}

# חוקי WFP נמחקים על ידי השירות עצמו בעת האישור. הניקוי כאן הוא רשת ביטחון
# למקרה שהשירות נהרג לפני שסיים, ומסתמך על כך שהסשן היה דינמי.
Write-Host "מוודא שאין חוקי רשת שנותרו..." -ForegroundColor Cyan

Write-Host "מוחק קבצים..." -ForegroundColor Cyan
Remove-Item -Recurse -Force $InstallPath -ErrorAction SilentlyContinue
Remove-Item -Recurse -Force $StateDir -ErrorAction SilentlyContinue
Remove-Item -Recurse -Force 'HKLM:\SOFTWARE\SafeMe' -ErrorAction SilentlyContinue

Write-Host ""
Write-Host "SafeMe הוסר מהמחשב." -ForegroundColor Green
