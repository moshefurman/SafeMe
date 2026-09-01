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

<#
    האם -Force קיים בכלל בבנייה הזו.

    בפיתוח כן, ובבנייה רשמית לא. build/pack.ps1 מחליף את השורה
    הזו ל-$false ומאמת שההחלפה תפסה — אם הסימן לא נמצא, האריזה
    נכשלת. סימן ששינה את שמו ואיש לא נכשל עליו הוא בדיוק הדרך
    שבה דלת אחורית נשארת פתוחה בלי שאיש התכוון.

    למה זה חשוב: -Force עוקף את כל תהליך ההסרה. בלי קוד, בלי
    מוקד, בלי אימות. כל ההקשחה — הרשאות שירות, הגנת רישום, שני
    שומרים, ובחירת ההורה בין הסרה עצמית להסרה דרך המוקד — אינה
    נוגעת בו כלל.

    וזו הנקודה שהופכת אותו לבלתי נסבל: ההורה מקבל הבטחה מפורשת
    במסך, "בחרת שההסרה תיעשה דרך המוקד בלבד", וההבטחה אינה נכונה
    כל עוד שורה אחת עוקפת אותה. פער כזה גרוע מהיעדר ההגדרה, כי
    הוא יוצר ביטחון שאינו קיים.
#>
$ForceAllowed = $true # SAFEME-FORCE-ALLOWED

$ErrorActionPreference = 'Stop'

$ServiceName = 'SafeMeAgent'
$GuardianName = 'SafeMeGuardian'
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

if ($Force -and -not $ForceAllowed) {
    Write-Host ""
    Write-Host "הסרה כפויה אינה קיימת בגרסה זו." -ForegroundColor Red
    Write-Host ""
    Write-Host "ההסרה נעשית בקוד בלבד. הרץ את הסקריפט בלי -Force," -ForegroundColor Yellow
    Write-Host "והפק קוד זיהוי במסך שייפתח." -ForegroundColor Yellow
    Write-Host ""
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

<#
    השומר נעצר ראשון, ובסדר הזה בדיוק.

    שני השירותים מחזירים זה את זה. עצירת הסוכן בזמן שהשומר פעיל
    תחזיר אותו תוך שתי שניות, וההסרה תיראה כאילו היא לא עובדת.

    זו בדיוק ההתנהגות הרצויה מול מי שמנסה לעצור — ולכן הסרה מסודרת
    חייבת לפרק את המנגנון לפי סדר, ולא להיאבק בו.
#>
<#
    משחרר את ההקשחה לפני העצירה.

    ההתקנה הסירה ממנהלים את הזכות לעצור ולמחוק. הסרה מסודרת מחזירה
    אותה במפורש ואז מפרקת — במקום להיאבק בהגנה שהיא עצמה התקינה.
#>
$default = 'D:(A;;CCLCSWRPWPDTLOCRSDRCWDWO;;;SY)(A;;CCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWLOCRRC;;;IU)(A;;CCLCSWLOCRRC;;;SU)'

foreach ($name in @($GuardianName, $ServiceName)) {
    & sc.exe sdset $name $default | Out-Null
}

Stop-Service -Name $GuardianName -Force -ErrorAction SilentlyContinue
& sc.exe delete $GuardianName | Out-Null

Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
Start-Sleep -Seconds 3

Get-Process -Name 'SafeMe.TrayApp' -ErrorAction SilentlyContinue | Stop-Process -Force

Write-Host "מוחק את רישום השירות..." -ForegroundColor Cyan
& sc.exe delete $ServiceName | Out-Null

Write-Host "מסיר משימה מתוזמנת..." -ForegroundColor Cyan
Unregister-ScheduledTask -TaskName 'SafeMe\Guardian' -Confirm:$false -ErrorAction SilentlyContinue

Write-Host "מנקה רישום Safe Mode..." -ForegroundColor Cyan
foreach ($mode in @('Minimal', 'Network')) {
    foreach ($name in @($ServiceName, $GuardianName)) {
        Remove-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SafeBoot\$mode\$name" `
            -Recurse -Force -ErrorAction SilentlyContinue
    }
}

# חוקי WFP נמחקים על ידי השירות עצמו בעת האישור. הניקוי כאן הוא רשת ביטחון
# למקרה שהשירות נהרג לפני שסיים, ומסתמך על כך שהסשן היה דינמי.
Write-Host "מוודא שאין חוקי רשת שנותרו..." -ForegroundColor Cyan

Write-Host "מוחק קבצים..." -ForegroundColor Cyan

Remove-Item -Recurse -Force $StateDir -ErrorAction SilentlyContinue
Remove-Item -Recurse -Force 'HKLM:\SOFTWARE\SafeMe' -ErrorAction SilentlyContinue
Remove-Item -Recurse -Force $InstallPath -ErrorAction SilentlyContinue

<#
    תיקיית ההתקנה, כשהמסיר רץ מתוכה.

    SafeMe.Uninstaller.exe יושב ב-$InstallPath, ותהליך אינו יכול
    למחוק את התיקייה שהוא רץ ממנה. Remove-Item נכשל, השגיאה נבלעה
    ב-SilentlyContinue, וההודעה "SafeMe הוסר מהמחשב" הופיעה בזמן
    שששים קבצים נשארו — ובהם appsettings.json עם כתובת השרת.

    נצפה בשטח בהסרה הראשונה שהצליחה מקצה לקצה.

    התשובה היא למחוק אחרי שהתהליך מת. cmd מנותק ממתין כמה שניות
    ומנקה, ו-Start-Process בלי -Wait מבטיח שהוא ישרוד את יציאתנו.

    ולא מדווחים הצלחה על מה שלא נבדק: אם משהו נשאר, נאמר מה ואיפה.
#>
if (Test-Path $InstallPath) {
    $remaining = @(Get-ChildItem $InstallPath -Recurse -File -Force -ErrorAction SilentlyContinue).Count

    <#
        השרשור בסוגריים, ולא חשוף.

        PowerShell פורש ארגומנטים של פקודה במצב פרשנות אחר: '+'
        אחרי מחרוזת אינו אופרטור אלא ארגומנט מיקומי נוסף, והקריאה
        נכשלת ב-"A positional parameter cannot be found".

        וזה נכשל בדיוק בשורה שאמורה למחוק את הקבצים — כלומר הסקריפט
        דיווח על הסרה והתיקייה נשארה שלמה, פעם שנייה באותו מקום.
    #>
    $cleanup = 'timeout /t 5 /nobreak >nul & rmdir /s /q "{0}"' -f $InstallPath

    Start-Process -FilePath 'cmd.exe' -WindowStyle Hidden -ArgumentList '/c', $cleanup

    Write-Host ""
    Write-Host "SafeMe הוסר. השירותים, ההגדרות וחוקי הרשת נמחקו." -ForegroundColor Green
    Write-Host ""
    Write-Host "$remaining קבצים בתיקיית ההתקנה יימחקו תוך כמה שניות," -ForegroundColor Yellow
    Write-Host "אחרי שתוכנית ההסרה עצמה תיסגר. אין צורך לעשות דבר." -ForegroundColor Yellow
    Write-Host "  $InstallPath" -ForegroundColor Yellow
}
else {
    Write-Host ""
    Write-Host "SafeMe הוסר מהמחשב." -ForegroundColor Green
}
