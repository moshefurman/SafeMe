<#
.SYNOPSIS
    מסיר את סוכן FilterPlus, לאחר שההסרה אושרה בקוד תקף.

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
    [string] $InstallPath = "$env:ProgramFiles\FilterPlus",
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
$ForceAllowed = $true # FILTERPLUS-FORCE-ALLOWED

$ErrorActionPreference = 'Stop'

$ServiceName = 'FilterPlusAgent'
$GuardianName = 'FilterPlusGuardian'
$StateDir    = "$env:ProgramData\FilterPlus"
$RegPath     = 'HKLM:\SOFTWARE\FilterPlus\Agent'

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

    $uninstaller = Join-Path $InstallPath 'FilterPlus.Uninstaller.exe'

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
        New-EventLog -LogName Application -Source 'FilterPlus' -ErrorAction SilentlyContinue
        Write-EventLog -LogName Application -Source 'FilterPlus' -EventId 9001 -EntryType Warning `
            -Message "בוצעה הסרה כפויה של FilterPlus על ידי $($identity.Name)."
    } catch {
        # אין למנוע הסרת חירום רק משום שהתיעוד נכשל
    }
}

<#
    עצירת שירות שאינה מפילה את הסקריפט.

    -ErrorAction SilentlyContinue אינו מספיק. השורה בראש הקובץ
    קובעת $ErrorActionPreference = 'Stop', וחריגות מסוימות של
    Stop-Service — "Cannot open <name> service on computer" —
    עולות ככשל קטלני למרות הדגל, ומפילות את כל ההתקנה.

    זה נצפה בשטח: ההתקנה הוצגה כ"נכשלה (קוד 1)" בגלל שירות
    שכבר לא היה שם. שירות חסר הוא בדיוק המצב הרגיל בהתקנה
    ראשונה, ואחרי הסרה שלא הושלמה.

    ההחזרה היא true/false כדי שהקורא יוכל להחליט. אף אחד מהם
    אינו מפיל.
#>
function Stop-FilterPlusService {
    param([Parameter(Mandatory)] [string] $Name)

    try {
        $svc = Get-Service -Name $Name -ErrorAction Stop
    }
    catch {
        # אין שירות כזה. אין מה לעצור, וזה אינו כשל.
        return $true
    }

    if ($svc.Status -eq 'Stopped') { return $true }

    try {
        Stop-Service -Name $Name -Force -ErrorAction Stop
        return $true
    }
    catch {
        Write-Host "  ! עצירת $Name נכשלה: $($_.Exception.Message)" -ForegroundColor Yellow
        return $false
    }
}

<#
    משחרר את הקשחת השירותים, כדי שאפשר יהיה לעצור ולמחוק אותם.

    ההתקנה אינה משאירה למנהלים את הזכות לשנות את הרשאות השירות
    (WD), ולכן sc sdset מתהליך של מנהל נכשל ב-Access Denied. רק
    SYSTEM יכול לשחרר.

    שני מסלולים:
      · העדכון האוטומטי רץ כ-SYSTEM ממילא, והפקודה הישירה מצליחה.
      · התקנה ידנית והסרה מאושרת רצות כמנהל. שם השחרור רץ דרך
        משימה מתוזמנת חד-פעמית כ-SYSTEM, שנמחקת מיד.

    זו אינה חומה, ואין להציג אותה ככזו: מנהל שיודע ליצור משימה
    כ-SYSTEM יכול לעשות את אותו הדבר ביד. מה שהשתנה הוא שפקודה
    אחת של sc כבר אינה מספיקה, ושיצירת משימה כזו משאירה רישום
    ביומן המשימות של Windows.

    הבדיקה היא על התוצאה ולא על קוד היציאה: sdshow אחרי השחרור
    צריך להראות שלמנהלים יש זכות עצירה (WP). פקודה שהצליחה ולא
    תפסה גרועה מכשל גלוי.
#>
function Unlock-FilterPlusService {
    param([Parameter(Mandatory)] [string] $Name)

    $default = 'D:(A;;CCLCSWRPWPDTLOCRSDRCWDWO;;;SY)(A;;CCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWLOCRRC;;;IU)(A;;CCLCSWLOCRRC;;;SU)'

    function Test-Released {
        $shown = ((& sc.exe sdshow $Name) -join '') -replace '\s', ''
        return $shown -match '\(A;;[A-Z]*WP[A-Z]*;;;BA\)'
    }

    & sc.exe sdset $Name $default | Out-Null

    if (Test-Released) { return $true }

    $task = 'FilterPlus-Unlock-' + [Guid]::NewGuid().ToString('N').Substring(0, 8)

    try {
        $action    = New-ScheduledTaskAction -Execute "$env:SystemRoot\System32\sc.exe" `
                         -Argument "sdset $Name $default"
        $principal = New-ScheduledTaskPrincipal -UserId 'S-1-5-18' -RunLevel Highest

        Register-ScheduledTask -TaskName $task -Action $action -Principal $principal -Force | Out-Null
        Start-ScheduledTask -TaskName $task

        # המשימה היא פקודה אחת של sc. עשר שניות הן מרווח נדיב.
        for ($i = 0; $i -lt 20; $i++) {
            Start-Sleep -Milliseconds 500
            if (Test-Released) { break }
        }
    }
    catch {
        Write-Host "  ! שחרור הרשאות $Name כ-SYSTEM נכשל: $($_.Exception.Message)" -ForegroundColor Yellow
    }
    finally {
        Unregister-ScheduledTask -TaskName $task -Confirm:$false -ErrorAction SilentlyContinue
    }

    if (Test-Released) { return $true }

    Write-Host "  ! הרשאות $Name לא שוחררו. העצירה והמחיקה שלו ייכשלו." -ForegroundColor Yellow
    return $false
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
foreach ($name in @($GuardianName, $ServiceName)) {
    if (Get-Service -Name $name -ErrorAction SilentlyContinue) {
        [void](Unlock-FilterPlusService -Name $name)
    }
}

[void](Stop-FilterPlusService -Name $GuardianName)
& sc.exe delete $GuardianName | Out-Null

[void](Stop-FilterPlusService -Name $ServiceName)
Start-Sleep -Seconds 3

Get-Process -Name 'FilterPlus.TrayApp' -ErrorAction SilentlyContinue | Stop-Process -Force

Write-Host "מוחק את רישום השירות..." -ForegroundColor Cyan
& sc.exe delete $ServiceName | Out-Null

Write-Host "מסיר משימה מתוזמנת..." -ForegroundColor Cyan
Unregister-ScheduledTask -TaskName 'FilterPlus\Guardian' -Confirm:$false -ErrorAction SilentlyContinue

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
Remove-Item -Recurse -Force 'HKLM:\SOFTWARE\FilterPlus' -ErrorAction SilentlyContinue

# הפניית ה-DNS של הרשימה הלבנה. הסוכן מסיר אותה בעצמו בהסרה מאושרת,
# אבל כלל שנשאר מאחור הוא מחשב בלי DNS, ולכן היא נמחקת גם כאן.
foreach ($root in @(
        'HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters\DnsPolicyConfig',
        'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient\DnsPolicyConfig')) {
    Get-ChildItem -Path $root -ErrorAction SilentlyContinue | Where-Object {
        $_.PSChildName -eq '{5AFE3E00-D5F1-4C0B-9A53-5AFE3E0D0053}' -or
        (Get-ItemProperty -Path $_.PSPath -ErrorAction SilentlyContinue).Comment -eq 'FilterPlus'
    } | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
}
Clear-DnsClientCache -ErrorAction SilentlyContinue
Remove-Item -Recurse -Force $InstallPath -ErrorAction SilentlyContinue

<#
    תיקיית ההתקנה, כשהמסיר רץ מתוכה.

    FilterPlus.Uninstaller.exe יושב ב-$InstallPath, ותהליך אינו יכול
    למחוק את התיקייה שהוא רץ ממנה. Remove-Item נכשל, השגיאה נבלעה
    ב-SilentlyContinue, וההודעה "FilterPlus הוסר מהמחשב" הופיעה בזמן
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

    Start-Process -FilePath 'cmd.exe' -WindowStyle Hidden -WorkingDirectory $env:SystemRoot `
        -ArgumentList '/c', $cleanup

    Write-Host ""
    Write-Host "FilterPlus הוסר. השירותים, ההגדרות וחוקי הרשת נמחקו." -ForegroundColor Green
    Write-Host ""
    Write-Host "$remaining קבצים בתיקיית ההתקנה יימחקו תוך כמה שניות," -ForegroundColor Yellow
    Write-Host "אחרי שתוכנית ההסרה עצמה תיסגר. אין צורך לעשות דבר." -ForegroundColor Yellow
    Write-Host "  $InstallPath" -ForegroundColor Yellow
}
else {
    Write-Host ""
    Write-Host "FilterPlus הוסר מהמחשב." -ForegroundColor Green
}
