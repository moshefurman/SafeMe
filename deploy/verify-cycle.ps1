<#
.SYNOPSIS
    מריץ את מחזור החיים המלא של SafeMe ומדווח ירוק/אדום על כל שלב.

.DESCRIPTION
    התקנה, רישום, קבלת מדיניות, זיהוי ספק, פעימות, ואם נמסר קוד —
    גם הסרה וניקיון מלא.

    למה זה קיים: כל באג שנמצא ב-1.9.2026 נמצא כשמישהו הריץ משהו על
    מכונה אמיתית, ולא כשמישהו קרא קוד. שלושה־עשר באגים ביום אחד,
    ובהם ארבעה שהיו מונעים מלקוח להסיר את התוכנה או מוציאים מחשב
    מהישג יד לצמיתות. כולם היו נתפסים כאן.

    הכלל שמנחה את הסקריפט: לעולם לא לדווח ירוק בלי מדידה. שלב
    שדולג נאמר במפורש כ"לא נבדק", כי בדיקה שלא רצה נראית בדוח בדיוק
    כמו בדיקה שעברה — וזה בדיוק איך שכשל עובר לייצור.

.PARAMETER Installer
    נתיב ל-SafeMe-Setup.exe שנבדק.

.PARAMETER EnrollToken
    אסימון ההתקנה, בצורה ENR-XXXXXXXXXXXXXXXXXXXXXXXX.

.PARAMETER ServerUrl
    הכתובת שהמחשב אמור לדבר איתה. נבדקת גם אחרי ההתקנה — עדכון
    שהסיט מחשב לכתובת אחרת הוציא אותו מהישג יד, וזה קרה.

.PARAMETER ExpectedProvider
    מזהה הספק שאמור להיזהות (netfree / rimon). כשלא נמסר, שלב
    הזיהוי מדווח מה נמצא בלי לקבוע אם זה נכון.

.PARAMETER UninstallCode
    קוד ההסרה מהפורטל. אם לא נמסר, הסקריפט מדפיס את קוד הזיהוי
    ומבקש אותו תוך כדי ריצה — הקוד נחתם מול זיהוי מסוים, ולכן אי
    אפשר להכין אותו מראש.

.PARAMETER SkipUninstall
    מדלג על שלבי ההסרה. הם ידווחו כלא נבדקו, לא כעברו.

.EXAMPLE
    .\verify-cycle.ps1 -Installer .\SafeMe-Setup.exe -EnrollToken ENR-... `
        -ServerUrl https://safeme-1-i3km.onrender.com -ExpectedProvider rimon
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string] $Installer,
    [Parameter(Mandatory)] [string] $EnrollToken,
    [Parameter(Mandatory)] [string] $ServerUrl,
    [string] $ExpectedProvider,
    [string] $UninstallCode,
    [switch] $SkipUninstall,
    [string] $InstallPath = "$env:ProgramFiles\SafeMe"
)

$ErrorActionPreference = 'Stop'

# ---------------------------------------------------------------- תשתית דוח

$script:Failed  = 0
$script:Skipped = 0

function Section([string] $Title) {
    Write-Host ""
    Write-Host $Title -ForegroundColor White
    Write-Host ('─' * 64) -ForegroundColor DarkGray
}

function Pass([string] $What, [string] $Measured = '') {
    $tail = if ($Measured) { " — $Measured" } else { '' }
    Write-Host "  [ עבר ] $What$tail" -ForegroundColor Green
}

function Fail([string] $What, [string] $Measured = '') {
    $script:Failed++
    $tail = if ($Measured) { " — $Measured" } else { '' }
    Write-Host "  [נכשל] $What$tail" -ForegroundColor Red
}

<#
    דילוג הוא לא הצלחה.

    זו הסיבה שיש לו צבע וספירה משלו: דוח שבו בדיקה שלא רצה נראית
    כמו בדיקה שעברה הוא בדיוק המנגנון שמעביר כשל לייצור.
#>
function Skip([string] $What, [string] $Why) {
    $script:Skipped++
    Write-Host "  [ דולג ] $What — $Why" -ForegroundColor Yellow
}

# ---------------------------------------------------------------- עזרי מדידה

function Get-AgentEvents([int] $Minutes = 10) {
    Get-WinEvent -FilterHashtable @{
        LogName      = 'Application'
        ProviderName = 'SafeMe'
        StartTime    = (Get-Date).AddMinutes(-$Minutes)
    } -ErrorAction SilentlyContinue | Sort-Object TimeCreated
}

function Test-AgentSaid([string] $Pattern, [int] $Minutes = 10) {
    return @(Get-AgentEvents -Minutes $Minutes |
        Where-Object { $_.Message -match $Pattern }).Count -gt 0
}

function Get-InstalledVersion {
    if ([string]::IsNullOrWhiteSpace($InstallPath)) { return $null }

    $exe = Join-Path $InstallPath 'SafeMe.Service.exe'

    if (-not (Test-Path -LiteralPath $exe -ErrorAction SilentlyContinue)) { return $null }

    return (Get-Item $exe).VersionInfo.FileVersion
}

function Get-SafeMeProcesses {
    return @(Get-Process -Name 'SafeMe.Service', 'SafeMe.Guardian', `
        'SafeMe.TrayApp', 'SafeMe.Uninstaller' -ErrorAction SilentlyContinue)
}

<#
    מנפיק התעודה, כפי שהמחשב באמת רואה אותו.

    זו המדידה שסגרה את השאלה "למה רימון לא מזוהה": התעודה מונפקת
    בשם Netspark, והמילה "רימון" אינה מופיעה בה כלל. תבנית שנבחרה
    לפי שם הספק המסחרי לא הייתה מתאימה לעולם.

    המארח חייב להיות כזה שהסינון מגיש עליו דף ולא מנתק — ניתוק אינו
    מציג תעודה, ואין ממנו מה ללמוד.
#>
function Get-TlsIssuer([string] $HostName) {
    $client = $null
    $ssl = $null

    try {
        $client = New-Object System.Net.Sockets.TcpClient($HostName, 443)

        $ssl = New-Object System.Net.Security.SslStream(
            $client.GetStream(), $false,
            ({ $true } -as [System.Net.Security.RemoteCertificateValidationCallback]))

        $ssl.AuthenticateAsClient($HostName)

        return (New-Object System.Security.Cryptography.X509Certificates.X509Certificate2(
            $ssl.RemoteCertificate)).Issuer
    }
    catch {
        return $null
    }
    finally {
        if ($ssl) { $ssl.Dispose() }
        if ($client) { $client.Dispose() }
    }
}

<#
    האם הסוכן באמת מדבר עם השרת.

    חיבור פתוח הוא הראיה הישירה היחידה שיש מכאן: הפעימה נרשמת ביומן
    ברמת מידע בלבד, ולכן שקט ביומן אינו אומר דבר. הדגימה חייבת לכסות
    מחזור פעימה שלם — דגימה של שבעים שניות מול מחזור של מאה שמונים
    מחזירה "אין תעבורה" על סוכן תקין לגמרי, וזה כבר הטעה.
#>
function Test-ServerTraffic([string] $Url, [int] $Seconds = 200) {
    $svc = Get-CimInstance Win32_Service -Filter "Name='SafeMeAgent'" -ErrorAction SilentlyContinue

    if (-not $svc -or -not $svc.ProcessId) { return $false }

    try { $ips = [System.Net.Dns]::GetHostAddresses(([Uri]$Url).Host) | ForEach-Object { $_.IPAddressToString } }
    catch { return $false }

    $until = (Get-Date).AddSeconds($Seconds)

    while ((Get-Date) -lt $until) {
        $hit = Get-NetTCPConnection -OwningProcess $svc.ProcessId -RemotePort 443 `
            -ErrorAction SilentlyContinue | Where-Object { $ips -contains $_.RemoteAddress }

        if ($hit) { return $true }

        Start-Sleep -Milliseconds 1500
    }

    return $false
}

function Test-WfpClean {
    $dump = (& netsh wfp show filters file=- 2>$null) -join ''

    return $dump -notmatch 'SafeMe'
}

# ---------------------------------------------------------------- פתיחה

$identity  = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)

if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "יש להריץ כמנהל מערכת."
}

if (-not (Test-Path $Installer)) { throw "לא נמצא מתקין: $Installer" }

Write-Host ""
Write-Host "════════════════════════════════════════════════════════════════"
Write-Host "  SafeMe · מחזור חיים מלא"
Write-Host "════════════════════════════════════════════════════════════════"
Write-Host "  מתקין : $Installer"
Write-Host "  שרת   : $ServerUrl"
Write-Host "  מחשב  : $env:COMPUTERNAME"

# ---------------------------------------------------------------- 0. נקודת התחלה

Section "0 · נקודת התחלה"

<#
    מכונה שאינה נקייה פוסלת את כל הריצה.

    המחזור בודק מעברים — מ"אין" ל"יש" ובחזרה — ומכונה שכבר מותקנת
    עליה התוכנה מדלגת על החצי הראשון בלי שהדבר ייראה בדוח. מריצים
    את זה על מכונה וירטואלית מצילום נקי, וזו כל הנקודה.
#>
$dirty = @()

if (Get-Service SafeMeAgent    -ErrorAction SilentlyContinue) { $dirty += 'שירות הסוכן' }
if (Get-Service SafeMeGuardian -ErrorAction SilentlyContinue) { $dirty += 'שירות השומר' }
if (Test-Path "$env:ProgramData\SafeMe")                      { $dirty += 'ProgramData' }
if (Test-Path 'HKLM:\SOFTWARE\SafeMe')                        { $dirty += 'מפתח רישום' }
if (@(Get-ChildItem $InstallPath -Recurse -File -Force -EA SilentlyContinue).Count -gt 0) {
    $dirty += 'תיקיית התקנה'
}

if ($dirty.Count -gt 0) {
    Fail "המכונה נקייה" ("נמצא: " + ($dirty -join ', '))

    Write-Host ""
    Write-Host "  המחזור נעצר. יש להריץ על מכונה נקייה — צילום מצב של VM." -ForegroundColor Yellow
    Write-Host ""

    exit 1
}

Pass "המכונה נקייה"

# ---------------------------------------------------------------- 1. התקנה

Section "1 · התקנה"

$installStart = Get-Date

$proc = Start-Process -FilePath $Installer -Wait -PassThru -NoNewWindow `
    -ArgumentList '--quiet', '--token', $EnrollToken, '--server', $ServerUrl

if ($proc.ExitCode -eq 0) {
    Pass "המתקין הסתיים" "קוד יציאה 0"
}
else {
    Fail "המתקין הסתיים" "קוד יציאה $($proc.ExitCode)"

    <#
        היומן, ולא רק המספר.

        "ההתקנה נכשלה (קוד 1)" בלי סיבה עלה שעה של חיפוש, פעמיים
        באותו יום. הסיבה תמיד הייתה בקובץ הזה.
    #>
    $log = Get-ChildItem "$env:ProgramData\SafeMe\logs\install-*.log" -EA SilentlyContinue |
        Sort-Object LastWriteTime | Select-Object -Last 1

    if ($log) {
        Write-Host ""
        Write-Host "  מתוך $($log.Name):" -ForegroundColor DarkGray
        Get-Content $log.FullName -Tail 12 | ForEach-Object { Write-Host "    $_" -ForegroundColor DarkGray }
    }
}

$version = Get-InstalledVersion

if ($version) { Pass "הקבצים נפרסו" "גרסה $version" }
else          { Fail "הקבצים נפרסו" "SafeMe.Service.exe לא נמצא" }

foreach ($name in 'SafeMeAgent', 'SafeMeGuardian') {
    $svc = Get-Service $name -ErrorAction SilentlyContinue

    if ($svc -and $svc.Status -eq 'Running') { Pass "שירות $name רץ" }
    elseif ($svc)                            { Fail "שירות $name רץ" $svc.Status }
    else                                     { Fail "שירות $name רץ" "אינו רשום" }
}

<#
    הכתובת שנכתבה בפועל.

    עדכון שנקטע השאיר כתובת ברירת מחדל שאינה נפתרת, וכל משיכת
    מדיניות נכשלה. החמור מכל: מחשב שאיבד את כתובתו אינו יכול לקבל
    גם את העדכון שיתקן אותה — הוא יוצא מהישג יד. זו בדיקה בת שורה
    שהייתה מונעת את זה.
#>
$configPath = Join-Path $InstallPath 'appsettings.json'

if (Test-Path $configPath) {
    $baseUrl = (Get-Content $configPath -Raw | ConvertFrom-Json).Server.BaseUrl

    if ($baseUrl -eq $ServerUrl) { Pass "כתובת השרת נכתבה" $baseUrl }
    else                         { Fail "כתובת השרת נכתבה" "התקבל $baseUrl" }
}
else {
    Fail "כתובת השרת נכתבה" "appsettings.json חסר"
}

# ---------------------------------------------------------------- 2. קשר לשרת

Section "2 · קשר לשרת"

Write-Host "  דוגם מחזור פעימה שלם, עד 200 שניות..." -ForegroundColor DarkGray

if (Test-ServerTraffic -Url $ServerUrl) { Pass "הסוכן מדבר עם השרת" }
else                                    { Fail "הסוכן מדבר עם השרת" "לא נצפתה תעבורה במחזור שלם" }

<#
    מדיניות שהגיעה, ולא רק סימן שלה.

    הרישום מחזיר ETag, והסוכן שלח אותו במשיכה הראשונה. השרת ענה
    "לא השתנה", והסוכן נשאר בלי מדיניות בזמן שהדיסק שלו היה ריק —
    ומכיוון שהסימן כבר תאם, שום פעימה עתידית לא משכה שוב. סוכן בלי
    מדיניות אין לו כללי זיהוי, ולכן הוא מדווח שהחיבור אינו מסונן
    על מחשב מסונן לחלוטין.
#>
$policyEvent = Get-AgentEvents -Minutes 15 |
    Where-Object { $_.Message -match 'מדיניות גרסה \d+ הוחלה' } |
    Select-Object -Last 1

if ($policyEvent) {
    <#
        המספר נחלץ מהשורה שנמצאה, ולא מ-$Matches שנשאר מקריאה
        קודמת. $Matches הוא משתנה גלובלי שכל -match דורס, וערך
        ששרד מבדיקה אחרת נראה כאן בדיוק כמו מדידה אמיתית.
    #>
    $shown = ''

    if ($policyEvent.Message -match 'מדיניות גרסה (\d+) הוחלה') { $shown = "גרסה $($Matches[1])" }

    Pass "מדיניות התקבלה והוחלה" $shown
}
else {
    Fail "מדיניות התקבלה והוחלה" "לא נרשמה החלת מדיניות"
}

if (Test-AgentSaid 'משיכת מדיניות נכשלה' -Minutes 15) {
    Fail "אין כשלי משיכת מדיניות" "נרשם כשל ביומן"
}
else {
    Pass "אין כשלי משיכת מדיניות"
}

# ---------------------------------------------------------------- 3. זיהוי ספק

Section "3 · זיהוי ספק סינון"

$issuer = Get-TlsIssuer 'www.bet365.com'

if ($issuer) { Write-Host "  מנפיק התעודה בפועל: $issuer" -ForegroundColor DarkGray }
else         { Write-Host "  לא ניתן היה לקרוא תעודה מ-www.bet365.com" -ForegroundColor DarkGray }

<#
    אזהרה מפורשת כשאין ממה לזהות.

    מריצים את זה על מכונה שמחוברת דרך ספק מסונן, אחרת השלב הזה
    בודק שהסוכן לא מזהה כלום — וזה נכון אך חסר ערך.
#>
if ($issuer -and $issuer -notmatch 'Netspark|NetFree|Rimon') {
    Write-Host "  ! החיבור אינו נראה מסונן. שלב הזיהוי אינו בדיקה אמיתית כאן." -ForegroundColor Yellow
}

if (Test-AgentSaid 'לא זוהה אף ספק סינון מאושר' -Minutes 15) {
    Fail "ספק זוהה" "הסוכן דיווח שלא זוהה ספק"
}
elseif (Test-AgentSaid 'זוהה ספק' -Minutes 15) {
    $ev = Get-AgentEvents -Minutes 15 | Where-Object { $_.Message -match 'זוהה ספק (\w+)' } |
        Select-Object -Last 1

    $found = if ($ev.Message -match 'זוהה ספק (\w+)') { $Matches[1] } else { '?' }

    if (-not $ExpectedProvider)          { Pass "ספק זוהה" $found }
    elseif ($found -eq $ExpectedProvider) { Pass "ספק זוהה" $found }
    else                                  { Fail "ספק זוהה" "צפוי $ExpectedProvider, התקבל $found" }
}
else {
    <#
        אין הכרעה זה לא כשל, וגם לא הצלחה.

        זיהוי נרשם ברמת מידע, ויומן האירועים מקבל אזהרות ומעלה
        בלבד. היעדר שורה כאן פירושו שאין לנו מה למדוד — לא שהזיהוי
        נכשל. ההבחנה הזו היא בדיוק מה שהיה חסר כשסוכן בלי כללים
        הכריז "אינו מסונן" במקום "אינני יודע".
    #>
    Skip "ספק זוהה" "אין רישום מכריע ביומן"
}

# ---------------------------------------------------------------- 4. הסרה

Section "4 · הסרה"

if ($SkipUninstall) {
    Skip "ההסרה בוצעה"       "נתבקש דילוג מפורש"
    Skip "המחשב נוקה במלואו" "ההסרה לא בוצעה"
}
else {
    <#
        ההסרה נעשית דרך המסיר, ולא דרך הסקריפט ישירות.

        זה מה שהמשתמש מפעיל, ולכן זה מה שצריך להיבדק. הסקריפט
        לבדו עוקף את האימות, ובדיקה שעוקפת את החלק שנשבר אינה
        בדיקה.

        --code הוא מסלול לא אינטראקטיבי לבדיקות; אם אינו קיים
        בבנייה, השלב נופל וזה בדיוק מה שצריך לקרות.
    #>
    $uninstaller = Join-Path $InstallPath 'SafeMe.Uninstaller.exe'

    if (-not (Test-Path $uninstaller)) {
        Fail "ההסרה בוצעה" "לא נמצא SafeMe.Uninstaller.exe"
    }
    else {
        <#
            הזיהוי מונפק כאן, והקוד חייב להיות שלו.

            אתגר כולל nonce אקראי, וקוד ההסרה נחתם מולו. אי אפשר
            להנפיק זיהוי חדש ולהשתמש בקוד שהופק מול קודם — וזו לא
            מגבלה טכנית אלא ההגנה עצמה, מפני קוד שנשמר ומשמש שוב.

            לכן שני שלבים: הסקריפט מדפיס את הזיהוי, ממתין שתנפיק
            מולו קוד, ורק אז מאמת.
        #>
        $challenge = (& $uninstaller --new-challenge 2>&1 | Select-Object -Last 1).ToString().Trim()

        if (-not $challenge -or $challenge -notmatch '^[0-9A-Z-]{20,}$') {
            Fail "הופק קוד זיהוי" $challenge
        }
        else {
            Pass "הופק קוד זיהוי" $challenge

            if (-not $UninstallCode) {
                Write-Host ""
                Write-Host "  הנפק קוד הסרה בפורטל מול הזיהוי שלמעלה, והדבק אותו כאן." -ForegroundColor Cyan
                $UninstallCode = (Read-Host "  קוד הסרה").Trim()
            }

            $u = Start-Process -FilePath $uninstaller -Wait -PassThru -NoNewWindow `
                -ArgumentList '--challenge', $challenge, '--code', $UninstallCode

            if ($u.ExitCode -eq 0) { Pass "ההסרה בוצעה" }
            else                   { Fail "ההסרה בוצעה" "קוד יציאה $($u.ExitCode)" }
        }

        # התיקייה נמחקת על ידי תהליך מושהה, אחרי שהמסיר עצמו מת
        Start-Sleep -Seconds 12

        $left = @()

        if (Get-Service SafeMeAgent    -EA SilentlyContinue) { $left += 'שירות הסוכן' }
        if (Get-Service SafeMeGuardian -EA SilentlyContinue) { $left += 'שירות השומר' }
        if (Test-Path 'HKLM:\SOFTWARE\SafeMe')               { $left += 'מפתח רישום' }
        if (Test-Path "$env:ProgramData\SafeMe")             { $left += 'ProgramData' }
        if (Get-ScheduledTask -TaskName 'SafeMe*' -EA SilentlyContinue) { $left += 'משימה מתוזמנת' }

        $files = @(Get-ChildItem $InstallPath -Recurse -File -Force -EA SilentlyContinue).Count
        if ($files -gt 0) { $left += "$files קבצים" }

        $procs = Get-SafeMeProcesses
        if ($procs.Count -gt 0) { $left += "$($procs.Count) תהליכים" }

        if ($left.Count -eq 0) { Pass "המחשב נוקה במלואו" }
        else                   { Fail "המחשב נוקה במלואו" ($left -join ', ') }

        <#
            חוקי רשת שנשארו הם הכשל השקט ביותר.

            אין להם ממשק, אין מי שיתלונן עליהם, והם ממשיכים לחסום
            תעבורה אחרי שהתוכנה כבר לא קיימת — כלומר אין גם מי
            שישחרר אותם.
        #>
        if (Test-WfpClean) { Pass "לא נותרו חוקי רשת" }
        else               { Fail "לא נותרו חוקי רשת" "נמצאו חוקי SafeMe ב-WFP" }

        <#
            השומר לא התערב.

            השמירה ההדדית לא הכירה במצב "ההסרה אושרה", והחזירה את
            שני השירותים תוך שתי שניות מכל הסרה — כולל הסרה עם קוד
            תקף. התוצאה נראתה כמו הסרה שהצליחה, ובפועל השאירה שני
            שירותים רצים מתוך תיקייה שנמחקה למחצה.
        #>
        if (Test-AgentSaid 'הוחזר לפעולה על ידי השומר|שירות השומר נעצר והוחזר' -Minutes 5) {
            Fail "השומר לא התנגד להסרה" "נרשמה החזרת שירות אחרי האישור"
        }
        else {
            Pass "השומר לא התנגד להסרה"
        }
    }
}

# ---------------------------------------------------------------- סיכום

Write-Host ""
Write-Host "════════════════════════════════════════════════════════════════"

if ($script:Failed -eq 0 -and $script:Skipped -eq 0) {
    Write-Host "  המחזור עבר במלואו." -ForegroundColor Green
}
elseif ($script:Failed -eq 0) {
    Write-Host "  לא נמצאו כשלים, אך $($script:Skipped) שלבים לא נבדקו." -ForegroundColor Yellow
    Write-Host "  מחזור עם דילוגים אינו אישור לשחרור." -ForegroundColor Yellow
}
else {
    Write-Host "  $($script:Failed) כשלים · $($script:Skipped) דילוגים" -ForegroundColor Red
}

Write-Host "════════════════════════════════════════════════════════════════"
Write-Host ""

if ($script:Failed -gt 0) { exit 1 }

exit 0
