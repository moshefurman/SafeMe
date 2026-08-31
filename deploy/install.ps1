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
    # מרכז הניהול. מארח נפרד מה-API, ולכן נמסר בנפרד.
    #
    # בלעדיו, מחשב שנחסם אינו יכול להגיע למסך שבו מסירים את החסימה.
    # ההורה נשאר מול מחשב נעול, והדרך היחידה החוצה עוברת במחשב אחר.
    [string] $PortalUrl   = "",
    [string] $EnrollToken = "",
    # התקנה ללא חשבון: המחשב נחסם לחלוטין, וההסרה מחייבת קוד מהמוקד.
    # דגל מפורש ולא אסימון ריק, כי אסימון ריק נראה בדיוק כמו אסימון
    # שנשכח בטעות — ושני מצבים שנראים זהים הם מצב אחד שלא נבדק.
    [switch] $Unmanaged,
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

# ---------------------------------------------------------------- השהיית השומרים

<#
    מסמן לשומרים שלא יתערבו, לפני כל דבר אחר.

    שלושה רכיבים בסוכן נלחמים במתקין בלי הסימן הזה: שירות
    השומר מחזיר את הסוכן, הסוכן מחזיר את השומר, ו-IntegrityWorker
    מקשיח מחדש כל שלושים שניות. כל אחד מהם מספיק כדי ש-Stop-Service
    ו-sc delete ייכשלו והקבצים יישארו נעולים.

    הסימן נכתב בעדכון אוטומטי, ולא בהתקנה ידנית — ולכן הוא
    נכתב גם כאן. כל התקנה היא התקנה, והשומרים צריכים לעמוד
    בצד בשתיהן.

    לסימן יש תפוגה של חמש דקות, ולכן התקנה שנקטעה אינה
    משתיקה אותם לנצח.
#>

$markerDir  = Join-Path $env:ProgramData 'SafeMe\state'
$markerPath = Join-Path $markerDir 'update.lock'

try {
    New-Item -ItemType Directory -Force -Path $markerDir | Out-Null
    [System.IO.File]::WriteAllText($markerPath, (Get-Date).ToUniversalTime().ToString('o'))
}
catch {
    Write-Host "  ! לא ניתן לסמן התקנה בעיצומה: $($_.Exception.Message)" -ForegroundColor Yellow
    Write-Host "    השומרים עלולים להתערב. אם ההתקנה נכשלת, זו הסיבה הראשונה לבדוק." -ForegroundColor Yellow
}

# ---------------------------------------------------------------- רשת ביטחון

<#
    מהרגע שהשירותים נמחקים ועד שהם נרשמים מחדש, המחשב
    חשוף. כל כשל בדרך משאיר אותו כך.

    זה קרה בשטח בעדכון ל-1.1.27: המתקין מחק את שני
    השירותים, שומר שהתעורר החזיר אחד מהם תוך שתי שניות,
    הקבצים נעלו, ההעתקה נכשלה — והמחשב נשאר בלי שירות סוכן
    כלל, עד שמישהו רשם אותו ידנית.

    המלכודת כאן רושמת את השירותים בחזרה ממה שיש בתיקייה,
    גם אם אלה הקבצים הישנים. גרסה ישנה שעובדת עדיפה על היעדר
    הגנה, והעדכון ינוסה שוב מאוחר יותר.
#>

$script:ServicesRemoved = $false

function Restore-ServicesAfterFailure {
    if (-not $script:ServicesRemoved) { return }

    $svcExe = Join-Path $InstallPath 'SafeMe.Service.exe'
    $gdExe  = Join-Path $InstallPath 'SafeMe.Guardian.exe'

    Write-Host ""
    Write-Host "ההתקנה נכשלה. מחזיר את השירותים כדי שהמחשב לא יישאר חשוף..." -ForegroundColor Yellow

    if ((Test-Path $svcExe) -and -not (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue)) {
        & sc.exe create $ServiceName binPath= "`"$svcExe`"" start= auto obj= "LocalSystem" `
            DisplayName= "$DisplayName" | Out-Null
        & sc.exe failure $ServiceName reset= 0 actions= restart/5000/restart/5000/restart/10000 | Out-Null
        Start-Service -Name $ServiceName -ErrorAction SilentlyContinue
        Write-Host "  $ServiceName הוחזר." -ForegroundColor Green
    }

    if ((Test-Path $gdExe) -and -not (Get-Service -Name 'SafeMeGuardian' -ErrorAction SilentlyContinue)) {
        & sc.exe create 'SafeMeGuardian' binPath= "`"$gdExe`"" start= auto obj= "LocalSystem" `
            DisplayName= "SafeMe Guardian" | Out-Null
        & sc.exe failure 'SafeMeGuardian' reset= 0 actions= restart/5000/restart/5000/restart/10000 | Out-Null
        Start-Service -Name 'SafeMeGuardian' -ErrorAction SilentlyContinue
        Write-Host "  SafeMeGuardian הוחזר." -ForegroundColor Green
    }

    Write-Host "  המחשב מוגן בגרסה שהייתה מותקנת. נסה את העדכון שוב." -ForegroundColor Yellow
}

trap {
    Restore-ServicesAfterFailure
    break
}

# ---------------------------------------------------------------- עצירת מופע קיים

$existing = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue

if ($existing) {
    Write-Host "עוצר מופע קיים של השירות..." -ForegroundColor Yellow

    <#
        משחרר את ההקשחה לפני העצירה.

        התקנה קודמת הסירה ממנהלים את הזכות לעצור, ולכן בלי השחרור
        הזה ההתקנה מחדש הייתה נכשלת בשקט: Stop-Service עם
        SilentlyContinue אינו מתלונן, sc delete נכשל, ו-sc create
        נכשל אחריו — והמשתמש היה מקבל "ההתקנה נכשלה" בלי סיבה.

        השומר מוסר ראשון, כדי שלא יחזיר את הסוכן באמצע.
    #>
    $default = 'D:(A;;CCLCSWRPWPDTLOCRSDRCWDWO;;;SY)(A;;CCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWLOCRRC;;;IU)(A;;CCLCSWLOCRRC;;;SU)'

    foreach ($name in @('SafeMeGuardian', $ServiceName)) {
        if (Get-Service -Name $name -ErrorAction SilentlyContinue) {
            & sc.exe sdset $name $default | Out-Null

            <#
                וגם ההקשחה על מפתח הרישום, לא רק על אובייקט השירות.
                
                הן שתי הרשאות נפרדות לגמרי, והשחרור טיפל רק באחת.
                sc create, sc description ו-sc failure כותבים כולם
                למפתח — ומנהל שאין לו SetValue מקבל Access denied.
                
                כלומר כל התקנה חוזרת התנגשה בהקשחה שההתקנה הקודמת
                יצרה. זה מה שהרג את העדכון ל-1.1.27 אחרי שהשירותים
                כבר נמחקו, והשאיר את המחשב בלי סוכן.
                
                הירושה מוחזרת והכללים המפורשים מוסרים; ההקשחה תוחל
                מחדש בסוף ההתקנה ממילא.
            #>
            try {
                $hklm = [Microsoft.Win32.RegistryKey]::OpenBaseKey(
                    [Microsoft.Win32.RegistryHive]::LocalMachine,
                    [Microsoft.Win32.RegistryView]::Default)

                $key = $hklm.OpenSubKey(
                    "SYSTEM\CurrentControlSet\Services\$name",
                    [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree,
                    [System.Security.AccessControl.RegistryRights]::ChangePermissions)

                if ($key) {
                    $acl = $key.GetAccessControl()
                    $acl.SetAccessRuleProtection($false, $true)
                    $key.SetAccessControl($acl)
                    $key.Close()
                }
            }
            catch {
                Write-Host "  ! שחרור הרשאות הרישום של $name נכשל: $($_.Exception.Message)" `
                    -ForegroundColor Yellow
            }

            Stop-Service -Name $name -Force -ErrorAction SilentlyContinue
            & sc.exe delete $name | Out-Null
        }
    }

    Start-Sleep -Seconds 2

    Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 2

    & sc.exe delete $ServiceName | Out-Null
    Start-Sleep -Seconds 2

    # מכאן והלאה המחשב חשוף עד ש-sc create ירוץ. המלכודת למעלה
    # מחזירה את השירותים אם משהו בדרך נכשל.
    $script:ServicesRemoved = $true
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

# שני המארחים נשארים פתוחים גם בחסימה מלאה: ה-API כדי שהמחשב
# יוכל לדווח ולקבל שחרור, והפורטל כדי שיהיה מסך שאפשר לשחרר ממנו.
$allowHosts = @(([Uri]$ServerUrl).Host)

if ($PortalUrl) {
    $portalHost = ([Uri]$PortalUrl).Host

    if ($portalHost -and $allowHosts -notcontains $portalHost) {
        $allowHosts += $portalHost
    }
}

$config.Server.AlwaysAllowHosts = $allowHosts

if ($Unmanaged -and $EnrollToken) {
    throw "אי אפשר להעביר גם -Unmanaged וגם -EnrollToken. יש לבחור אחד."
}

# ---------------------------------------------------------------- שער הבטיחות
#
# חסימה מוחלטת בלי מפתח לאימות קודי הסרה היא חסימה לצמיתות.
#
# במסלול הרגיל המפתח מגיע מהשרת בתשובת הרישום. כאן אין רישום, ולכן
# הוא חייב להיות מוטבע בהתקנה. אם הוא חסר — עדיף להיכשל עכשיו, כשעוד
# לא נגענו במחשב, מאשר לחסום אותו ולגלות זאת אחר כך בטלפון.

if ($Unmanaged) {
    $embedded = $config.Server.UninstallPublicKeyPem

    if (-not $embedded -or $embedded -notmatch 'BEGIN PUBLIC KEY') {
        throw @"
התקנה ללא חשבון בוטלה: חסר מפתח ציבורי לאימות קודי הסרה.

בלעדיו המחשב היה נחסם בלי שום דרך לשחרר אותו, גם לא מהמוקד.
המפתח מוטבע בשלב האריזה. יש לארוז מחדש עם build/pack.ps1.
"@
    }
}

if ($EnrollToken) { $config.Server.EnrollToken = $EnrollToken }

# הסוכן קורא את הדגל הזה בעלייה ונכנס לחסימה מוחלטת. הוא נכתב
# לקובץ התצורה ולא נגזר מהיעדר אסימון: קובץ תצורה שנפגם והשמיט
# אסימון היה מפעיל חסימה מוחלטת בטעות.
$config.Server | Add-Member -NotePropertyName Unmanaged -NotePropertyValue ([bool]$Unmanaged) -Force

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

# ---------------------------------------------------------------- שירות השומר

<#
    שני שירותים ששומרים זה על זה.

    שירות אינו יכול לשמור על עצמו: ברגע שהוא נעצר, כל קוד שבתוכו
    נעצר איתו. sc failure מחזיר שירות שקרס, אך עצירה בפקודה אינה כשל
    ומבחינת Windows לא קרה דבר.

    כדי לכבות את ההגנה צריך עכשיו לעצור את שניהם בתוך פחות משתי
    שניות — ואז המשימה המתוזמנת עוד ממתינה ברקע.
#>

Write-Host "רושם את שירות השומר..." -ForegroundColor Cyan

$guardianName = 'SafeMeGuardian'
$guardianExe  = Join-Path $InstallPath 'SafeMe.Guardian.exe'

& sc.exe create $guardianName binPath= "`"$guardianExe`"" start= auto obj= "LocalSystem" `
    DisplayName= "SafeMe Guardian" | Out-Null
& sc.exe description $guardianName "מחזיר את שירות SafeMe אם נעצר." | Out-Null
& sc.exe failure $guardianName reset= 0 actions= restart/5000/restart/5000/restart/10000 | Out-Null
& sc.exe failureflag $guardianName 1 | Out-Null

foreach ($mode in @('Minimal', 'Network')) {
    $key = "HKLM:\SYSTEM\CurrentControlSet\Control\SafeBoot\$mode\$guardianName"
    New-Item -Path $key -Force | Out-Null
    Set-ItemProperty -Path $key -Name '(Default)' -Value 'Service'
}

# ---------------------------------------------------------------- הקשחת השירותים

<#
    מסיר ממנהלים את הזכות לעצור ולמחוק את השירותים.

    עד כאן כל מי שיש לו הרשאות מנהל יכול היה להריץ sc stop, והשומר
    היה מחזיר תוך שתי שניות. זה עבד, אבל זו הייתה תחרות — והדרך
    לנצח בה היא פשוט להריץ את הפקודה בלולאה.

    עכשיו הפקודה עצמה נכשלת ב-Access Denied. SYSTEM שומר על שליטה
    מלאה, ולכן העדכון האוטומטי, השומר וההסרה המסודרת ממשיכים לעבוד.

    מה זה **אינו**: חומה. מנהל יכול לקחת בעלות על האובייקט ולשכתב
    את ההרשאות. אבל זו כבר פעולה מכוונת בכמה שלבים, שמשאירה עקבות
    ביומן — ולא שורה אחת. זו כל המטרה הריאלית בלי מנהל התקן חתום.

    פירוט ההרשאות:
      CC  שאילתת הגדרות      LC  שאילתת מצב
      SW  מניית תלויות       RP  הפעלה
      WP  עצירה              DT  השהיה
      LO  תשאול              CR  פקודה מותאמת
      RC  קריאת הרשאות       SD  מחיקה
      WD  שינוי הרשאות       WO  שינוי בעלות

    למנהלים ניתנות שאילתה, הפעלה, ושינוי הרשאות — אך לא WP, לא SD,
    ולא DC. היעדר DC הוא שעוצר את sc config, שהוא מסלול העקיפה
    השקט ביותר: החלפת נתיב ההרצה משאירה שירות בשם SafeMe שמריץ
    משהו אחר, והכול נראה תקין.

    WD למנהלים הוא ויתור מחושב. בלעדיו גם המתקין שלנו לא היה יכול
    לעצור את השירות בהתקנה ידנית, כי הוא רץ כמנהל ולא כ-SYSTEM.
    איתו, עצירה דורשת שתי פקודות מכוונות במקום אחת — והשנייה
    מזוהה ומדווחת בידי בודק השלמות.

    זו המטרה הריאלית בלי מנהל התקן חתום: לא למנוע, אלא להפוך כל
    ניסיון לפעולה מכוונת שמשאירה סימן.
#>

Write-Host "מקשיח את הרשאות השירותים..." -ForegroundColor Cyan

$hardened = 'D:(A;;CCLCSWRPWPDTLOCRSDRCWDWO;;;SY)(A;;CCLCSWRPLOCRRCWD;;;BA)(A;;CCLCSWLOCRRC;;;IU)(A;;CCLCSWLOCRRC;;;SU)'

foreach ($name in @($ServiceName, $guardianName)) {
    & sc.exe sdset $name $hardened | Out-Null

    # אימות בשטח: הרשאה שלא נתפסה גרועה מהרשאה שלא נוסתה, כי היא
    # יוצרת ביטחון שאינו קיים
    $applied = (& sc.exe sdshow $name) -join ''

    if ($applied -notmatch 'CCLCSWRPLOCRRCWD;;;BA') {
        Write-Host "  ! הקשחת $name לא נתפסה. השירות עדיין ניתן לעצירה בידי מנהל." `
            -ForegroundColor Yellow
    }
}

# ---------------------------------------------------------------- הרשאות הרישום

<#
    מגן על מפתחות הרישום של השירותים.

    לא מפני sc config — אותו עוצרת הקשחת אובייקט השירות, שאינה
    מעניקה למנהלים את DC. sc config אינו כותב לרישום מהתהליך
    הקורא אלא שולח RPC ל-SCM, וה-SCM כותב כ-SYSTEM — כלומר ה-ACL
    כאן לא היה עוצר אותו בכל מקרה.

    מה שהוא כן עוצר: עריכה ישירה של המפתח, שעוקפת את SCM לגמרי.
    reg add על ImagePath, או regedit ביד. שם אין בקשת RPC ואין
    בדיקת זכויות על השירות — יש רק ההרשאות של המפתח עצמו.

    התוצאה של עקיפה כזו זהה בשני המסלולים, והיא שקטה במיוחד:
    שירות בשם SafeMe שמריץ משהו אחר. הכול נראה מותקן ותקין,
    השירות "רץ", ובפועל אין הגנה.

    מנהלים מקבלים קריאה בלבד — ובנוסף שינוי הרשאות ובעלות, מאותה
    סיבה שהם קיבלו אותם על אובייקט השירות: בלעדיהם ההסרה וההתקנה
    מחדש היו נתקעות. שני צעדים במקום אחד, והשני מזוהה.
#>

Write-Host "מגן על מפתחות הרישום..." -ForegroundColor Cyan

<#
    פתיחה מפורשת עם ChangePermissions.

    Get-Item פותח את המפתח לקריאה בלבד, ו-SetAccessControl עליו נכשל
    ב-"Cannot write to the registry key" — גם כשמריצים כמנהל. זו
    הייתה התקלה: הבלוק רץ, נכשל, הדפיס אזהרה צהובה שאיש לא רואה
    בעדכון אוטומטי, וההגנה מעולם לא הוחלה.
#>

$hklm = [Microsoft.Win32.RegistryKey]::OpenBaseKey(
    [Microsoft.Win32.RegistryHive]::LocalMachine,
    [Microsoft.Win32.RegistryView]::Default)

foreach ($name in @($ServiceName, $guardianName)) {
    try {
        $key = $hklm.OpenSubKey(
            "SYSTEM\CurrentControlSet\Services\$name",
            [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree,
            [System.Security.AccessControl.RegistryRights]::ChangePermissions)

        if (-not $key) { throw "המפתח אינו קיים" }

        $acl = $key.GetAccessControl()
        $acl.SetAccessRuleProtection($true, $false)

        foreach ($rule in @($acl.Access)) { [void]$acl.RemoveAccessRule($rule) }

        $inherit = [System.Security.AccessControl.InheritanceFlags]::ContainerInherit

        $acl.AddAccessRule((New-Object System.Security.AccessControl.RegistryAccessRule(
            'NT AUTHORITY\SYSTEM', 'FullControl', $inherit, 'None', 'Allow')))

        # קריאה, ושתי הזכויות שמאפשרות שחזור מכוון
        $acl.AddAccessRule((New-Object System.Security.AccessControl.RegistryAccessRule(
            'BUILTIN\Administrators',
            'ReadKey, ChangePermissions, TakeOwnership',
            $inherit, 'None', 'Allow')))

        <#
            קריאה למשתמשים רגילים — לא ויתור, תיקון.

            בלי הכלל הזה נשברת בדיקת מצב השירות מכל תהליך לא-מוסלם.
            SCM קורא את DisplayName מהמפתח בהתחזות לקורא, ולכן
            GetServiceDisplayName מחזיר Access denied — ו-ServiceController
            מתרגם את זה ל"השירות לא נמצא". אפליקציית המגש מסיקה שהסוכן
            הוסר, ומנסה להפעילו כל שתי דקות בלי סיכוי.

            קריאה אינה מחלישה דבר. מה שנחסם כאן הוא כתיבה ל-ImagePath,
            והתוכן עצמו גלוי ממילא לכל משתמש דרך sc qc. כך בדיוק בנויים
            שירותי המערכת: Spooler נותן ReadKey ל-BUILTIN\Users.

            השורה נוספה אחרי שההגנה הראשונה נבדקה רק מהצד שהוקשח.
            האימות למטה בודק מעכשיו גם את הצד שנשבר.
        #>
        $acl.AddAccessRule((New-Object System.Security.AccessControl.RegistryAccessRule(
            'BUILTIN\Users', 'ReadKey', $inherit, 'None', 'Allow')))

        $key.SetAccessControl($acl)
        $key.Close()

        <#
            אימות בקריאה חוזרת.

            הכתיבה יכולה להצליח ולא לתפוס. הגנה שלא נתפסה גרועה
            מהיעדר הגנה, כי היא יוצרת ביטחון שאינו קיים — ולכן
            נבדק כאן מה באמת יושב על המפתח.
        #>
        $check = (Get-Acl "HKLM:\SYSTEM\CurrentControlSet\Services\$name")

        $adminsWrite = $check.Access | Where-Object {
            $_.IdentityReference -like '*Administrators' -and
            $_.RegistryRights -band [System.Security.AccessControl.RegistryRights]::SetValue
        }

        if (-not $check.AreAccessRulesProtected -or $adminsWrite) {
            Write-Host "  ! הגנת הרישום של $name לא נתפסה. sc config עדיין אפשרי." `
                -ForegroundColor Yellow
        }

        # והצד השני: הקשחה שחוסמת גם קריאה שוברת את בדיקת המצב במגש
        $usersRead = $check.Access | Where-Object {
            $_.IdentityReference -like '*Users' -and
            $_.AccessControlType -eq 'Allow' -and
            $_.RegistryRights -band [System.Security.AccessControl.RegistryRights]::ReadKey
        }

        if (-not $usersRead) {
            Write-Host "  ! משתמשים רגילים אינם יכולים לקרוא את מפתח $name. בדיקת מצב השירות תיכשל." `
                -ForegroundColor Yellow
        }
    }
    catch {
        Write-Host "  ! הגנת הרישום של $name נכשלה: $($_.Exception.Message)" `
            -ForegroundColor Yellow
    }
}

# ---------------------------------------------------------------- משימת גיבוי

Write-Host "יוצר משימה מתוזמנת כשכבת גיבוי..." -ForegroundColor Cyan

<#
    השכבה השלישית.

    היא איטית — פעם ברבע שעה — ובכוונה: היא לא נועדה להיות ההגנה
    אלא הרשת שמתחתיה, למקרה ששני השירותים נעצרו יחד. היא מפעילה את
    שניהם, כי החזרת אחד מהם מספיקה להחזיר את השני.
#>
$action    = New-ScheduledTaskAction -Execute 'cmd.exe' `
                -Argument "/c sc start $ServiceName & sc start $guardianName"
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
Start-Service -Name $guardianName
Start-Sleep -Seconds 3

$service = Get-Service -Name $ServiceName

if ($service.Status -ne 'Running') {
    throw "השירות לא עלה. בדוק את יומן האירועים תחת המקור SafeMe."
}

# ההתקנה הסתיימה, והשומרים חוזרים לתפקידם מיד ולא בעוד חמש דקות.
try { Remove-Item $markerPath -Force -ErrorAction SilentlyContinue } catch { }

Write-Host ""
Write-Host "ההתקנה הושלמה." -ForegroundColor Green
Write-Host "  שירות : $ServiceName ($($service.Status))"
Write-Host "  נתיב  : $InstallPath"
Write-Host "  שרת   : $ServerUrl"
Write-Host ""
Write-Host "אייקון המגש יעלה אוטומטית תוך כמה שניות בכל סשן משתמש מחובר."

# ---------------------------------------------------------------- המלצות

<#
    שתי ההמלצות האלה אינן קישוט.

    SafeMe מגן על ההתקנה של Windows שהוא רץ בתוכה. שתי הדרכים שהוא
    אינו יכול לסגור בעצמו הן חשבון משתמש עם הרשאות מנהל, ואתחול
    ממערכת הפעלה אחרת — ושתיהן נסגרות בפעולה חד-פעמית של ההורה.

    עדיף שההורה יידע ויחליט, מאשר שיניח שהכול מכוסה.
#>

Write-Host ""
Write-Host "  כדי שההגנה תהיה מלאה:" -ForegroundColor Cyan
Write-Host ""

# בדיקת הרשאות של המשתמשים המקומיים
$adminGroup = (Get-LocalGroup -SID 'S-1-5-32-544' -ErrorAction SilentlyContinue).Name

$localAdmins = @()

if ($adminGroup) {
    $localAdmins = Get-LocalGroupMember -Group $adminGroup -ErrorAction SilentlyContinue |
        Where-Object { $_.ObjectClass -eq 'User' -and $_.PrincipalSource -eq 'Local' } |
        # שני לוכסנים: '\' לבדו הוא ביטוי רגולרי לא חוקי וזורק
        # "Illegal \ at end of pattern". זה קרה אחרי שההתקנה כבר
        # הצליחה, והפיל את קוד היציאה ל-1 — התקנה תקינה שנראתה כשל.
        ForEach-Object { ($_.Name -split '\\')[-1] } |
        Where-Object { $_ -notin @('Administrator', 'DefaultAccount', 'WDAGUtilityAccount') }
}

if ($localAdmins.Count -gt 0) {
    Write-Host "  [!] חשבונות עם הרשאות מנהל: $($localAdmins -join ', ')" -ForegroundColor Yellow
    Write-Host "      מנהל מערכת יכול לעצור את SafeMe. אם זה החשבון שהילד"
    Write-Host "      משתמש בו, מומלץ להפוך אותו למשתמש רגיל:"
    Write-Host "        Settings > Accounts > Family & other users"
} else {
    Write-Host "  [OK] אין חשבונות משתמש עם הרשאות מנהל." -ForegroundColor Green
}

Write-Host ""
Write-Host "  [!] סיסמת BIOS וביטול אתחול מהתקן חיצוני" -ForegroundColor Yellow
Write-Host "      אתחול ממקל USB עם מערכת אחרת עוקף כל תוכנה שרצה"
Write-Host "      ב-Windows, כולל SafeMe. זו פעולה חד-פעמית בהגדרות"
Write-Host "      ה-BIOS, וללא הסתמכות עליה נשארת דלת פתוחה."
Write-Host ""

<#
    קוד יציאה מפורש.

    בלעדיו powershell.exe -File מחזיר את $LASTEXITCODE של הפקודה
    הנייטיבית האחרונה, או 1 אם שגיאה כלשהי התרחשה בדרך. שני המצבים
    האלה אינם אומרים דבר על הצלחת ההתקנה — וכשל בשורת תצוגה הפך
    התקנה מוצלחת ל"נכשלה (קוד 1)".

    כשל אמיתי עוצר קודם, דרך throw, ומחזיר קוד שאינו אפס.
#>
exit 0
