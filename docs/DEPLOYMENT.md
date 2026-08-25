# SafeMe — מדריך בנייה, התקנה ובדיקה

---

## 1. דרישות סביבה

| רכיב | דרישה |
|---|---|
| מערכת הפעלה | Windows 10 1809+ / Windows 11 / Server 2019+ (x64) |
| SDK | .NET 9 SDK |
| שירות מערכת | `BFE` (Base Filtering Engine) חייב לרוץ |
| הרשאות | התקנה והרצה דורשות הרשאות מנהל |
| חתימת קוד | לא נדרשת לפיתוח. לייצור נדרשת תעודת Code Signing |

---

## 2. בנייה מקומית

```powershell
# מתיקיית השורש של הפתרון
dotnet restore SafeMe.sln
dotnet build   SafeMe.sln -c Release
dotnet test    tests\SafeMe.Tests\SafeMe.Tests.csproj
```

### 2.1 פרסום (Publish)

```powershell
dotnet publish src\SafeMe.Service\SafeMe.Service.csproj        -c Release -r win-x64 --self-contained false -o artifacts
dotnet publish src\SafeMe.TrayApp\SafeMe.TrayApp.csproj        -c Release -r win-x64 --self-contained false -o artifacts
dotnet publish src\SafeMe.Uninstaller\SafeMe.Uninstaller.csproj -c Release -r win-x64 --self-contained false -o artifacts
```

שלושת הרכיבים מתפרסמים לאותה תיקייה בכוונה: ה‑Watchdog מחפש את
`SafeMe.TrayApp.exe` לצד `SafeMe.Service.exe`.

---

## 3. הנפקת מפתחות השרת

לפני התקנה ראשונה יש להנפיק זוג מפתחות. **המפתח הפרטי נשאר בשרת בלבד.**

```powershell
dotnet run --project tools\SafeMe.CodeGen -- keygen --out safeme-server
# safeme-server-private.pem  ← שרת בלבד
# safeme-server-public.pem   ← נשלח למכשירים בעת הרישום
```

בדיקת שפיות מלאה של מנגנון האתגר/תגובה, ללא צורך בהתקנה:

```powershell
dotnet run --project tools\SafeMe.CodeGen -- demo
```

הפלט מדגים: הפקת אתגר, חתימה, אימות מוצלח, דחיית קוד מזויף, ודחייה לאחר פקיעת תוקף.

---

## 4. התקנה

```powershell
# PowerShell כמנהל מערכת
.\deploy\install.ps1 -ServerUrl "https://api.safeme.io" -LicenseKey "SAFE-1234-5678-9012"
```

הסקריפט מבצע:

1. וידוא ש‑`BFE` רץ (ומפעיל אותו אם צריך)
2. בנייה ופרסום
3. העתקה ל‑`C:\Program Files\SafeMe`
4. עדכון `appsettings.json` בכתובת השרת ובמפתח הרישיון
5. הקשחת ACL — `SYSTEM:F`, `Administrators:F`, `Users:RX`
6. רישום השירות `SafeMeAgent` כ‑`LocalSystem`, הפעלה אוטומטית
7. פעולות התאוששות: `restart/5000, restart/5000, restart/10000`, ללא איפוס מונה
8. רישום ב‑`SafeBoot\Minimal` וב‑`SafeBoot\Network`
9. משימה מתוזמנת `\SafeMe\Guardian` כל 15 דקות
10. הפעלת השירות

### 4.1 רישום ידני של השירות

```powershell
sc.exe create SafeMeAgent binPath= "\"C:\Program Files\SafeMe\SafeMe.Service.exe\"" start= auto obj= "LocalSystem" DisplayName= "SafeMe Agent"
sc.exe description SafeMeAgent "סוכן SafeMe"
sc.exe failure SafeMeAgent reset= 0 actions= restart/5000/restart/5000/restart/10000
sc.exe failureflag SafeMeAgent 1
sc.exe start SafeMeAgent
```

### 4.2 הרצה במצב קונסולה (פיתוח)

```powershell
# מחלון מורם. ללא הרשאות מנהל, WFP ייכשל באתחול.
dotnet run --project src\SafeMe.Service
```

בהרצה כתהליך רגיל ה‑Host מזהה שאינו שירות ומריץ בקונסולה. ה‑IPC,
הביקורת וה‑Watchdog פועלים כרגיל.

---

## 5. אימות ההתקנה

### 5.1 סטטוס בסיסי

```powershell
Get-Service SafeMeAgent
Get-Process SafeMe.TrayApp -ErrorAction SilentlyContinue
Get-ChildItem "$env:ProgramData\SafeMe\logs" | Select-Object -Last 1
```

### 5.2 בדיקת ערוץ ה‑IPC

```powershell
[System.IO.Directory]::GetFiles("\\.\pipe\") | Where-Object { $_ -match 'SafeMe' }
```

תוצאה צפויה: `\\.\pipe\SafeMe.Agent.v1`

### 5.3 בדיקת חוקי WFP

```powershell
# ייצוא מצב המסנן הנוכחי
netsh wfp show filters file="$env:TEMP\wfp.xml"
Select-String -Path "$env:TEMP\wfp.xml" -Pattern "SafeMe" | Select-Object -First 20
```

בזמן נעילה פעילה יופיעו חוקים בשמות `SafeMe - חסימת כל היוצא IPv4`,
`SafeMe - היתר ...` וכד', כולם תחת ה‑SubLayer `SafeMe Enforcement`.

> **שים לב:** חוקי SafeMe **לא** יופיעו ב‑`wf.msc`. הם יושבים ב‑SubLayer
> ייעודי שהממשק הגרפי של חומת האש אינו מציג. זו התנהגות מכוונת.

### 5.4 בדיקת נעילת חירום מקצה לקצה

בסביבת מעבדה (מומלץ במכונה וירטואלית עם snapshot):

1. הגדירו במדיניות `enforcement.mode = "enforce"` ו‑`onRedAction = "lockout"`.
2. נתקו את המכשיר מהחיבור המסונן.
3. תוך עד מחזור ביקורת אחד (ברירת מחדל 15 דקות, או `בדוק עכשיו` מהמגש)
   הסטטוס יהפוך לאדום והנעילה תיכנס לתוקף.
4. אמתו: גלישה כללית חסומה, אך `api.safeme.io` עדיין נגיש.
5. שחררו: `RunAudit` לאחר חזרה לחיבור מסונן, או פקודת `ReleaseLockout` מהשרת.

### 5.5 בדיקת ה‑Watchdog הכפול

```powershell
# הריגת אייקון המגש - אמור לחזור תוך עד 5 שניות
Stop-Process -Name SafeMe.TrayApp -Force
Start-Sleep 8; Get-Process SafeMe.TrayApp

# הריגת השירות - SCM אמור להחזירו תוך 5 שניות
Stop-Process -Id (Get-CimInstance Win32_Service -Filter "Name='SafeMeAgent'").ProcessId -Force
Start-Sleep 10; Get-Service SafeMeAgent
```

יעד: התאוששות של שני הרכיבים בתוך פחות מ‑10 שניות.

---

## 6. תהליך ההסרה

### 6.1 מהלך רגיל

```powershell
.\deploy\uninstall.ps1
```

הסקריפט בודק אם קיים אישור הסרה בתוקף. אם לא — הוא פותח את מסך ההסרה
ומסיים **בלי להסיר דבר**.

במסך ההסרה:

1. לחצו **הפק קוד אתגר** — מתקבל קוד בן 36 תווים בשש קבוצות.
2. מסרו אותו לנציג המוקד.
3. הנציג מייצר קוד תגובה:
   ```powershell
   dotnet run --project tools\SafeMe.CodeGen -- inspect --challenge "K7M2QX-4BNP9L-..."
   dotnet run --project tools\SafeMe.CodeGen -- respond --challenge "K7M2QX-4BNP9L-..." --key safeme-server-private.pem
   ```
4. הדביקו את קוד התגובה ולחצו **אמת והסר**.
5. השירות מאמת, מפרק את חוקי ה‑WFP, וכותב אסימון לרג'יסטרי.
6. הריצו שוב את `uninstall.ps1` — הפעם ההסרה מתבצעת.

### 6.2 מגבלות מכוונות

| מגבלה | ערך |
|---|---|
| תוקף אתגר | 30 דקות (+5 דקות סבילות שעון) |
| ניסיונות לפני נעילה | 3 |
| נעילה ראשונה | 15 דקות |
| הסלמה | הכפלה בכל נעילה, עד 4 שעות |
| תוקף אישור ההסרה | שעה אחת |
| שימוש חוזר באתגר | חסום (Nonce חד‑פעמי) |
| הזזת שעון אחורה | אינה מקצרת נעילה |

### 6.3 הסרת חירום

```powershell
.\deploy\uninstall.ps1 -Force
```

לצוות תמיכה בלבד. הפעולה נרשמת ביומן האירועים תחת המקור `SafeMe`, מזהה 9001.

---

## 7. תצורה

`C:\Program Files\SafeMe\appsettings.json`

```jsonc
{
  "Server": {
    "BaseUrl": "https://api.safeme.io",
    "AlwaysAllowHosts": [ "api.safeme.io" ],
    "PinnedSpkiSha256": [],
    "HeartbeatSeconds": 180,
    "AuditMinutes": 15,
    "LicenseKey": null
  }
}
```

לטעינת מדיניות לבדיקה ללא שרת, העתיקו את `deploy\sample-policy.json` אל
`C:\Program Files\SafeMe\...` ואז אל `%ProgramData%\SafeMe\state\policy.json`,
והפעילו את השירות מחדש. כשאין `serverPublicKeyPem` מוגדר, אימות החתימה
מדולג ונרשמת אזהרה — מצב פיתוח בלבד.

---

## 8. יומנים ואבחון

| מקור | מיקום |
|---|---|
| יומן אירועים | Event Viewer ← Application ← מקור `SafeMe` |
| קבצי לוג | `%ProgramData%\SafeMe\logs\` |
| מצב מכשיר | `%ProgramData%\SafeMe\state\device.dat` (מוצפן DPAPI) |
| מדיניות פעילה | `%ProgramData%\SafeMe\state\policy.json` |
| תור אירועים | `%ProgramData%\SafeMe\queue\events.ndjson` |

### 8.1 תקלות נפוצות

| תסמין | סיבה סבירה | פתרון |
|---|---|---|
| `פתיחת מנוע WFP נכשלה. קוד 0x80320003` | השירות אינו רץ כ‑SYSTEM | ודאו `obj= "LocalSystem"` ברישום |
| השירות עולה ונופל מיד | `BFE` מושבת | `Start-Service BFE` והפעילו מחדש |
| אייקון המגש לא מופיע | הפעלה בסשן נכשלה | בדקו לוג `SessionLauncher`; ב‑Server ודאו סשן אינטראקטיבי |
| `הפעולה דורשת הרשאות מנהל` | המסך לא הורם | הפעילו את `SafeMe.Uninstaller.exe` דרך "הפעל כמנהל" |
| ציון 0 והכול "לא הוכרע" | אין קישוריות לכתובות הבדיקה | בדקו `Server.BaseUrl` וכתובות הגששים במדיניות |
| `חתימת המדיניות אינה תקפה` | חוסר התאמה בין השרת ללקוח | ודאו שהשרת חותם על ה‑JSON הקנוני **ללא** שדה `signature` |

---

## 9. מה נדרש לפני ייצור

הפריטים הבאים חורגים מהיקף מימוש הסוכן ויש להשלימם לפני פריסה רחבה:

1. **חתימת קוד** — Authenticode על שלושת קבצי ההרצה. בלעדיה
   `SERVICE_LAUNCH_PROTECTED_WINDOWS_LIGHT` אינו זמין.
2. **חבילת MSI** (WiX) — עם `CustomAction` שקורא את אסימון ההסרה מהרג'יסטרי
   ומבטל את ההסרה אם אינו קיים או פג תוקפו.
3. **שרת הניהול** — מימוש נקודות הקצה שבסעיף 4 של מסמך הארכיטקטורה,
   כולל חתימת מדיניות ו‑Dead Man's Switch.
4. **Certificate Pinning** — מילוי `PinnedSpkiSha256` וחיבורו למטפל ה‑HTTP
   של לקוח השרת.
5. **בדיקות שדה** מול כל ספק סינון נתמך, למילוי טביעות האצבע ותבניות ה‑DNS
   האמיתיות ב‑`sample-policy.json`.
