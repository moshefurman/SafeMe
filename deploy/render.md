# פריסת שרת SafeMe ב-Render

`render.yaml` שבשורש מגדיר את הכול חוץ משני דברים שאי אפשר להצהיר
עליהם בקובץ: יצירת משתמש האפליקציה, והמפתח ב-KMS.

## 1. יצירת הסביבה

ב-Render, `New → Blueprint`, ולבחור את הריפו. הבלופרינט יוצר שני
שירותים ובסיס נתונים אחד: `safeme-api` (Docker, פרנקפורט),
`safeme-portal` (אתר סטטי על ה-CDN), ו-`safeme-db` (פרנקפורט).

הפריסה הראשונה **תיכשל**, וזה צפוי: `DATABASE_URL_APP` עדיין ריק.

## 2. הרצת המיגרציות

מ-Shell של השירות:

```sh
node scripts/migrate.ts
```

## 3. יצירת משתמש האפליקציה

זהו הצעד שאי אפשר לאוטומט, והוא היחיד שבו בידוד הדיירים נקבע.

השרת מתחבר כ-`safeme_app`, ולא כבעל הסכמה. זה מכוון: RLS ב-Postgres
**אינו חל על בעל הטבלה**. אם השרת יתחבר כבעל הסכמה, כל מדיניות
הבידוד תהפוך לקישוט, וכל דייר יראה את הנתונים של כולם — בלי שום
שגיאה שתסגיר את זה. הקוד מאמת את זה בעלייה ומסרב לרוץ אחרת.

מ-psql של בסיס הנתונים:

```sql
ALTER ROLE safeme_app WITH LOGIN PASSWORD '<סיסמה אקראית ארוכה>';
```

ואז להגדיר ב-Render את `DATABASE_URL_APP` לאותו חיבור, עם
`safeme_app` כמשתמש. משתמשים באותו מארח פנימי כמו `DATABASE_URL`.

## 4. מפתח החתימה ב-AWS KMS

זהו תנאי לעלייה, לא שיפור לעתיד. `SIGNER=local` חסום כשה-NODE_ENV
הוא production, ובלי מפתח KMS השרת פשוט לא יעלה.

### יצירת המפתח

```sh
aws kms create-key   --key-spec RSA_2048   --key-usage SIGN_VERIFY   --description "SafeMe policy signing"

aws kms create-alias   --alias-name alias/safeme-policy   --target-key-id <KeyId>
```

`RSA_2048` ו-`SIGN_VERIFY` אינם ניתנים לשינוי אחרי היצירה, והקוד
מאמת את שניהם בעלייה. מפתח שגוי היה מייצר חתימות שכל מחשב בשטח
דוחה — תקלה שחייבת להתגלות לפני הפריסה ולא בהפצת המדיניות הראשונה.

### חלופה: Google Cloud KMS

זהה בתפקוד, ולרוב פשוט יותר להתחלה — ההרשמה היא כניסה עם חשבון
Google קיים. גם זול יותר: כ-0.06 דולר לחודש למפתח מול כ-1 דולר
ב-AWS.

```sh
gcloud kms keyrings create safeme --location europe-west3

gcloud kms keys create safeme-policy   --keyring safeme --location europe-west3   --purpose asymmetric-signing   --default-algorithm rsa-sign-pss-2048-sha256

gcloud kms keys create safeme-loosening   --keyring safeme --location europe-west3   --purpose asymmetric-signing   --default-algorithm rsa-sign-pss-2048-sha256

gcloud kms keys create safeme-uninstall   --keyring safeme --location europe-west3   --purpose asymmetric-signing   --default-algorithm rsa-sign-pss-2048-sha256

gcloud kms keys create safeme-update   --keyring safeme --location europe-west3   --purpose asymmetric-signing   --default-algorithm rsa-sign-pss-2048-sha256
```

**המזהה חייב להצביע על גרסת מפתח, לא על המפתח.** זו הטעות השכיחה,
והקוד דוחה אותה בעלייה:

```
projects/<פרויקט>/locations/europe-west3/keyRings/safeme/cryptoKeys/safeme-policy/cryptoKeyVersions/1
```

הרשאה נדרשת: `roles/cloudkms.signerVerifier` על שני המפתחות. היא
כוללת חתימה ושליפת מפתח ציבורי, ולא יצירה או מחיקה.

האימות מול Render נעשה בקובץ JSON של חשבון שירות, דרך המשתנה
`GOOGLE_APPLICATION_CREDENTIALS_JSON` או `GOOGLE_APPLICATION_CREDENTIALS`.

| משתנה | ערך |
|---|---|
| `SIGNER` | `gcp` |
| `SIGNER_KMS_KEY_ID` | הנתיב המלא כולל `/cryptoKeyVersions/1` |
| `SIGNER_LOOSENING_KMS_KEY_ID` | אותו דבר, למפתח ההיתרים |
| `SIGNER_UNINSTALL_KMS_KEY_ID` | אותו דבר, למפתח ההסרה |
| `SIGNER_UPDATE_KMS_KEY_ID` | אותו דבר, למפתח העדכונים |
| `SIGNER_KID` · `SIGNER_LOOSENING_KID` · `SIGNER_UNINSTALL_KID` · `SIGNER_UPDATE_KID` | מזהים קצרים שאתה ממציא. **חייבים להיות שונים זה מזה** — הסוכן בוחר מפתח אימות לפי ה-kid |

GCP מחזיר את המפתח הציבורי כ-PEM ישירות, ומספק סיכום ביקורת
דו-כיווני על הגיבוב ועל החתימה. הקוד מאמת את שניהם וזורק את החתימה
אם אחד מהם אינו תואם — חתימה על גיבוב שהשתבש בדרך תיראה תקינה
לחלוטין במחשב, והיא פשוט תהיה חתימה על משהו אחר.

### הרשאות

למשתמש או לתפקיד שהשרת פועל בשמו דרושות שתי פעולות בלבד:

```
kms:Sign
kms:GetPublicKey
```

לא `kms:CreateKey`, לא `kms:ScheduleKeyDeletion`. שרת שנפרץ יוכל
לבקש חתימות בזמן הפריצה, אך לא לגנוב את המפתח ולא למחוק אותו.

### משתני הסביבה ב-Render

| משתנה | ערך |
|---|---|
| `SIGNER` | `aws` |
| `SIGNER_KMS_KEY_ID` | ה-ARN או `alias/safeme-policy` |
| `SIGNER_KID` | מזהה קצר, למשל `policy-2026-01` |
| `SIGNER_LOOSENING_KMS_KEY_ID` | ה-ARN או `alias/safeme-loosening` |
| `SIGNER_LOOSENING_KID` | למשל `loosening-2026-01` |
| `SIGNER_UNINSTALL_KMS_KEY_ID` | ה-ARN או `alias/safeme-uninstall` |
| `SIGNER_UNINSTALL_KID` | למשל `uninstall-2026-01` |
| `AWS_REGION` | האזור שבו נוצר המפתח |
| `AWS_ACCESS_KEY_ID` | של משתמש עם שתי ההרשאות בלבד |
| `AWS_SECRET_ACCESS_KEY` | |

### הודעות

| משתנה | ערך |
|---|---|
| `MAIL_PROVIDER` | `none` · `console` · `resend` |
| `PORTAL_URL` | כתובת מרכז הניהול, מופיעה בגוף ההודעה |

ברירת המחדל היא `none`, ולא נשלח דבר. זו התנהגות מודעת ולא תקלה:
ההתראה נרשמת בפורטל בכל מקרה, וההודעה רק מקצרת את הזמן עד שההורה
יידע.

`resend` נכשל במפורש עד שיוגדר ספק. הודעה שלא נשלחה בלי שאיש יידע
גרועה מכישלון גלוי, כי היא יוצרת ביטחון שאינו קיים.

`SIGNER_KID` נרשם בטבלת `signing_keys` בעלייה הראשונה יחד עם המפתח
הציבורי. **אל תשנה אותו** בלי להחליף מפתח: הסוכן בוחר מפתח אימות
לפי ה-kid שבמעטפה.

### ארבעה מפתחות, ארבע סמכויות

כל מפתח הוא סמכות אחת, וההפרדה מונעת ממי שהשיג אחת לקבל גם את
האחרות.

| מפתח | מה הוא מאשר |
|---|---|
| `safeme-policy` | "זו המדיניות הרשמית" |
| `safeme-loosening` | "מחשב זה רשאי לרדת מתחת לרצפה" |
| `safeme-uninstall` | "מחשב זה רשאי להיות מוסר" |
| `safeme-update` | "הורד את הקוד הזה והרץ אותו כ-SYSTEM" |

ההפרדה נאכפת בשלוש שכבות, ולכל אחת יש מה שרק היא תופסת:

| שכבה | מה נבדק | מה זה תופס |
|---|---|---|
| `config.ts` | כל שלושת המזהים שונים | הטעות המפורשת — אותו ARN בשני שדות |
| `buildApp` | שלושת המפתחות הציבוריים שונים | **שני כינויים שמצביעים לאותו מפתח.** המזהים שונים, ההפרדה אינה קיימת |
| הסוכן | ההיתר או קוד ההסרה לא נחתמו במפתח המדיניות | שרת שנפרץ, או שרת מזויף שהמחשב הופנה אליו, ששולח את אותו מפתח בכל השדות |

השכבה השלישית היא הקריטית: הסוכן אינו סומך על כך שהשרת אכף. את
שלושת המפתחות הוא מקבל ברישום ושומר בנפרד, ומסרב לכל פעולה שנחתמה
במפתח הלא נכון.

הבדיקה ב-buildApp רצה **לפני** רישום המפתחות, כדי שתצורה שגויה לא
תשאיר מפתח רשום למחצה.

### Azure

`SIGNER=azure` נכשל במפורש. המנשק פתוח — `Signer` עם `sign` ו-
`publicKeyPem` — וכל מימוש חייב RSA-2048, PSS, SHA-256, salt באורך
הגיבוב. סטייה כלשהי פוסלת כל מדיניות בשטח.

## 5. בדיקה

```sh
curl https://<השירות>.onrender.com/api/v1/health
```

## 6. כתובת ה-API בפורטל

הפורטל מוגש ממקור נפרד מה-API, ולכן `render.yaml` מגדיר לו כלל
`rewrite` שמעביר `/api/*` אל `safeme-api`. זה תנאי ולא נוחות:
עוגיית ההפעלה היא `HttpOnly` עם `SameSite=Strict` ובלי `Domain`,
והפורטל שולח `credentials: "same-origin"`. מול מקור אחר העוגייה
לא נשלחת כלל, והכניסה נכשלת בלי שגיאה שמסבירה למה.

הכלל מצביע על `https://safeme-api.onrender.com`. **יש לוודא שזו
הכתובת שהשירות קיבל בפועל** — Render מוסיף סיומת אקראית כששם
השירות תפוס, ואז הכתובת שונה. בדיקה:

```sh
curl -i https://<הפורטל>.onrender.com/api/v1/health
```

תשובת 200 מהכלל הזה מאשרת שהשרשור עובד. 404 מ-CDN סטטי אומרת
שהכתובת ביעד שגויה.

## מה לא נמצא כאן

- **Redis** — אין. המשימות המתוזמנות רצות בתוך ה-API עם
  `pg_advisory_lock`, כי בהיקף הזה תור נפרד הוא תשתית מיותרת

## התקנה ללא חשבון — חסימה מוחלטת

מחשב שנחסם כך אינו מדבר עם שום שרת, וההסרה היחידה היא קוד מהמוקד
שנוצר מול מזהה החומרה שלו. לכן המפתח הציבורי שמאמת את הקוד חייב
להיות מוטבע במתקין כבר בשלב האריזה — במסלול הרגיל הוא מגיע מהשרת
בתשובת הרישום, וכאן אין רישום.

```powershell
cd server
node scripts/export-uninstall-key.ts --out ..\uninstall.pem
cd ..
.\build\pack.ps1 -Version 1.1.0 -UninstallKeyPem .\uninstall.pem
```

`--out` ולא `>`. ב-PowerShell 5.1 האופרטור `>` כותב UTF-16LE, והקובץ
נראה תקין בעורך אך נקרא כזבל בכל כלי שמצפה ל-UTF-8.

האריזה מדווחת מה קרה:

| הודעה | משמעות |
|---|---|
| `מפתח ההסרה הוטבע (294 בתים)` | התקנה ללא חשבון אפשרית |
| `ללא מפתח הסרה מוטבע` | המתקין תקין, אך יסרב לחסום מחשב |

הסירוב מכוון. `install.ps1` בודק את המפתח לפני שהוא נוגע במחשב,
כי חסימה בלי מפתח היא לצמיתות — לא מהמוקד, לא בתשלום, ולא בכלל.

המפתח ציבורי, ולכן הטבעתו אינה חושפת דבר. מה שחותם נשאר ב-KMS.

## כללי ה-Rewrite בפורטל

שלושה כללים, **והסדר הוא חלק מההגדרה**. הכלל הראשון שמתאים הוא זה
שרץ, ולכן `/*` חייב להיות אחרון — הוא תופס הכול, וכל כלל שיבוא
אחריו מת.

| # | Source | Destination | למה |
|---|---|---|---|
| 1 | `/api/*` | `https://safeme-h7h4.onrender.com/api/*` | מקור אחד לדפדפן, אחרת עוגיית ההפעלה אינה נשלחת |
| 2 | `/d/*` | `https://safeme-h7h4.onrender.com/d/*` | ההורדות הן מסלול שרת ולא נתיב בפורטל |
| 3 | `/*` | `/index.html` | רענון של כתובת שאינה השורש |

בלי כלל 2, קישור ההורדה מחזיר את דף ה-HTML: הוא נראה תקין, נלחץ,
ולא קורה כלום. זה חל גם על ההורדה לחסימה וגם על קישורי ההורדה
היחסיים עם אסימון.

## מנהל פלטפורמה

ניהול ספקי הסינון — הכללים שקובעים מה נחשב חיבור מסונן — פתוח
ל-`platform_admin` בלבד. דייר שיכול להגדיר זאת יכול לאשר לעצמו כל
חיבור, ובכך לבטל את המוצר מבפנים.

חשבון שנפתח בהרשמה רגילה הוא `tenant_owner`, ואי אפשר לקדם אותו:
תפקיד פלטפורמה מחייב חשבון בלי דייר. יש ליצור חשבון נפרד.

```powershell
cd server
node scripts/create-admin.ts --email you@example.com
```

הסיסמה מוצגת פעם אחת ואינה נשמרת. בכניסה הראשונה הפורטל ידרוש
רישום אימות דו-שלבי — עד אז החשבון במצב `invited` ואינו פעיל.

זה אינו מכשול טכני אלא אילוץ בסכימה: `users_platform_requires_mfa`
אינו מתיר חשבון פלטפורמה **פעיל** בלי אימות שני, ולכן אין רגע שבו
קיים חשבון כזה בלי הגנה.

אחרי הכניסה תופיע לשונית **ספקי סינון**.
