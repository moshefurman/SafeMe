using System.Diagnostics;
using System.Runtime.Versioning;
using System.Security.Cryptography;

using Microsoft.Extensions.Logging;

using SafeMe.Core.Abstractions;
using SafeMe.Core.Models;
using SafeMe.Core.Security;
using SafeMe.Core.Updates;
using SafeMe.Service.State;

namespace SafeMe.Service.Workers;

/// <summary>
/// מחיל עדכון שהשרת הציע.
///
/// זה החלק העדין: התהליך מחליף את הקבצים שהוא עצמו רץ מהם. לכן הוא
/// אינו עושה זאת בעצמו — הוא מפעיל את המתקין החדש כתהליך נפרד,
/// ומת. המתקין עוצר את השירות, מחליף, ומפעיל מחדש.
///
/// מה שנבדק לפני שמריצים משהו:
///
///   החתימה — במפתח העדכונים, שהוא נפרד ממפתח המדיניות. שרת שנפרץ
///             ויכול לחתום מדיניות אינו יכול לחתום עדכון.
///   ההצעה  — למי היא נועדה, מתי פגה, ומה היא מציעה. ראה UpdateGate.
///   הקובץ  — גיבוב מלא אחרי ההורדה, לפני ההרצה.
///
/// שלוש הבדיקות בלתי תלויות. אף אחת מהן לבדה אינה מספיקה, וכל אחת
/// חוסמת תקיפה אחרת.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class UpdateWorker
{
    /// <summary>
    /// מרווח מינימלי בין ניסיונות.
    ///
    /// הצעה חוזרת בכל פעימה היא המצב הרגיל — השרת אינו יודע שכשלנו.
    /// בלי המרווח, כישלון קבוע היה מוריד 60 מגה כל שלוש דקות.
    /// </summary>
    public static readonly TimeSpan RetryAfterFailure = TimeSpan.FromHours(6);

    private readonly ILogger<UpdateWorker> _log;
    private readonly DeviceStateStore _deviceStore;
    private readonly IHardwareIdProvider _hwid;
    private readonly HttpClient _http;

    private DateTimeOffset _nextAttempt = DateTimeOffset.MinValue;
    private string? _lastFailedVersion;

    /// <summary>הורדה פעילה. int ולא bool, כדי ש-Interlocked יוכל לגעת בו.</summary>
    private int _downloading;

    public UpdateWorker(
        ILogger<UpdateWorker> log,
        DeviceStateStore deviceStore,
        IHardwareIdProvider hwid,
        HttpClient http)
    {
        _log = log;
        _deviceStore = deviceStore;
        _hwid = hwid;
        _http = http;
    }

    /// <summary>הגרסה שרצה כרגע, כפי שהיא בקובץ ההרצה.</summary>
    public static string CurrentVersion =>
        typeof(UpdateWorker).Assembly.GetName().Version is { } v
            ? $"{v.Major}.{v.Minor}.{v.Build}"
            : "0.0.0";

    /// <summary>
    /// בודק הצעה, ומשגר הורדה ברקע כשהיא מתקבלת.
    ///
    /// מחזיר true רק כדי לומר שההצעה יצאה לדרך. השירות ייעצר
    /// מאוחר יותר, על ידי המתקין, ולא בחזרה מכאן — ולכן הקורא
    /// אינו אמור להסיק מהערך שהעדכון הושלם.
    ///
    /// אינו אסינכרוני עוד: כל מה שהוא עושה הוא אימות חתימה
    /// והכרעה, ושניהם מקומיים ומיידיים.
    /// </summary>
    public bool TryApply(
        SignedEnvelope? envelope,
        DateTimeOffset now,
        CancellationToken ct)
    {
        if (envelope is null) return false;

        var device = _deviceStore.Load();
        var keyPem = device.UpdatePublicKeyPem;

        if (string.IsNullOrWhiteSpace(keyPem))
        {
            _log.LogWarning("התקבלה הצעת עדכון אך אין מפתח לאמת אותה. ההצעה נדחתה.");

            return false;
        }

        // ---- 1. החתימה ----

        var verified = SignedEnvelopeReader.Verify<UpdateOffer>(envelope, keyPem);

        if (!verified.Ok || verified.Value is null)
        {
            /*
             * חתימה שאינה נאמתת אינה תקלה — היא ניסיון.
             *
             * הצעה תקינה תמיד תיחתם, ולכן כישלון כאן פירושו שמישהו
             * שידר משהו אחר. נרשם ברמת אזהרה כדי שייראה בפורטל.
             */
            _log.LogWarning("חתימת הצעת העדכון אינה תקפה: {Reason}", verified.Message);

            return false;
        }

        var offer = verified.Value;

        /*
         * ---- הנסיגה, וממה בדיוק נסוגים ----
         *
         * הבדיקה ישבה לפני אימות החתימה, ולכן לא ידעה על איזו גרסה
         * היא מדברת — והשתיקה כל ניסיון עדכון לשש שעות. גרסה אחת
         * שבורה הרעילה את הערוץ כולו: 1.1.25 הצביעה לנכס שלא הועלה,
         * חזרה 404, ו-1.1.26 התקינה לגמרי לא נבדקה אפילו פעם אחת.
         *
         * זה נצפה בשטח בדיוק כך — "אני לא רואה שהתוכנה מתעדכנת",
         * בזמן שהגרסה החדשה כבר פורסמה והנכס החזיר 200.
         *
         * _lastFailedVersion נשמר מהיום הראשון ומעולם לא נקרא.
         * הכוונה הייתה ברורה והמימוש חסר, ומה שנשאר היה שדה שנראה
         * כאילו הוא עושה את העבודה.
         *
         * הגנת ההצפה נשמרת, ומכוונת למה שנועדה לו: אותה גרסה שנכשלה
         * אינה מנוסה שוב מיד. כל גרסה אחרת נבדקת כרגיל, וזה מה
         * שמאפשר לתקן שחרור שבור בלי להמתין שש שעות.
         *
         * המחיר הוא אימות חתימה אחד לכל פעימה גם בזמן נסיגה. זו
         * פעולה מקומית וזולה, והיא גם מוסיפה: חתימה פסולה תירשם
         * עכשיו גם בתקופה הזו במקום להיבלע.
         */
        if (now < _nextAttempt &&
            string.Equals(offer.Version, _lastFailedVersion, StringComparison.OrdinalIgnoreCase))
        {
            // שקט בכוונה. ההצעה חוזרת בכל פעימה, ורישום בכל אחת
            // מהן היה מציף את היומן במקום להסביר.
            return false;
        }

        // ---- 2. תוכן ההצעה ----

        var verdict = UpdateGate.Evaluate(offer, CurrentVersion, HwidHash(), now);

        if (!verdict.Accepted)
        {
            /*
             * "אינה חדשה" הוא המצב הרגיל אחרי עדכון מוצלח: השרת
             * ממשיך להציע עד שהפעימה הבאה מדווחת על הגרסה החדשה.
             * שאר הסיבות חריגות ונרשמות ככאלה.
             */
            var level = verdict.Reason == UpdateRejection.NotNewer
                ? LogLevel.Debug
                : LogLevel.Warning;

            _log.Log(level, "הצעת עדכון נדחתה: {Why}", verdict.Explanation);

            return false;
        }

        /*
         * ---- 3. ההורדה, ולא כאן ----
         *
         * ההורדה רצה עד עכשיו בתוך הפעימה, והפעימה חד-חוטית. שישים
         * ואחת מגה מקו סלולרי איטי פירושן שהסוכן יורד מהאוויר לכל
         * משך ההורדה — עד עשרים דקות, לפי פסק הזמן של הלקוח.
         *
         * בזמן הזה הוא אינו מדווח, אינו מרענן מדיניות, ואינו מבצע
         * פקודות מרחוק. פקודת נעילה שנשלחה באותן דקות פשוט אינה
         * מגיעה, וההורה רואה מחשב שהפסיק לדווח בלי לדעת למה.
         *
         * נצפה בשטח: 21:11:34 הדיווח האחרון, ואחריו אחת עשרה דקות
         * של שקט מוחלט מול חיבור פתוח ל-GitHub שטרם החזיר כותרות.
         *
         * ההורדה עוברת למשימת רקע. הפעימה ממשיכה כרגיל, והמתקין
         * יעצור את השירות כשיהיה מוכן — בדיוק כפי שהיה קורה קודם,
         * רק בלי לחנוק את כל השאר בדרך.
         *
         * הדגל מונע הורדות מקבילות: ההצעה חוזרת בכל פעימה, ובלעדיו
         * היינו פותחים הורדה חדשה של שישים מגה כל שלוש דקות.
         */
        if (Interlocked.CompareExchange(ref _downloading, 1, 0) != 0)
        {
            // הורדה כבר רצה. שקט בכוונה — ההצעה חוזרת בכל פעימה.
            return false;
        }

        _log.LogWarning("מתחיל להוריד את גרסה {Version} ברקע. הפעימות ממשיכות.", offer.Version);

        _ = Task.Run(() => DownloadAndLaunchAsync(offer, now, ct), CancellationToken.None);

        /*
         * false, ובכוונה.
         *
         * הערך אומר "המתקין הופעל והשירות עומד להיעצר", וזה עדיין
         * לא נכון. הוא ייאמר ביומן ברגע שזה יקרה באמת.
         */
        return false;
    }

    /// <summary>
    /// מוריד, מאמת, ומפעיל את המתקין. רץ מחוץ ללולאת הפעימה.
    ///
    /// אינו זורק החוצה: זו משימת רקע שאיש אינו ממתין לה, וחריגה
    /// שאינה נתפסת כאן הייתה עולה כשגיאה לא מטופלת בתהליך.
    /// </summary>
    private async Task DownloadAndLaunchAsync(
        UpdateOffer offer,
        DateTimeOffset now,
        CancellationToken ct)
    {
        var target = Path.Combine(
            Path.GetTempPath(),
            $"SafeMe-Update-{offer.Version}-{Guid.NewGuid().ToString("N")[..8]}.exe");

        try
        {
            var outcome = await DownloadAsync(offer, target, ct);

            if (outcome != DownloadOutcome.Ok)
            {
                Backoff(offer.Version, now, transient: outcome == DownloadOutcome.Transient);

                return;
            }

            _log.LogWarning("העדכון אומת. מפעיל את המתקין.");

            if (Launch(target, offer.Version))
                _log.LogWarning("עדכון הוחל. השירות ייעצר על ידי המתקין.");
        }
        catch (OperationCanceledException)
        {
            // כיבוי מסודר של השירות. אין מה לרשום, וננסה שוב בעלייה.
            Cleanup(target);
        }
        catch (Exception ex)
        {
            /*
             * כל חריגה שמגיעה לכאן היא תקלת רשת או קלט/פלט.
             * הפסילות של השחרור — מצב, גודל, גיבוב — חוזרות כ-false
             * ומטופלות למעלה, ולא נזרקות.
             */
            _log.LogError(ex, "העדכון נכשל.");
            Cleanup(target);
            Backoff(offer.Version, now, transient: true);
        }
        finally
        {
            /*
             * הדגל משתחרר גם כשההצלחה מלאה.
             *
             * כשהמתקין הופעל, התהליך הזה עומד להיעצר תוך שניות והדגל
             * חסר משמעות. כשהוא נכשל להיעצר — וזה קרה — הדגל היה
             * נשאר דלוק לנצח, ושום עדכון לא היה נבדק שוב עד הפעלה
             * מחדש. הנסיגה כבר מונעת ניסיון חוזר מיידי.
             */
            Interlocked.Exchange(ref _downloading, 0);
        }
    }

    // ---------------------------------------------------------------- הורדה

    /// <summary>
    /// מה קרה, והאם שווה לנסות שוב בקרוב.
    /// </summary>
    private enum DownloadOutcome
    {
        Ok,

        /// <summary>תקלה שעשויה לחלוף מעצמה: קו שנפל, שרת עמוס.</summary>
        Transient,

        /// <summary>תכונה של השחרור: 404, גודל או גיבוב שאינם תואמים.</summary>
        Permanent
    }

    /// <summary>
    /// מוריד ומאמת, ומנקה אחריו על כל פגם.
    /// </summary>
    private async Task<DownloadOutcome> DownloadAsync(
        UpdateOffer offer, string target, CancellationToken ct)
    {
        using (var response = await _http.GetAsync(
            offer.DownloadUrl, HttpCompletionOption.ResponseHeadersRead, ct))
        {
            if (!response.IsSuccessStatusCode)
            {
                var status = (int)response.StatusCode;

                /*
                 * חמש מאות הוא השרת שממנו מורידים, לא השחרור.
                 * גם 429 — הוא בקשה מפורשת לחזור מאוחר יותר.
                 */
                var transient = status >= 500 || status == 429;

                _log.LogWarning("הורדת העדכון נכשלה: {Status}", status);

                return transient ? DownloadOutcome.Transient : DownloadOutcome.Permanent;
            }

            /*
             * הגודל נבדק גם תוך כדי, ולא רק בכותרת.
             *
             * Content-Length הוא הצהרה של השרת שממנו מורידים, והוא
             * יכול פשוט לשקר או להיעדר. בלי התקרה בזמן הכתיבה,
             * תשובה בלתי נגמרת הייתה ממלאת את הדיסק.
             */
            using var source = await response.Content.ReadAsStreamAsync(ct);
            using var file = File.Create(target);

            var buffer = new byte[81920];
            long written = 0;

            while (true)
            {
                var read = await source.ReadAsync(buffer, ct);

                if (read == 0) break;

                written += read;

                if (written > offer.SizeBytes)
                {
                    _log.LogWarning("הקובץ גדול מהמוצהר. ההורדה נעצרה.");

                    return DownloadOutcome.Permanent;
                }

                await file.WriteAsync(buffer.AsMemory(0, read), ct);
            }

            if (written != offer.SizeBytes)
            {
                _log.LogWarning(
                    "גודל שאינו תואם: {Actual} במקום {Expected}.", written, offer.SizeBytes);

                /*
                 * זה דו משמעי — גם הצהרה שגויה וגם הורדה שנקטעה
                 * בשקט נראים כאן אותו דבר. פחות מהמוצהר הוא כמעט
                 * תמיד קו שנפל, ולכן נסיגה קצרה.
                 */
                return written < offer.SizeBytes
                    ? DownloadOutcome.Transient
                    : DownloadOutcome.Permanent;
            }
        }

        // ---- הגיבוב ----
        //
        // אחרי שהקובץ נסגר, ועל התוכן שנשמר בפועל. חישוב על הזרם
        // תוך כדי הורדה היה מאמת את מה שעבר ברשת ולא את מה שנכתב.
        var actual = await ComputeSha256Async(target, ct);

        if (!string.Equals(actual, offer.Sha256, StringComparison.OrdinalIgnoreCase))
        {
            _log.LogError(
                "גיבוב שאינו תואם. צפוי {Expected}, התקבל {Actual}.", offer.Sha256, actual);

            Cleanup(target);

            /*
             * הגודל תאם והתוכן לא. זה אינו קו שנפל — זה
             * קובץ אחר, וניסיון חוזר יקבל אותו קובץ בדיוק.
             */
            return DownloadOutcome.Permanent;
        }

        return DownloadOutcome.Ok;
    }

    private static async Task<string> ComputeSha256Async(string path, CancellationToken ct)
    {
        await using var stream = File.OpenRead(path);

        var hash = await SHA256.HashDataAsync(stream, ct);

        return Convert.ToHexString(hash).ToLowerInvariant();
    }

    // ---------------------------------------------------------------- הרצה

    /// <summary>
    /// מפעיל את המתקין ומחזיר את השליטה.
    ///
    /// ‎--quiet כי אין כאן משתמש שמסתכל: זה עדכון שקורה ברקע, ולא
    /// התקנה שמישהו יזם. המתקין יעצור את השירות הזה, יחליף את
    /// הקבצים, ויפעיל מחדש.
    ///
    /// UseShellExecute=false במכוון, ולא רק בשביל CreateNoWindow.
    /// הוא מוליך ל-CreateProcess, שאינו מפעיל את מתווך ההסלמה של
    /// Windows: התהליך יורש את האסימון של השירות. עם UseShellExecute
    /// היה נפתח דיאלוג UAC — על שולחן עבודה שאיש אינו רואה, כי
    /// שירות יושב ב-session 0 — והעדכון היה תלוי לנצח.
    ///
    /// אין המתנה לסיום, ובמכוון: המתקין הורג את התהליך שממתין לו.
    /// </summary>
    private bool Launch(string installer, string version)
    {
        var info = new ProcessStartInfo
        {
            FileName = installer,
            UseShellExecute = false,
            CreateNoWindow = true,
        };

        info.ArgumentList.Add("--quiet");

        try
        {
            var process = Process.Start(info);

            if (process is null)
            {
                _log.LogError("הפעלת המתקין נכשלה.");
                Cleanup(installer);

                return false;
            }

            _log.LogWarning(
                "מתקין גרסה {Version} הופעל (תהליך {Pid}). השירות ייעצר בקרוב.",
                version, process.Id);

            return true;
        }
        catch (System.ComponentModel.Win32Exception ex) when (ex.NativeErrorCode == 740)
        {
            /*
             * ERROR_ELEVATION_REQUIRED.
             *
             * המתקין דורש הרשאות מנהל, ולמי שמפעיל אותו אין. זה אינו
             * אמור לקרות — השירות רץ כ-LocalSystem, ותהליך שנוצר ממנו
             * יורש את האסימון — אבל אם חשבון השירות ישונה אי־פעם, זו
             * בדיוק הצורה שהכשל יקבל: העדכון פשוט לא קורה.
             *
             * הודעה נפרדת כי הסיבה כאן ניתנת לתיקון, וההודעה הכללית
             * לא הייתה מרמזת עליה.
             */
            _log.LogError(
                ex,
                "המתקין דורש הרשאות מנהל והשירות אינו מריץ בהן. "
                + "עדכונים לא יוחלו עד שחשבון השירות יוחזר ל-LocalSystem.");

            Cleanup(installer);

            return false;
        }
        catch (Exception ex)
        {
            _log.LogError(ex, "הפעלת המתקין נכשלה.");
            Cleanup(installer);

            return false;
        }
    }

    // ---------------------------------------------------------------- עזר

    /*
     * שתי נסיגות, כי יש שני סוגי כישלון.
     *
     * קו שנופל באמצע הורדה אינו אומר דבר על הגרסה. הוא
     * אומר שמישהו על קו סלולרי ניסה למשוך שישים ואחת מגה
     * ברצף אחד. שש שעות שקט אחרי דבר כזה הן עונש על גיבוב
     * ברשת, ועל קו חלש הן עלולות למנוע עדכון לצמיתות:
     * כל ניסיון נשבר, ובין ניסיון לניסיון עובר רבע יום.
     *
     * נצפה בשטח: IOException אחרי שלוש עשרה דקות ממודם סלולרי,
     * ומיד אחריו נסיגה עד שלוש לפנות בוקר — על גרסה תקינה
     * לגמרי שהנכס שלה מחזיר 200.
     *
     * לעומת זאת 404, גודל שאינו תואם או גיבוב שאינו תואם הם
     * תכונה של השחרור עצמו. הם לא ישתנו בעוד חמש דקות,
     * ושם המתנה ארוכה היא התשובה הנכונה.
     */
    public static readonly TimeSpan RetryAfterTransient = TimeSpan.FromMinutes(5);

    private void Backoff(string version, DateTimeOffset now, bool transient = false)
    {
        _lastFailedVersion = version;
        _nextAttempt = now + (transient ? RetryAfterTransient : RetryAfterFailure);

        _log.LogWarning(
            "העדכון ל-{Version} ייבדק שוב לא לפני {When}. {Kind}",
            version, _nextAttempt, transient ? "(תקלת רשת זמנית)" : "(כשל בשחרור עצמו)");
    }

    /// <summary>
    /// גיבוב מזהה החומרה, בדיוק כפי שהשרת מחשב אותו.
    ///
    /// היה כאן חישוב משלו, ושלושה דברים בו נבדלו מהשרת: הקלט לא
    /// נורמל לאותיות גדולות, נלקח הגיבוב המלא במקום שמונת הבתים
    /// הראשונים, וההקסה יצאה באותיות קטנות.
    ///
    /// התוצאה הייתה שכל הצעת עדכון נדחתה כ"נועדה למחשב אחר" —
    /// כלומר המנגנון נראה עובד לגמרי, דיווח סיבה שנשמעת הגיונית,
    /// ומעולם לא עדכן דבר. שני מימושים של אותו חישוב נפרדים בשקט,
    /// וזו בדיוק הסיבה שהחישוב הזה יושב במקום אחד.
    /// </summary>
    private string HwidHash() =>
        Convert.ToHexString(UninstallChallenge.ComputeHwidHash(_hwid.GetHardwareId()));

    private void Cleanup(string path)
    {
        try
        {
            if (File.Exists(path)) File.Delete(path);
        }
        catch (IOException)
        {
            // קובץ נעול. יימחק בניקוי הבא של המערכת.
        }
        catch (UnauthorizedAccessException)
        {
        }
    }

    /// <summary>הגרסה שניסיון העדכון אליה נכשל לאחרונה. לאבחון.</summary>
    public string? LastFailedVersion => _lastFailedVersion;
}
