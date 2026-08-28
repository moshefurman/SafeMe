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
    /// בודק הצעה ומחיל אותה. מחזיר true אם המתקין הופעל.
    ///
    /// כשהוא מחזיר true, התהליך הזה עומד להיסגר על ידי המתקין.
    /// </summary>
    public async Task<bool> TryApplyAsync(
        SignedEnvelope? envelope,
        DateTimeOffset now,
        CancellationToken ct)
    {
        if (envelope is null) return false;

        if (now < _nextAttempt)
        {
            // שקט בכוונה. ההצעה חוזרת בכל פעימה, ורישום בכל אחת
            // מהן היה מציף את היומן במקום להסביר.
            return false;
        }

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

        _log.LogInformation("מתחיל עדכון ל-{Version}.", offer.Version);

        // ---- 3. ההורדה ----

        var target = Path.Combine(
            Path.GetTempPath(),
            $"SafeMe-Update-{offer.Version}-{Guid.NewGuid().ToString("N")[..8]}.exe");

        try
        {
            if (!await DownloadAsync(offer, target, ct))
            {
                Backoff(offer.Version, now);

                return false;
            }

            _log.LogInformation("העדכון אומת. מפעיל את המתקין.");

            return Launch(target, offer.Version);
        }
        catch (OperationCanceledException)
        {
            // כיבוי מסודר של השירות. אין מה לרשום, וננסה שוב בעלייה.
            Cleanup(target);

            throw;
        }
        catch (Exception ex)
        {
            _log.LogError(ex, "העדכון נכשל.");
            Cleanup(target);
            Backoff(offer.Version, now);

            return false;
        }
    }

    // ---------------------------------------------------------------- הורדה

    /// <summary>
    /// מוריד ומאמת. מחזיר false על כל פגם, אחרי שניקה אחריו.
    /// </summary>
    private async Task<bool> DownloadAsync(UpdateOffer offer, string target, CancellationToken ct)
    {
        using (var response = await _http.GetAsync(
            offer.DownloadUrl, HttpCompletionOption.ResponseHeadersRead, ct))
        {
            if (!response.IsSuccessStatusCode)
            {
                _log.LogWarning("הורדת העדכון נכשלה: {Status}", (int)response.StatusCode);

                return false;
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

                    return false;
                }

                await file.WriteAsync(buffer.AsMemory(0, read), ct);
            }

            if (written != offer.SizeBytes)
            {
                _log.LogWarning(
                    "גודל שאינו תואם: {Actual} במקום {Expected}.", written, offer.SizeBytes);

                return false;
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

            return false;
        }

        return true;
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
        catch (Exception ex)
        {
            _log.LogError(ex, "הפעלת המתקין נכשלה.");
            Cleanup(installer);

            return false;
        }
    }

    // ---------------------------------------------------------------- עזר

    private void Backoff(string version, DateTimeOffset now)
    {
        _lastFailedVersion = version;
        _nextAttempt = now + RetryAfterFailure;

        _log.LogWarning(
            "העדכון ל-{Version} ייבדק שוב לא לפני {When}.", version, _nextAttempt);
    }

    private string HwidHash()
    {
        var bytes = SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(_hwid.GetHardwareId()));

        return Convert.ToHexString(bytes).ToLowerInvariant();
    }

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
