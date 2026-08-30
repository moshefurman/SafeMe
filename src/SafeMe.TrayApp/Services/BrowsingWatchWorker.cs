using System.Runtime.Versioning;

using SafeMe.Core.Browsing;
using SafeMe.Core.Models;
using SafeMe.Core.Policy;

namespace SafeMe.TrayApp.Services;

/// <summary>
/// סורק לשוניות פתוחות ומדווח כמה נחסמו.
///
/// רץ במגש כי שירות ב-session 0 אינו רואה חלונות משתמש. מדווח
/// לשירות דרך IPC, והשירות מעביר הלאה — ספירה בלבד.
///
/// **מתריע ואינו סוגר.** התאמה על כותרת עלולה לטעות, וסגירת לשונית
/// באמצע עבודה הורסת את האמון מהר יותר משהיא מועילה. אם יתברר
/// שאחוז הטעויות נמוך, אפשר יהיה להוסיף סגירה כבחירה מפורשת.
///
/// ומה שנשלח הוא ספירה. הכותרות והכתובות נבדקות כאן ונשארות כאן.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class BrowsingWatchWorker : IDisposable
{
    private static readonly TimeSpan Minimum = TimeSpan.FromSeconds(5);

    private readonly BrowserTabReader _reader = new();
    private readonly StatusPoller _poller;
    private readonly CancellationTokenSource _cts = new();

    private Task? _loop;

    /*
     * מה שכבר דווח.
     *
     * אותה לשונית פתוחה נסרקת שוב ושוב, ובלי הזיכרון הזה ההורה היה
     * מקבל התראה כל עשרים שניות על אותו דבר. מה שמעניין הוא שנפתח
     * משהו, ולא שהוא עדיין פתוח.
     */
    private readonly HashSet<string> _reported = new(StringComparer.OrdinalIgnoreCase);

    public BrowsingWatchWorker(StatusPoller poller) => _poller = poller;

    public void Start() => _loop = Task.Run(() => RunAsync(_cts.Token));

    private async Task RunAsync(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            var rule = await ReadRuleAsync(ct);

            var wait = rule is { Enabled: true }
                ? TimeSpan.FromSeconds(Math.Max(rule.ScanSeconds, Minimum.TotalSeconds))
                : TimeSpan.FromMinutes(2);

            if (rule is { Enabled: true }) Scan(rule);

            try
            {
                await Task.Delay(wait, ct);
            }
            catch (OperationCanceledException)
            {
                return;
            }
        }
    }

    private async Task<BrowsingWatchRule?> ReadRuleAsync(CancellationToken ct)
    {
        try
        {
            var policy = await _poller.RequestPolicyAsync(ct);

            return policy?.Enforcement.BrowsingWatch;
        }
        catch (Exception)
        {
            // אין קשר לשירות. לא סורקים, ולא מניחים דבר.
            return null;
        }
    }

    private void Scan(BrowsingWatchRule rule)
    {
        try
        {
            var tabs = _reader.Read();

            var matches = TabMatcher.Match(tabs, rule.BlockedHosts, rule.BlockedTitleTerms);

            /*
             * המפתח לזיהוי חוזר הוא הכותרת והמארח יחד — והוא נשאר
             * כאן בלבד. הוא לא נכנס לדיווח ולא נשמר לדיסק.
             */
            var fresh = matches
                .Where(m => _reported.Add($"{m.Tab.Host}|{m.Tab.Title}"))
                .ToList();

            // הזיכרון אינו גדל בלי גבול: אחרי מאתיים ערכים הוא מתאפס
            // ומתחיל מחדש. חזרה על התראה ישנה עדיפה על דליפת זיכרון.
            if (_reported.Count > 200) _reported.Clear();

            if (fresh.Count == 0) return;

            _poller.ReportBrowsing(BrowsingBlockSummary.From(fresh));
        }
        catch (Exception)
        {
            // סריקה שנכשלה אינה סיבה להפיל את המגש
        }
    }

    public void Dispose()
    {
        _cts.Cancel();

        try
        {
            _loop?.Wait(TimeSpan.FromSeconds(2));
        }
        catch (Exception)
        {
            // כיבוי. אין למי לדווח.
        }

        _cts.Dispose();
    }
}
