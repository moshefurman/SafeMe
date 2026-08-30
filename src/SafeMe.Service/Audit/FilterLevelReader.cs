using System.Runtime.Versioning;

using Microsoft.Extensions.Logging;

using SafeMe.Core.Policy;

namespace SafeMe.Service.Audit;

/// <summary>
/// קורא את רמת הסינון מדף החסימה של הספק.
///
/// למה זה שווה את המאמץ: זיהוי שהמחשב מסונן אינו אומר דבר על **כמה**
/// הוא מסונן. הורה שהגדיר רמה מחמירה ומצא אותה מוקלת לא היה יודע,
/// וזו בדיוק צורת העקיפה שקשה לתפוס — לא ניתוק הסינון, אלא החלשתו
/// בשקט. הספק עצמו מדווח את המספר בגוף דף החסימה, ולכן אין צורך
/// לנחש אותו מבדיקות עקיפות.
///
/// ולמה זה עדין: המארחים שמייצרים דף חסימה בכל רמה הם דווקא אלה
/// שבקטגוריות הבוטות, ופורנוגרפיה היא הבחירה המובהקת. הימורים או
/// רשתות חברתיות מותרים ברמות מקלות, ואז אין דף חסימה ואין מה לקרוא.
///
/// ולכן השער.
///
/// לפני כל בקשת HTTP נעשית לחיצת יד בלבד, שקוראת את מנפיק התעודה.
/// רק אם המנפיק הוא של הספק — כלומר רק אם הוכח שמה שיחזור הוא דף
/// החסימה שלו — נשלחת הבקשה. על מחשב שאינו מסונן הבדיקה נעצרת
/// בלחיצת היד, ושום בקשה לא יוצאת אל האתר עצמו.
///
/// בלי השער הזה, כלי שנועד לאכוף סינון היה זה שמבקר באתרים
/// שאסור לו להגיע אליהם, בדיוק על המחשב שאינו מוגן.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class FilterLevelReader
{
    private readonly TlsIssuerAuditor _tls;
    private readonly IHttpClientFactory _httpFactory;
    private readonly ILogger<FilterLevelReader> _log;

    public FilterLevelReader(
        TlsIssuerAuditor tls,
        IHttpClientFactory httpFactory,
        ILogger<FilterLevelReader> log)
    {
        _tls = tls;
        _httpFactory = httpFactory;
        _log = log;
    }

    /// <summary>
    /// מנסה לקרוא את הרמה. מחזיר null כשלא הצלחנו — וזה שונה
    /// מ"אין סינון", שהוא מסקנה של הביקורת ולא של הקריאה הזו.
    /// </summary>
    public async Task<FilterLevel?> ReadAsync(ProviderRule provider, CancellationToken ct)
    {
        var markers = provider.HttpMarkers;

        if (markers is null) return null;

        /*
         * איחוד, ולא בחירה.
         *
         * הגרסה הראשונה העדיפה את רשימת הרמה ודילגה על מארח הסמנים
         * כשהיא קיימת — וזה היה בדיוק ההפך מהנכון. המארחים שנבחרו
         * לרשימה היו בקטגוריה הבוטה, מתוך הנחה שהיא נחסמת בכל רמה,
         * והיא נכונה. מה שהיא לא לקחה בחשבון: הסינון חוסם אותם
         * **בניתוק לפי SNI** ולא בהגשת דף.
         *
         * נמדד על מכונה מסוננת: pornhub ו-xvideos מנתקים את לחיצת
         * היד בלי להגיש תעודה כלל, בעוד bet365 מיירט ומגיש דף עם
         * level=-30&urllevel=-35. כלומר דווקא הקטגוריה הבוטה ביותר
         * היא זו שאין ממנה מה לקרוא.
         *
         * לכן שניהם, לפי הסדר. הראשון שמגיש תעודה תואמת מנצח.
         */
        var hosts = markers.LevelHosts
            .Concat(HostsFrom(markers.Url))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();

        var patterns = provider.TlsIssuer?.Patterns ?? [];

        foreach (var host in hosts)
        {
            /*
             * השער.
             *
             * לחיצת יד בלבד — בלי בקשה ובלי תוכן. אם המנפיק אינו של
             * הספק, המחשב אינו מסונן על המארח הזה, ובקשה אליו הייתה
             * מגיעה לאתר האמיתי. עוצרים.
             */
            if (patterns.Count > 0)
            {
                var probe = await _tls.ObserveAsync(host, ct);

                if (probe.Observation != TlsObservation.Certificate) continue;

                if (probe.Issuer is null
                    || !patterns.Any(p => Wildcard.IsMatch(probe.Issuer, p)))
                {
                    _log.LogDebug(
                        "דילוג על קריאת רמה מ-{Host}: התעודה אינה של {Provider}.",
                        host, provider.Id);

                    continue;
                }
            }

            var level = await FetchAsync(host, markers.LevelNames, ct);

            if (level is { HasAny: true })
            {
                _log.LogInformation(
                    "רמת הסינון נקראה מ-{Host}: {Description}",
                    host, FilterLevelReaderText.Describe(level));

                return level;
            }
        }

        return null;
    }

    private async Task<FilterLevel?> FetchAsync(
        string host, IReadOnlyList<string> levelNames, CancellationToken ct)
    {
        try
        {
            var client = _httpFactory.CreateClient("probe");

            using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);

            cts.CancelAfter(TimeSpan.FromSeconds(6));

            using var response = await client.GetAsync(
                $"https://{host}/", HttpCompletionOption.ResponseContentRead, cts.Token);

            /*
             * הגוף נקרא חתוך.
             *
             * דף חסימה הוא קטן, והמחרוזת שמעניינת אותנו יושבת בראשו.
             * קריאה בלי גבול הייתה הופכת תקלה — מארח שבכל זאת החזיר
             * תוכן אמיתי — להורדה מלאה שלו.
             */
            var body = await ReadCappedAsync(response, cts.Token);

            return SafeMe.Core.Policy.FilterLevelReader.Read(body, levelNames);
        }
        catch (Exception ex)
        {
            _log.LogDebug(ex, "קריאת רמת סינון מ-{Host} נכשלה.", host);
            return null;
        }
    }

    /// <summary>קורא עד 64 קילובייט. די בהרבה לדף חסימה.</summary>
    private static async Task<string> ReadCappedAsync(
        HttpResponseMessage response, CancellationToken ct)
    {
        const int cap = 64 * 1024;

        await using var stream = await response.Content.ReadAsStreamAsync(ct);

        var buffer = new byte[cap];
        var read = 0;

        while (read < cap)
        {
            var n = await stream.ReadAsync(buffer.AsMemory(read, cap - read), ct);

            if (n == 0) break;

            read += n;
        }

        return System.Text.Encoding.UTF8.GetString(buffer, 0, read);
    }

    private static List<string> HostsFrom(string? url)
    {
        if (string.IsNullOrWhiteSpace(url)) return [];

        return Uri.TryCreate(url, UriKind.Absolute, out var parsed)
            ? [parsed.Host]
            : [];
    }
}

/// <summary>גישה לניסוח שב-Core, בלי להתנגש בשם המחלקה שכאן.</summary>
internal static class FilterLevelReaderText
{
    public static string Describe(FilterLevel level) =>
        SafeMe.Core.Policy.FilterLevelReader.Describe(level);
}
