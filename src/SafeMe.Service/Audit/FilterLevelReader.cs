using SafeMe.Core.Models;
using System.Runtime.Versioning;
using System.Text.RegularExpressions;

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
public sealed partial class FilterLevelReader
{
    /*
     * כתובת ההפניה בגוף דף החסימה.
     *
     * מוגבלת ל-https ולתווים שאינם רווח או מרכאה, כדי שלא תיתפס
     * מחרוזת שרירותית מתוך סקריפט. גוף שאינו של הספק פשוט לא יתאים.
     */
    [GeneratedRegex(@"https://[^\s""'<>]+", RegexOptions.IgnoreCase)]
    private static partial Regex RedirectPattern();

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
    public Task<FilterLevel?> ReadAsync(ProviderRule provider, CancellationToken ct) =>
        ReadAsync(provider, null, ct);

    /// <param name="detection">
    /// מה שכבר הוכח על החיבור. טווח כתובות או ASN של הספק הם
    /// הוכחה שהקו הוא שלו — ואז אין צורך בתעודה כדי להרשות בקשה.
    /// </param>
    public async Task<FilterLevel?> ReadAsync(
        ProviderRule provider, ProviderDetection? detection, CancellationToken ct)
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
        /*
         * השער נבדק פעם אחת, על מארח שהסינון מיירט בו TLS — ולא על
         * מארחי הרמה עצמם.
         *
         * זו הייתה הטעות. המארחים שדף החסימה שלהם מזכיר את רמת
         * ההגנה הם דווקא אלה שהסינון מנתק להם את לחיצת היד, ולכן
         * שער שדרש מהם תעודה לא היה עובר לעולם — ואילו המארח שכן
         * הגיש תעודה הוא זה שדף החסימה שלו אינו מזכיר רמה כלל.
         *
         * נמדד: קטגוריה 41 מחזירה דף של 12,589 בתים בלי שם דרגה,
         * וקטגוריה 56 מחזירה 9,055 בתים ובהם "בסיסית".
         *
         * ההוכחה שהמחשב מסונן נשארת חזקה בדיוק כשהייתה: מנפיק
         * התעודה הוא של הספק, ואי אפשר לזייף אותו. מה שהשתנה הוא
         * שהיא נבדקת במקום שאפשר לבדוק אותה בו.
         */
        var proven = await _tls.MatchesAsync(provider, ct);

        /*
         * הקו עצמו הוא הוכחה.
         *
         * נמדד: רימון הפסיקה להגיש תעודה על אתרים חסומים ועברה
         * לנתק את לחיצת היד. שער שדורש תעודה לא היה נפתח לעולם,
         * והרמה — שעדיין נקראת מדף החסימה ב-HTTP רגיל — הייתה
         * נשארת "לא נקראה" על קו מסונן לחלוטין.
         *
         * כתובת ציבורית בטווח הספק, או ASN שלו, אינם ניתנים לזיוף
         * מצד המחשב: הם מה שהאינטרנט רואה כשהוא מסתכל חזרה.
         */
        var lineProven = detection is { IpRangeMatch: true } or { AsnMatch: true };

        if (!proven.Matched && !lineProven)
        {
            _log.LogDebug(
                "רמת הסינון לא נקראה: לא הוכח שהחיבור עובר דרך {Provider}.", provider.Id);

            return null;
        }

        var hosts = markers.LevelHosts
            .Concat(HostsFrom(markers.Url))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();

        foreach (var host in hosts)
        {
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


    /// <summary>
    /// עוקב אחרי ההפניה שבגוף ומחפש בה את שם הדרגה.
    ///
    /// מחזיר null כשאין הפניה, כשהיא אינה של הספק, או כשהקריאה
    /// נכשלה — ואז נשארים עם המספר לבדו, וזה מצב תקין.
    /// </summary>
    private async Task<FilterLevel?> FollowAsync(
        string body, IReadOnlyList<string> levelNames, CancellationToken ct)
    {
        var match = RedirectPattern().Match(body);

        if (!match.Success) return null;

        var url = match.Value;

        try
        {
            var client = _httpFactory.CreateClient("probe");

            using var response = await client.GetAsync(
                url, HttpCompletionOption.ResponseContentRead, ct);

            var page = await ReadCappedAsync(response, ct);

            var level = SafeMe.Core.Policy.FilterLevelReader.Read(page, levelNames);

            // הדף השני נושא את השם; המספרים כבר נקראו מהראשון
            return level.Name is null ? null : level;
        }
        catch (Exception ex)
        {
            _log.LogDebug(ex, "מעקב אחרי דף החסימה נכשל.");
            return null;
        }
    }

    private async Task<FilterLevel?> FetchAsync(
        string host, IReadOnlyList<string> levelNames, CancellationToken ct)
    {
        try
        {
            var client = _httpFactory.CreateClient("probe");

            using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);

            cts.CancelAfter(TimeSpan.FromSeconds(6));

            /*
             * HTTP ולא HTTPS, ובכוונה.
             *
             * הסינון מנתק את לחיצת היד למארחים האלה לפי SNI, ולכן
             * דרך HTTPS אין דף כלל. מעל HTTP הוא מיירט ומגיש את דף
             * החסימה — וזה מה שיש בו לקרוא.
             *
             * הגישה מותנית בשער שכבר עבר: הוכח שהחיבור עובר דרך
             * הספק, ולכן מה שיחזור הוא דף החסימה שלו ולא האתר.
             */
            using var response = await client.GetAsync(
                $"http://{host}/", HttpCompletionOption.ResponseContentRead, cts.Token);

            /*
             * הגוף נקרא חתוך.
             *
             * דף חסימה הוא קטן, והמחרוזת שמעניינת אותנו יושבת בראשו.
             * קריאה בלי גבול הייתה הופכת תקלה — מארח שבכל זאת החזיר
             * תוכן אמיתי — להורדה מלאה שלו.
             */
            var body = await ReadCappedAsync(response, cts.Token);

            var level = SafeMe.Core.Policy.FilterLevelReader.Read(body, levelNames);

            /*
             * התשובה הישירה היא הפניה, לא דף החסימה.
             *
             * נמדד: רימון מחזירה 688 בתים ובהם level ו-urllevel, ואחריהם
             * סקריפט שמעביר לדף האמיתי. שם הדרגה יושב **רק** בדף
             * השני — ולכן הקריאה כאן מצאה מספר ולא מצאה שם, לעולם.
             *
             * ההפניה היא JavaScript ולא 302, ולכן HttpClient אינו
             * עוקב אחריה מעצמו וצריך לחלץ אותה מהגוף.
             *
             * הבקשה השנייה נעשית רק כשחסר שם ויש מספר — כלומר רק
             * כשהוכח שזה דף חסימה של הספק, ולכן היא אינה מרחיבה את
             * מה שהסוכן ניגש אליו.
             */
            if (level.Name is not null || !level.HasAny) return level;

            var followed = await FollowAsync(body, levelNames, cts.Token);

            return followed ?? level;
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
