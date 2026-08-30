using System.Diagnostics.Eventing.Reader;
using System.Runtime.Versioning;

using Microsoft.Extensions.Logging;

namespace SafeMe.Service.Integrity;

/// <summary>עצירה אחת של שירות, כפי שמנהל השירותים רשם אותה.</summary>
public sealed record ServiceStopRecord(string Service, DateTimeOffset WhenUtc);

/// <summary>
/// מוצא עצירות של שירותי SafeMe שקרו בזמן שהסוכן לא פעל.
///
/// זו החוליה שהייתה חסרה, והיא דווקא החשובה שבהן.
///
/// כל שאר ההגנות פועלות בזמן שהסוכן חי: השומר מחזיר אותו, בודק
/// השלמות מחזיר הרשאות, והאכיפה נאכפת. אבל ברגע שהוא עצור, אין מי
/// שיבחין בדבר — וזה בדיוק החלון שמעניין את מי שמנסה. כל מה שקרה
/// שם היה נעלם בלי זכר.
///
/// מנהל השירותים של Windows רושם כל שינוי מצב ביומן המערכת, והוא
/// עושה זאת בין אם הסוכן פועל ובין אם לא. כלומר העדות קיימת גם על
/// תקופה שבה לא היינו — צריך רק לקרוא אותה.
///
/// זו אינה מניעה, וזה בסדר: בלי מנהל התקן חתום אי אפשר למנוע ממנהל
/// דבר. המטרה היא שלא תהיה דרך לעשות משהו בלי שההורה יידע.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class ServiceStopReader
{
    private const string SystemLog = "System";

    /// <summary>
    /// 7036 — "השירות עבר למצב X".
    ///
    /// מנהל השירותים רושם אותו על כל מעבר, ולכן הוא כולל גם עצירות
    /// לגיטימיות: כיבוי המחשב, עדכון, והסרה מסודרת. הסינון ביניהן
    /// נעשה למעלה, כי רק שם ידוע מה הסוכן עצמו יזם.
    /// </summary>
    private const int ServiceStateChanged = 7036;

    /// <summary>7034 — השירות הסתיים באופן לא צפוי. קריסה, לא עצירה.</summary>
    private const int ServiceCrashed = 7034;

    private static readonly string[] Watched = ["SafeMeAgent", "SafeMeGuardian"];

    private readonly ILogger _log;

    public ServiceStopReader(ILogger log) => _log = log;

    /// <summary>
    /// עצירות שנרשמו מאז הרגע שנמסר.
    ///
    /// הרגע הוא הדיווח האחרון שהסוכן הספיק לשלוח. כל מה שאחריו הוא
    /// בהגדרה מה שקרה כשלא היינו.
    /// </summary>
    public IReadOnlyList<ServiceStopRecord> StopsSince(DateTimeOffset sinceUtc)
    {
        /*
         * הסינון על השם נעשה כאן ולא בשאילתה.
         *
         * מנהל השירותים כותב את שם השירות בתוך גוף ההודעה ולא בשדה
         * נפרד, ו-XPath של יומן האירועים אינו יודע לחפש בתוכו.
         * שאילתה על מזהה ותאריך היא זולה, והסינון על מחרוזת קצרה
         * זול עוד יותר.
         */
        var xpath =
            $"*[System[(EventID={ServiceStateChanged} or EventID={ServiceCrashed}) "
            + $"and TimeCreated[@SystemTime&gt;='{sinceUtc.UtcDateTime:o}']]]";

        var found = new List<ServiceStopRecord>();

        try
        {
            using var reader = new EventLogReader(
                new EventLogQuery(SystemLog, PathType.LogName, xpath));

            while (reader.ReadEvent() is { } record)
            {
                using (record)
                {
                    var text = Describe(record);

                    if (text is null) continue;

                    var service = Watched.FirstOrDefault(
                        name => text.Contains(name, StringComparison.OrdinalIgnoreCase));

                    if (service is null) continue;

                    // מעבר למצב "פועל" אינו עצירה. 7034 הוא תמיד כזו.
                    if (record.Id == ServiceStateChanged && !LooksStopped(text)) continue;

                    if (record.TimeCreated is not { } when) continue;

                    found.Add(new ServiceStopRecord(
                        service, new DateTimeOffset(when.ToUniversalTime(), TimeSpan.Zero)));
                }
            }
        }
        catch (EventLogException ex)
        {
            // כלי גילוי, לא תנאי. כשל בקריאה אינו מפיל את העלייה.
            _log.LogWarning(ex, "קריאת עצירות שירות מיומן המערכת נכשלה.");
        }

        return found;
    }

    /// <summary>
    /// הניסוח משתנה בין גרסאות Windows ובין שפות התקנה.
    ///
    /// לכן הבדיקה היא על מילות המצב בעברית ובאנגלית, ולא על תבנית
    /// מדויקת. החמצה כאן עדיפה על דיווח שגוי: התראה על עצירה שלא
    /// קרתה שוחקת את האמון בכל השאר.
    /// </summary>
    private static bool LooksStopped(string text) =>
        text.Contains("stopped", StringComparison.OrdinalIgnoreCase)
        || text.Contains("נעצר", StringComparison.Ordinal);

    private string? Describe(EventRecord record)
    {
        try
        {
            return record.FormatDescription();
        }
        catch (EventLogException)
        {
            // אירוע שאי אפשר לנסח אינו אירוע שאפשר לזהות
            return null;
        }
    }
}
