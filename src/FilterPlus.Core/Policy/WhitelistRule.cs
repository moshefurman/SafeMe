using System.Text.Json;
using System.Text.Json.Serialization;

namespace FilterPlus.Core.Policy;

/// <summary>
/// גלישה לרשימה לבנה בלבד.
///
/// כל שאר האכיפה במוצר נשענת על כך שמישהו אחר מסנן: ספק, והסוכן
/// רק מוודא שהוא שם. כאן הסוכן עצמו הוא המסנן, ולכן המצב הזה עומד
/// גם על קו שאינו מסונן כלל — וזו הסיבה שהוא מקבל סטטוס משלו ולא
/// "אינו מסונן".
///
/// האכיפה היא בשמות ולא בכתובות, כי כך בנוי האינטרנט: אתר אחד נטען
/// מעשרות שמות, והכתובות שמאחוריהם מתחלפות כל כמה דקות. הסוכן מריץ
/// שרת שמות מקומי, עונה רק על שמות מותרים, ופותח ב-WFP רק את
/// הכתובות שהוא עצמו החזיר.
/// </summary>
public sealed class WhitelistRule
{
    public bool Enabled { get; set; }

    /// <summary>
    /// הדומיינים המותרים. כל ערך מתיר את עצמו ואת כל מה שמתחתיו:
    /// "example.com" מתיר גם את "static.example.com".
    /// </summary>
    public List<string> Domains { get; set; } = new();

    /// <summary>
    /// דומיינים שהמערכת עצמה צריכה: בדיקת הקישוריות של Windows, שעון.
    /// מגיעים מהשרת כדי שאפשר יהיה לתקן אותם בלי גרסה.
    /// </summary>
    public List<string> SystemDomains { get; set; } = new();

    /// <summary>
    /// שרתי השמות שאליהם מועברות השאלות המותרות.
    ///
    /// ברירת המחדל היא שרת שמסווג תוכן וחוסם פורנוגרפיה בעצמו. זו
    /// השכבה השנייה: גם דומיין שנכנס לרשימה בדרך כלשהי לא ייפתר אם
    /// הוא מסווג כך, וגם חלון הלמידה אינו פותח אותו.
    /// </summary>
    public List<string> UpstreamResolvers { get; set; } = new() { "1.1.1.3", "1.0.0.3" };

    /// <summary>
    /// סוף חלון הלמידה. עד אז כל שם שנפתר מותר ונרשם, כדי שההורה
    /// יוכל לבחור מתוכו מה לאשר.
    ///
    /// זמן מוחלט ולא משך: המדיניות חתומה, והסוכן אינו יכול להאריך
    /// לעצמו חלון שהשרת קצב.
    /// </summary>
    public DateTimeOffset? LearnUntilUtc { get; set; }

    [JsonExtensionData]
    public Dictionary<string, JsonElement>? Unknown { get; set; }

    public bool IsLearning(DateTimeOffset now) => LearnUntilUtc is { } until && now < until;

    /// <summary>
    /// האם המנגנון צריך לפעול כרגע. למידה מפעילה אותו גם כשהרשימה
    /// עצמה עוד כבויה — לומדים קודם, מפעילים אחר כך.
    /// </summary>
    public bool IsActive(DateTimeOffset now) => Enabled || IsLearning(now);
}
