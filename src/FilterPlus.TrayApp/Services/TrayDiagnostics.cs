using System.Diagnostics;
using System.IO;

namespace FilterPlus.TrayApp.Services;

/// <summary>
/// רישום אבחוני מאפליקציית המגש.
///
/// עד כה היא לא רשמה דבר, בשום מקום. "האייקון נעלם" חזר שוב ושוב,
/// והמדידה מצאה את התהליך חי ואת החלון מוצג — כלומר מה שקרה בין
/// לבין לא הותיר עקבות, ואי אפשר היה לדעת מה הסתיר אותו.
///
/// היעד הראשון הוא יומן האירועים תחת המקור "FilterPlus", כמו השירות:
/// כך חבילת האבחון שהשירות אוסף לבקשת התמיכה כוללת גם את זה בלי
/// שינוי. המקור נרשם על ידי השירות; משתמש רגיל רשאי לכתוב אליו.
/// כשזה נכשל — קובץ בפרופיל המשתמש.
///
/// עם ריסון: אותה הודעה לא נרשמת יותר מפעם בעשר דקות. תקלה שחוזרת
/// כל חמש שניות הייתה ממלאת את היומן במקום להסביר.
/// </summary>
public static class TrayDiagnostics
{
    private const string Source = "FilterPlus";

    private static readonly TimeSpan Throttle = TimeSpan.FromMinutes(10);
    private static readonly Dictionary<string, DateTimeOffset> _lastByKey = new();
    private static readonly object _sync = new();

    private static string FilePath => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        "FilterPlus", "tray.log");

    /// <summary>
    /// רושם אזהרה. <paramref name="key"/> מזהה את סוג התקלה לצורך
    /// הריסון; ההודעה עצמה יכולה להשתנות (שם החלון המכסה, למשל).
    /// </summary>
    public static void Warn(string key, string message)
    {
        lock (_sync)
        {
            var now = DateTimeOffset.UtcNow;

            if (_lastByKey.TryGetValue(key, out var last) && now - last < Throttle) return;

            _lastByKey[key] = now;
        }

        var text = $"[אייקון המגש] {message}";

        try
        {
            EventLog.WriteEntry(Source, text, EventLogEntryType.Warning);
            return;
        }
        catch (Exception)
        {
            // המקור אינו רשום או שהכתיבה חסומה. הקובץ הוא הגיבוי.
        }

        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(FilePath)!);
            File.AppendAllText(FilePath, $"{DateTimeOffset.Now:yyyy-MM-dd HH:mm:ss} {text}{Environment.NewLine}");
        }
        catch (Exception)
        {
            // אין לאן לרשום. האבחון אינו סיבה להפיל את המחוון.
        }
    }
}
