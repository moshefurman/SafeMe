using System.Diagnostics;
using System.Diagnostics.Eventing.Reader;
using System.IO;
using System.IO.Compression;
using System.Runtime.Versioning;
using System.Text;

namespace SafeMe.Service.Diagnostics;

/// <summary>
/// אוסף את מה שצריך כדי להבין תקלה במחשב של לקוח.
///
/// עד כה כל אבחון דרש גישה למכונה: יומן האירועים יושב על המחשב,
/// ההורה לא יידע לפתוח אותו, ואיש מאיתנו לא יהיה שם. בשדה, עם
/// אלפי התקנות, זו הדרך היחידה לדעת מה קרה.
///
/// ---
///
/// מה שנאסף, ולמה דווקא זה:
///
///   יומן האירועים   מה הסוכן אמר, ומתי. זו הראיה העיקרית.
///   מצב נוכחי       גרסה, שירותים, מדיניות — ההקשר שבלעדיו כל
///                   שורה ביומן ניתנת לשתי פרשנויות.
///   יומני התקנה     הסיבה היחידה שאפשר לשחזר ממנה למה התקנה
///                   נכשלה, אחרי שהמתקין כבר נמחק.
///
/// מה שלא נאסף, ובכוונה: תוכן גלישה, היסטוריה, וקבצים. היומן נועד
/// לאבחן את הסוכן, לא לתאר את המשתמש. גם כך הוא מכיל שמות רשתות
/// וכתובות, ולכן הוא נשלח רק לפי בקשה מפורשת ונמחק אחרי שבועיים.
/// </summary>
[SupportedOSPlatform("windows")]
public static class LogBundle
{
    /// <summary>
    /// כמה זמן אחורה לאסוף.
    ///
    /// יממה מכסה כל תקלה שדווחה באותו יום, וזה כל מה שיש לו סיכוי
    /// להיות רלוונטי. חלון רחב יותר מנפח את היומן בלי להוסיף מידע.
    /// </summary>
    private static readonly TimeSpan Window = TimeSpan.FromHours(24);

    /// <summary>
    /// גבול לפני דחיסה.
    ///
    /// השרת חוסם ארבעה מגה-בייט אחרי דחיסה, ויחס הדחיסה של יומן
    /// טקסט הוא בערך אחד לעשרה. הגבול כאן שמרני יותר בכוונה: מחשב
    /// שמייצר יומן חריג הוא בדיוק המחשב שהתקלה בו חמורה, ובקשה
    /// שנדחית בשרת אינה משאירה כלום.
    /// </summary>
    private const int MaxRawBytes = 12 * 1024 * 1024;

    /// <summary>אוסף ומחזיר gzip מוכן לשליחה.</summary>
    public static byte[] Collect(string agentVersion)
    {
        var text = new StringBuilder(256 * 1024);

        text.AppendLine("SafeMe · יומן אבחון");
        text.AppendLine($"נאסף  : {DateTimeOffset.Now:O}");
        text.AppendLine($"מחשב  : {Environment.MachineName}");
        text.AppendLine($"גרסה  : {agentVersion}");
        text.AppendLine($"מערכת : {Environment.OSVersion.VersionString}");
        text.AppendLine();

        AppendState(text);
        AppendEvents(text);
        AppendInstallLogs(text);

        return Compress(text.ToString());
    }

    // ---------------------------------------------------------------- מצב

    /// <summary>
    /// ההקשר שבלעדיו שורה ביומן אינה אומרת דבר.
    ///
    /// "לא זוהה ספק" פירושו דבר אחד כשהשירות רץ ומדיניות הוחלה,
    /// ודבר אחר לגמרי כשהוא עלה לפני שתי דקות. בלי המצב הנוכחי
    /// שתי האפשרויות נראות זהות — וזה עלה שעות באבחון אמיתי.
    /// </summary>
    private static void AppendState(StringBuilder text)
    {
        text.AppendLine("── מצב נוכחי ──");

        foreach (var name in new[] { "SafeMeAgent", "SafeMeGuardian" })
        {
            try
            {
                using var svc = new System.ServiceProcess.ServiceController(name);

                text.AppendLine($"{name}: {svc.Status}");
            }
            catch (Exception ex)
            {
                text.AppendLine($"{name}: אינו רשום ({ex.GetType().Name})");
            }
        }

        foreach (var p in new[] { "SafeMe.Service", "SafeMe.Guardian", "SafeMe.TrayApp" })
        {
            var count = Process.GetProcessesByName(p).Length;

            text.AppendLine($"תהליך {p}: {count}");
        }

        /*
         * appsettings בלי סודות.
         *
         * הכתובת היא מה שמעניין — עדכון שהסיט מחשב לכתובת אחרת
         * הוציא אותו מהישג יד, וזה נראה בקובץ הזה בשורה אחת. שאר
         * הקובץ עלול להכיל מפתחות, ולכן הוא אינו נכלל.
         */
        try
        {
            var config = Path.Combine(AppContext.BaseDirectory, "appsettings.json");

            if (File.Exists(config))
            {
                using var doc = System.Text.Json.JsonDocument.Parse(File.ReadAllText(config));

                if (doc.RootElement.TryGetProperty("Server", out var server)
                    && server.TryGetProperty("BaseUrl", out var url))
                {
                    text.AppendLine($"שרת: {url.GetString()}");
                }
            }
        }
        catch (Exception ex)
        {
            text.AppendLine($"קריאת התצורה נכשלה: {ex.Message}");
        }

        text.AppendLine();
    }

    // ---------------------------------------------------------------- אירועים

    private static void AppendEvents(StringBuilder text)
    {
        text.AppendLine($"── יומן אירועים · {Window.TotalHours:N0} שעות אחרונות ──");

        try
        {
            var since = DateTime.UtcNow - Window;

            /*
             * שאילתה על הזמן ועל המקור, ולא סינון אחרי הקריאה.
             *
             * יומן היישומים מכיל הכול; קריאה שלו במלואו וסינון
             * בצד שלנו לוקחת עשרות שניות ומעמיסה על מחשב שכבר
             * במצב לא תקין.
             */
            var query = "*[System[Provider[@Name='SafeMe'] and "
                + $"TimeCreated[@SystemTime>='{since:yyyy-MM-ddTHH:mm:ss.fffZ}']]]";

            using var reader = new EventLogReader(
                new EventLogQuery("Application", PathType.LogName, query));

            var seen = 0;

            for (var record = reader.ReadEvent(); record is not null; record = reader.ReadEvent())
            {
                using (record)
                {
                    text.Append(record.TimeCreated?.ToString("yyyy-MM-dd HH:mm:ss") ?? "?");
                    text.Append("  [");
                    text.Append(record.LevelDisplayName ?? "?");
                    text.Append("]  ");

                    var message = SafeMessage(record);

                    text.AppendLine(message.Replace("\r\n", " | ").Replace("\n", " | "));

                    seen++;
                }

                if (text.Length > MaxRawBytes)
                {
                    text.AppendLine("... נקטע: היומן חרג מהגבול.");
                    break;
                }
            }

            if (seen == 0) text.AppendLine("(אין רשומות בחלון הזמן)");
        }
        catch (Exception ex)
        {
            text.AppendLine($"קריאת יומן האירועים נכשלה: {ex.Message}");
        }

        text.AppendLine();
    }

    /// <summary>
    /// FormatDescription זורק על רשומות שהמניפסט שלהן חסר.
    ///
    /// רשומה אחת כזו הייתה מפילה את כל האיסוף, ומשאירה אותנו בלי
    /// שום יומן בדיוק במחשב שבו משהו לא תקין.
    /// </summary>
    private static string SafeMessage(EventRecord record)
    {
        try { return record.FormatDescription() ?? "(ללא תיאור)"; }
        catch (Exception ex) { return $"(תיאור לא זמין: {ex.GetType().Name})"; }
    }

    // ---------------------------------------------------------------- התקנה

    private static void AppendInstallLogs(StringBuilder text)
    {
        text.AppendLine("── יומני התקנה ──");

        try
        {
            var dir = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
                "SafeMe", "logs");

            if (!Directory.Exists(dir))
            {
                text.AppendLine("(אין)");
                text.AppendLine();

                return;
            }

            var files = new DirectoryInfo(dir)
                .GetFiles("install-*.log")
                .OrderByDescending(f => f.LastWriteTimeUtc)
                .Take(3);

            foreach (var file in files)
            {
                text.AppendLine($"--- {file.Name} ---");

                try { text.AppendLine(File.ReadAllText(file.FullName)); }
                catch (Exception ex) { text.AppendLine($"(קריאה נכשלה: {ex.Message})"); }
            }
        }
        catch (Exception ex)
        {
            text.AppendLine($"איסוף יומני ההתקנה נכשל: {ex.Message}");
        }

        text.AppendLine();
    }

    // ---------------------------------------------------------------- דחיסה

    private static byte[] Compress(string text)
    {
        var raw = Encoding.UTF8.GetBytes(text);

        using var output = new MemoryStream();

        using (var gzip = new GZipStream(output, CompressionLevel.SmallestSize, leaveOpen: true))
            gzip.Write(raw, 0, raw.Length);

        return output.ToArray();
    }
}
