namespace SafeMe.Core.Updates;

/// <summary>
/// הסימן שאומר לשומרים לא להתערב בזמן עדכון.
///
/// הם בדקו זאת לפי שם תהליך — "SafeMe-Setup" או "SafeMe.Installer" —
/// והמתקין שהעדכון מפעיל נקרא בכלל SafeMe-Update-{גרסה}-{גיבוב}.exe.
/// השער היה קיים בשני השומרים ומעולם לא ירה.
///
/// מה שקרה בשטח: המתקין מחק את שני השירותים, השומר של הסוכן החזיר
/// את שירות השומר תוך שתי שניות, השומר החי החזיק את הקבצים נעולים,
/// ההעתקה נכשלה — והמחשב נשאר בלי שירות סוכן כלל. העדכונים הקודמים
/// עברו במזל תזמון ולא משום שהשער עבד.
///
/// שם תהליך הוא הסכם שביר: הוא נקבע בצד אחד ונבדק בצד אחר, ואף
/// אחד לא נכשל כשהוא משתנה. קובץ במקום מוסכם הוא הסכם מפורש.
///
/// יש לו תפוגה. מתקין שקרס בלי לנקות היה משתיק את השומרים לנצח —
/// מחיר גבוה בהרבה מהתערבות מוקדמת בעדכון הבא.
/// </summary>
public static class UpdateMarker
{
    /// <summary>
    /// כמה זמן הסימן תקף.
    ///
    /// התקנה מלאה נמדדה בעשרות שניות. חמש דקות נותנות מרווח נדיב
    /// גם על מחשב איטי, ועדיין קצרות מכדי להשאיר את המחשב בלי
    /// שמירה אם המתקין מת.
    /// </summary>
    public static readonly TimeSpan Lifetime = TimeSpan.FromMinutes(5);

    /// <summary>
    /// האם עדכון פעיל, לפי תוכן הקובץ ושעה נתונה.
    ///
    /// טהור בכוונה: זו ההכרעה שקובעת אם שומר יתערב באמצע החלפת
    /// קבצים, והיא צריכה להיבדק בלי לגעת בדיסק.
    ///
    /// תוכן שאינו נקרא נחשב לא פעיל. קובץ פגום אינו סיבה להשבית
    /// את ההגנה, והכיוון הבטוח כאן הוא דווקא לשמור.
    /// </summary>
    public static bool IsActive(string? content, DateTimeOffset now)
    {
        if (string.IsNullOrWhiteSpace(content)) return false;

        if (!DateTimeOffset.TryParse(
                content.Trim(),
                null,
                System.Globalization.DateTimeStyles.RoundtripKind,
                out var startedUtc))
            return false;

        var age = now - startedUtc;

        /*
         * שעה עתידית נחשבת לא פעילה.
         *
         * שעון שקפץ קדימה, או קובץ שנכתב בכוונה עם תאריך רחוק,
         * היו משביתים את השומרים ללא הגבלה. זו בדיוק הדרך הזולה
         * לנטרל אותם, ולכן היא נסגרת כאן.
         */
        if (age < TimeSpan.Zero) return false;

        return age <= Lifetime;
    }

    /// <summary>התוכן שנכתב לקובץ כשעדכון מתחיל.</summary>
    public static string Stamp(DateTimeOffset now) => now.ToString("O");

    /// <summary>
    /// נתיב הסימן.
    ///
    /// ב-Core ולא ב-Service, כי שירות השומר הוא פרויקט נפרד שאינו
    /// מכיר את נתיבי הסוכן. שני הצדדים חייבים להסכים על אותו מקום,
    /// וההסכמה הזו צריכה להיות במקום אחד שאפשר לקמפל מולו.
    /// </summary>
    public static string Path { get; } = System.IO.Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
        "SafeMe", "state", "update.lock");

    /// <summary>קורא את הסימן מהדיסק. כשל בקריאה נחשב "אין עדכון".</summary>
    public static bool IsActive(DateTimeOffset now)
    {
        try
        {
            return File.Exists(Path) && IsActive(File.ReadAllText(Path), now);
        }
        catch (Exception)
        {
            /*
             * קובץ נעול, הרשאה חסרה, דיסק שנכשל — כולם מחזירים
             * "אין עדכון", כלומר השומרים ממשיכים לשמור. זה הכיוון
             * הבטוח: התערבות מיותרת בעדכון עולה עדכון אחד, והימנעות
             * מיותרת עולה את ההגנה עצמה.
             */
            return false;
        }
    }

    /// <summary>מסמן שעדכון מתחיל. אינו זורק — כישלון כאן אינו עוצר עדכון.</summary>
    public static void Write(DateTimeOffset now)
    {
        try
        {
            var dir = System.IO.Path.GetDirectoryName(Path);

            if (dir is not null) Directory.CreateDirectory(dir);

            File.WriteAllText(Path, Stamp(now));
        }
        catch (Exception)
        {
            // בלי הסימן השומרים עלולים להתערב, אבל עדכון שלא יצא
            // לדרך כלל הוא תוצאה גרועה יותר.
        }
    }

    /// <summary>מנקה את הסימן. בטוח לקריאה חוזרת.</summary>
    public static void Clear()
    {
        try
        {
            if (File.Exists(Path)) File.Delete(Path);
        }
        catch (Exception)
        {
            // התפוגה תטפל בזה ממילא.
        }
    }
}
