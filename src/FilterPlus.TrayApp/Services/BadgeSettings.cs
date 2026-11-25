using System.IO;
using System.Text.Json;

namespace FilterPlus.TrayApp.Services;

/// <summary>הפינה שאליה נצמד התג הצף.</summary>
public enum BadgeCorner
{
    BottomRight = 0,
    BottomLeft = 1,
    TopRight = 2,
    TopLeft = 3
}

/// <summary>
/// העדפות התצוגה של התג הצף.
///
/// נשמרות בפרופיל המשתמש ולא ב-ProgramData, כי אלה העדפות תצוגה
/// אישיות: שני משתמשים על אותו מחשב יכולים להעדיף פינות שונות.
/// אין כאן שום דבר שמשפיע על האכיפה, ולכן הקובץ ניתן לכתיבה למשתמש.
/// </summary>
public sealed class BadgeSettings
{
    public BadgeCorner Corner { get; set; } = BadgeCorner.BottomRight;

    /// <summary>מצב מכווץ: רק המגן, בלי טקסט.</summary>
    public bool Collapsed { get; set; }

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        Converters = { new System.Text.Json.Serialization.JsonStringEnumConverter() }
    };

    private static string FilePath => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
        "FilterPlus", "badge.json");

    public static BadgeSettings Load()
    {
        try
        {
            if (File.Exists(FilePath))
            {
                var json = File.ReadAllText(FilePath);
                return JsonSerializer.Deserialize<BadgeSettings>(json, JsonOptions) ?? new BadgeSettings();
            }
        }
        catch (Exception)
        {
            // העדפת תצוגה פגומה אינה סיבה להיכשל. חוזרים לברירת המחדל.
        }

        return new BadgeSettings();
    }

    public void Save()
    {
        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(FilePath)!);
            File.WriteAllText(FilePath, JsonSerializer.Serialize(this, JsonOptions));
        }
        catch (Exception)
        {
            // שמירה שנכשלה משפיעה רק על ההרצה הבאה
        }
    }
}
