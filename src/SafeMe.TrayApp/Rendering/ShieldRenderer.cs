using System.Drawing;
using System.Drawing.Drawing2D;
using System.IO;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using SafeMe.Core.Models;

namespace SafeMe.TrayApp.Rendering;

/// <summary>
/// מצייר את סמל המגן של SafeMe.
///
/// הציור מרוכז כאן ומשמש שלושה צרכנים: קובץ האייקון של התוכנה, אייקון
/// המגש, והתג הצף. כך הצורה זהה בכל מקום, ואי אפשר שאחד מהם ישתנה לבד.
///
/// הצורה נבנית מבזיירים ולא מקובץ תמונה, כדי שתישאר חדה בכל גודל
/// ובכל רמת DPI, ובלי תלות בקובץ חיצוני שאפשר למחוק.
/// </summary>
[SupportedOSPlatform("windows")]
public static partial class ShieldRenderer
{
    // צבע המותג. משמש לאייקון התוכנה, שאינו תלוי בסטטוס.
    public static readonly Color BrandDeep = Color.FromArgb(31, 92, 139);
    public static readonly Color BrandLight = Color.FromArgb(86, 155, 209);

    public static Color StatusColor(SecurityStatus status) => status switch
    {
        SecurityStatus.Safe => Color.FromArgb(34, 160, 88),
        SecurityStatus.LowFilter => Color.FromArgb(214, 142, 12),
        SecurityStatus.Unfiltered => Color.FromArgb(206, 56, 46),
        SecurityStatus.Blocked => Color.FromArgb(88, 96, 108),
        _ => Color.FromArgb(140, 150, 163)
    };

    private static Color Lighten(Color c, double amount) => Color.FromArgb(
        c.A,
        (int)Math.Min(255, c.R + (255 - c.R) * amount),
        (int)Math.Min(255, c.G + (255 - c.G) * amount),
        (int)Math.Min(255, c.B + (255 - c.B) * amount));

    /// <summary>
    /// בונה את קו המתאר של המגן בתוך ריבוע בגודל size.
    ///
    /// הצורה: כתפיים רחבות עם פינות מעוגלות, וירידה לקודקוד תחתון.
    /// הבזיירים נותנים את העיקול העדין בצדדים, שהוא מה שמבדיל מגן
    /// מצויר היטב ממשולש עם פינות עגולות.
    /// </summary>
    public static GraphicsPath BuildShieldPath(float size)
    {
        // עבודה ביחידות של 0..100 ואז שינוי קנה מידה, כדי שהיחסים
        // יישמרו בכל גודל
        var s = size / 100f;
        var path = new GraphicsPath();

        // הצורה ממלאת כמעט את כל המסגרת. בגודל 16 פיקסלים כל פיקסל
        // של שוליים מיותרים נראה, והאייקון מתגמד ליד שכניו במגש.
        const float top = 5f;
        const float shoulder = 32f;
        const float waist = 62f;
        const float bottom = 96f;
        const float left = 8f;
        const float right = 92f;
        const float radius = 10f;

        // כתף שמאלית עליונה
        path.AddArc(left * s, top * s, radius * 2 * s, radius * 2 * s, 180, 90);

        // הקצה העליון עד הכתף הימנית
        path.AddArc((right - radius * 2) * s, top * s, radius * 2 * s, radius * 2 * s, 270, 90);

        // צד ימין: ירידה ישרה ואז עיקול פנימה אל הקודקוד
        path.AddLine(right * s, (top + radius) * s, right * s, shoulder * s);

        path.AddBezier(
            right * s, shoulder * s,
            right * s, waist * s,
            (right - 14) * s, (bottom - 15) * s,
            50 * s, bottom * s);

        // צד שמאל, מראה של צד ימין
        path.AddBezier(
            50 * s, bottom * s,
            (left + 14) * s, (bottom - 15) * s,
            left * s, waist * s,
            left * s, shoulder * s);

        path.CloseFigure();

        return path;
    }

    /// <summary>סימן וי בתוך המגן. מסמן "נבדק ואושר".</summary>
    private static GraphicsPath BuildCheckPath(float size)
    {
        var s = size / 100f;
        var path = new GraphicsPath();

        path.AddLine(31f * s, 52f * s, 43f * s, 64f * s);
        path.AddLine(43f * s, 64f * s, 69f * s, 36f * s);

        return path;
    }

    /// <summary>
    /// מצייר מגן. fill הוא צבע הבסיס, והמילוי הוא מדרג עדין ממנו
    /// לגוון בהיר יותר, כדי שהצורה לא תיראה שטוחה בגדלים גדולים.
    /// </summary>
    public static Bitmap RenderShield(int size, Color fill, bool withCheck = true)
    {
        var bitmap = new Bitmap(size, size);

        using var g = Graphics.FromImage(bitmap);

        g.SmoothingMode = SmoothingMode.AntiAlias;
        g.InterpolationMode = InterpolationMode.HighQualityBicubic;
        g.PixelOffsetMode = PixelOffsetMode.HighQuality;
        g.Clear(Color.Transparent);

        using var shield = BuildShieldPath(size);

        using (var brush = new LinearGradientBrush(
                   new PointF(0, 0), new PointF(0, size),
                   Lighten(fill, 0.18), fill))
        {
            g.FillPath(brush, shield);
        }

        // קו מתאר בהיר מוסיף הפרדה מרקע כהה ומרקע בהיר כאחד
        using (var pen = new Pen(Color.FromArgb(70, 255, 255, 255), Math.Max(1f, size / 48f)))
        {
            g.DrawPath(pen, shield);
        }

        if (!withCheck || size < 20)
            return bitmap;

        // בגדלים קטנים הווי נעלם, ולכן מצוירים אותו רק כשיש מספיק פיקסלים
        using var check = BuildCheckPath(size);
        using var checkPen = new Pen(Color.White, Math.Max(1.6f, size / 11f))
        {
            StartCap = LineCap.Round,
            EndCap = LineCap.Round,
            LineJoin = LineJoin.Round
        };

        g.DrawPath(checkPen, check);

        return bitmap;
    }

    [LibraryImport("user32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool DestroyIcon(IntPtr handle);

    /// <summary>
    /// ממיר מפת סיביות לאייקון עצמאי.
    ///
    /// Icon.FromHandle אינו הבעלים של המזהה, ולכן מכפילים ומשחררים מיד.
    /// בלי זה נדלף HICON בכל קריאה, וזה מצטבר בתהליך שרץ חודשים.
    /// </summary>
    public static Icon ToIcon(Bitmap bitmap)
    {
        var handle = bitmap.GetHicon();

        try
        {
            using var temp = Icon.FromHandle(handle);
            return (Icon)temp.Clone();
        }
        finally
        {
            DestroyIcon(handle);
        }
    }

    public static Icon RenderStatusIcon(SecurityStatus status, int size = 32)
    {
        using var bitmap = RenderShield(size, StatusColor(status));
        return ToIcon(bitmap);
    }

    // ---------------------------------------------------------------- קובץ ICO

    private static readonly int[] IconSizes = [16, 24, 32, 48, 64, 128, 256];

    /// <summary>
    /// כותב קובץ ICO רב-גודל.
    ///
    /// המבנה נכתב ידנית משום ש-System.Drawing אינו יודע לשמור ICO
    /// עם כמה גדלים. כל תמונה מוטמעת כ-PNG, מה שנתמך מ-Windows Vista
    /// ומקטין משמעותית את הקובץ בגודל 256.
    /// </summary>
    public static void WriteIcoFile(string path, Color fill, bool withCheck = true)
    {
        var images = new List<byte[]>();

        foreach (var size in IconSizes)
        {
            using var bitmap = RenderShield(size, fill, withCheck);
            using var stream = new MemoryStream();

            bitmap.Save(stream, System.Drawing.Imaging.ImageFormat.Png);
            images.Add(stream.ToArray());
        }

        var directory = Path.GetDirectoryName(Path.GetFullPath(path));
        if (!string.IsNullOrEmpty(directory)) Directory.CreateDirectory(directory);

        using var file = File.Create(path);
        using var writer = new BinaryWriter(file);

        // ICONDIR
        writer.Write((ushort)0);              // שמור
        writer.Write((ushort)1);              // סוג: אייקון
        writer.Write((ushort)IconSizes.Length);

        var offset = 6 + 16 * IconSizes.Length;

        for (var i = 0; i < IconSizes.Length; i++)
        {
            var size = IconSizes[i];

            // 256 נכתב כאפס, לפי הגדרת הפורמט
            writer.Write((byte)(size >= 256 ? 0 : size));
            writer.Write((byte)(size >= 256 ? 0 : size));
            writer.Write((byte)0);            // מספר צבעים בפלטה
            writer.Write((byte)0);            // שמור
            writer.Write((ushort)1);          // planes
            writer.Write((ushort)32);         // ביטים לפיקסל
            writer.Write(images[i].Length);
            writer.Write(offset);

            offset += images[i].Length;
        }

        foreach (var image in images)
            writer.Write(image);
    }
}
