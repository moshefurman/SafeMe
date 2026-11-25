using System.Runtime.Versioning;
using FilterPlus.Core.Models;
using FilterPlus.TrayApp.Rendering;

namespace FilterPlus.AssetGen;

/// <summary>
/// מייצר את קובצי האייקון של FilterPlus.
///
/// הרצה: dotnet run --project tools/FilterPlus.AssetGen -- assets
/// </summary>
[SupportedOSPlatform("windows")]
public static class Program
{
    public static int Main(string[] args)
    {
        var outDir = args.Length > 0 ? args[0] : "assets";

        Directory.CreateDirectory(outDir);

        /*
         * אייקון התוכנה (filterplus.ico) ותמונת ה-512 אינם נוצרים כאן עוד.
         *
         * הם נגזרים מהלוגו של Filter+ (assets/filterplus-logo.svg, assets/filterplus-mark.svg),
         * ולא מציור של ShieldRenderer. יצירה שלהם מכאן הייתה דורסת את הלוגו
         * במגן הישן בכל הרצה, בלי שאיש ישים לב עד ההתקנה הבאה.
         */

        // גרסאות לפי סטטוס. אינן נדרשות בזמן ריצה, שכן התג ואייקון
        // המגש מציירים בעצמם, אך שימושיות לתיעוד, לאתר ולחנות.
        foreach (SecurityStatus status in Enum.GetValues<SecurityStatus>())
        {
            var name = status.ToString().ToLowerInvariant();
            var path = Path.Combine(outDir, $"filterplus-{name}.ico");

            ShieldRenderer.WriteIcoFile(path, ShieldRenderer.StatusColor(status), ShieldRenderer.MarkFor(status));
            Report(path);
        }

        // רצועת בדיקה: כל הסטטוסים בכל הגדלים שבהם Windows מציג אייקון.
        // הגודל 16 הוא המבחן האמיתי - שם צורות מורכבות מתמסמסות.
        var strip = Path.Combine(outDir, "preview-strip.png");
        WritePreviewStrip(strip);
        Report(strip);

        Console.WriteLine();
        Console.WriteLine("האייקונים נוצרו. הם משותפים עם אייקון המגש ועם התג הצף,");
        Console.WriteLine("ולכן שינוי ב-ShieldRenderer משנה את שלושתם יחד.");

        return 0;
    }

    /// <summary>מייצר לוח השוואה של כל הסטטוסים בכל הגדלים.</summary>
    private static void WritePreviewStrip(string path)
    {
        int[] sizes = [16, 24, 32, 48, 64];
        var statuses = Enum.GetValues<SecurityStatus>();

        const int pad = 16;
        var width = pad + sizes.Sum(s => s + pad);
        var height = pad + statuses.Length * (64 + pad);

        using var canvas = new System.Drawing.Bitmap(width, height);
        using var g = System.Drawing.Graphics.FromImage(canvas);

        // רקע בהיר, כי שם קווי מתאר בהירים מתקשים ביותר
        g.Clear(System.Drawing.Color.FromArgb(245, 246, 248));

        var y = pad;

        foreach (var status in statuses)
        {
            var x = pad;

            foreach (var size in sizes)
            {
                using var shield = ShieldRenderer.RenderShield(size, ShieldRenderer.StatusColor(status), ShieldRenderer.MarkFor(status));

                // יישור לתחתית השורה, כדי שההשוואה בין גדלים תהיה הוגנת
                g.DrawImage(shield, x, y + (64 - size));
                x += size + pad;
            }

            y += 64 + pad;
        }

        canvas.Save(path, System.Drawing.Imaging.ImageFormat.Png);
    }

    private static void Report(string path)
    {
        var size = new FileInfo(path).Length;
        Console.WriteLine($"  {Path.GetFileName(path),-26} {size,8:N0} בתים");
    }
}
