using System.IO;
using System.Windows;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using FilterPlus.Core.Models;
using FilterPlus.TrayApp.Services;
using Color = System.Windows.Media.Color;

namespace FilterPlus.TrayApp.Views;

/// <summary>
/// מרנדר את התג לקובץ תמונה, בלי להציג אותו על המסך.
///
/// מיועד לבדיקה ולתיעוד: מאפשר לראות בדיוק איך התג ייראה בכל סטטוס,
/// בלי לצלם מסך ובלי תלות ברמת ה-DPI של המכונה שמריצה.
///
/// הרצה: FilterPlus.TrayApp.exe --preview assets\badge-preview.png
/// </summary>
public static class BadgePreview
{
    /// <summary>רינדור בכפל 2, כדי שהתמונה תהיה חדה גם בתצוגה מוגדלת.</summary>
    private const double Dpi = 192;

    public static void Write(string path)
    {
        var statuses = Enum.GetValues<SecurityStatus>();
        var frames = new List<BitmapSource>();

        foreach (var status in statuses)
        {
            foreach (var collapsed in new[] { false, true })
                frames.Add(RenderOne(status, collapsed));
        }

        Compose(frames, statuses.Length, path);
    }

    private static BitmapSource RenderOne(SecurityStatus status, bool collapsed)
    {
        var badge = new StatusBadge(new StatusPoller(), previewOnly: true);

        var snapshot = new StatusSnapshot
        {
            Status = status,
            Score = status switch
            {
                SecurityStatus.Safe => 96,
                SecurityStatus.LowFilter => 71,
                SecurityStatus.Unfiltered => 24,
                _ => 0
            },
            ProviderDisplayName = status == SecurityStatus.Safe ? "נטפרי" : null,
            Headline = "תצוגה מקדימה"
        };

        return badge.RenderPreview(snapshot, collapsed, Dpi);
    }

    /// <summary>מסדר את הפריימים בשתי עמודות: מורחב ומכווץ.</summary>
    private static void Compose(IReadOnlyList<BitmapSource> frames, int rows, string path)
    {
        const int gap = 8;

        var expanded = frames.Where((_, i) => i % 2 == 0).ToList();
        var collapsed = frames.Where((_, i) => i % 2 == 1).ToList();

        var colWidth = expanded.Max(f => f.PixelWidth);
        var col2Width = collapsed.Max(f => f.PixelWidth);
        var rowHeight = expanded.Max(f => f.PixelHeight);

        var width = colWidth + col2Width + gap;
        var height = rows * rowHeight + (rows - 1) * gap;

        var visual = new DrawingVisual();

        using (var dc = visual.RenderOpen())
        {
            // רקע בהיר בינוני: בודק שהתג נקרא גם על רקע שאינו שחור ואינו לבן
            dc.DrawRectangle(
                new SolidColorBrush(Color.FromRgb(0x9A, 0xA5, 0xB1)),
                null,
                new Rect(0, 0, width, height));

            for (var i = 0; i < rows; i++)
            {
                var y = i * (rowHeight + gap);

                dc.DrawImage(expanded[i], new Rect(0, y, expanded[i].PixelWidth, expanded[i].PixelHeight));
                dc.DrawImage(collapsed[i],
                    new Rect(colWidth + gap, y, collapsed[i].PixelWidth, collapsed[i].PixelHeight));
            }
        }

        var target = new RenderTargetBitmap(width, height, 96, 96, PixelFormats.Pbgra32);
        target.Render(visual);

        var encoder = new PngBitmapEncoder();
        encoder.Frames.Add(BitmapFrame.Create(target));

        Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(path))!);

        using var stream = File.Create(path);
        encoder.Save(stream);
    }
}
