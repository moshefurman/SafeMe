using System.Drawing;
using System.Drawing.Drawing2D;
using System.Runtime.InteropServices;
using System.Windows;
using SafeMe.Core.Models;
using SafeMe.TrayApp.Rendering;
using SafeMe.TrayApp.Views;
using Application = System.Windows.Application;
using MessageBox = System.Windows.MessageBox;
using MouseButtons = System.Windows.Forms.MouseButtons;

namespace SafeMe.TrayApp.Services;

/// <summary>
/// מנהל את אייקון המגש: צבע לפי סטטוס, תפריט בעברית, והתראות על שינוי מצב.
///
/// האייקונים מצוירים בקוד ולא נטענים מקבצים, כדי שלא תהיה תלות במשאבים
/// חיצוניים שאפשר למחוק.
/// </summary>
public sealed partial class TrayIconHost : IDisposable
{
    private readonly NotifyIcon _icon;
    private readonly StatusPoller _poller;
    private readonly Dictionary<SecurityStatus, Icon> _icons = new();

    private StatusWindow? _window;
    private SecurityStatus _lastStatus = SecurityStatus.Unknown;

    public TrayIconHost(StatusPoller poller)
    {
        _poller = poller;

        BuildIcons();

        _icon = new NotifyIcon
        {
            Icon = _icons[SecurityStatus.Unknown],
            Visible = true,
            Text = "SafeMe",
            ContextMenuStrip = BuildMenu()
        };

        /*
         * לחיצה בודדת, לא רק כפולה.
         *
         * אייקון מגש הוא כפתור: אדם לוחץ עליו פעם אחת ומצפה שייפתח.
         * לחיצה כפולה בלבד נראית כמו תוכנה שלא הגיבה, והמשתמש לוחץ
         * שוב — כלומר מקבל לחיצה כפולה במקרה, ולא מפני שידע.
         *
         * MouseClick ולא Click, כדי להבדיל בין הכפתור השמאלי לימני:
         * הימני פותח את התפריט, ושניהם יחד היו נפתחים בבת אחת.
         */
        _icon.MouseClick += (_, e) =>
        {
            if (e.Button == MouseButtons.Left) ShowStatusWindow();
        };

        _icon.DoubleClick += (_, _) => ShowStatusWindow();

        _poller.StatusChanged += OnStatusChanged;
    }

    // ------------------------------------------------------------ תפריט

    private ContextMenuStrip BuildMenu()
    {
        var menu = new ContextMenuStrip
        {
            RightToLeft = RightToLeft.Yes,
            ShowImageMargin = false
        };

        menu.Items.Add("הצג מצב חיבור", null, (_, _) => ShowStatusWindow());
        menu.Items.Add("בדוק עכשיו", null, async (_, _) => await RunAuditAsync());
        menu.Items.Add(new ToolStripSeparator());
        menu.Items.Add("אודות SafeMe", null, (_, _) => ShowAbout());

        return menu;
    }

    public void ShowStatusWindow()
    {
        Application.Current.Dispatcher.Invoke(() =>
        {
            if (_window is not { IsLoaded: true })
            {
                _window = new StatusWindow(_poller);
                _window.Show();
            }

            BringToFront(_window);
        });
    }

    /// <summary>
    /// מביא את החלון לחזית באמת.
    ///
    /// Activate לבדו אינו מספיק, ובכוונת Windows: מערכת ההפעלה מונעת
    /// מתהליך שאינו בחזית לגנוב את הפוקוס, כדי שחלונות לא יקפצו
    /// באמצע הקלדה. התוצאה כאן הייתה חלון שנפתח בשורת המשימות
    /// ומהבהב, במקום להיפתח מול המשתמש שהרגע לחץ עליו.
    ///
    /// הרמת Topmost לרגע ושחרורה מיד היא הדרך המקובלת לעקוף את זה
    /// בלי P/Invoke: היא מציבה את החלון מעל, והורדתה מיד אחר כך
    /// מחזירה אותו להתנהגות רגילה כדי שלא יישאר תקוע מעל הכול.
    ///
    /// הסדר חשוב: קודם משחזרים ממוזער, אחר כך מציגים, ורק אז
    /// מפעילים. הפעלה על חלון ממוזער אינה עושה דבר.
    /// </summary>
    private static void BringToFront(Window window)
    {
        if (window.WindowState == WindowState.Minimized)
            window.WindowState = WindowState.Normal;

        window.Show();

        var wasTopmost = window.Topmost;

        window.Topmost = true;
        window.Topmost = wasTopmost;

        window.Activate();
        window.Focus();
    }

    private async Task RunAuditAsync()
    {
        _icon.ShowBalloonTip(3000, "SafeMe", "בודק את החיבור…", ToolTipIcon.Info);

        var report = await _poller.RequestAuditAsync();

        if (report is null)
        {
            _icon.ShowBalloonTip(4000, "SafeMe", "אי אפשר לבדוק עכשיו — השירות לא מגיב.", ToolTipIcon.Warning);
            return;
        }

        await _poller.PollOnceAsync(CancellationToken.None);

        _icon.ShowBalloonTip(4000, "SafeMe", report.Headline, ToolTipIcon.Info);
    }

    private void ShowAbout() =>
        MessageBox.Show(
            "SafeMe — שמירה על גלישה מסוננת\n\n" +
            "SafeMe בודק שהמחשב מחובר דרך אינטרנט מסונן ומאושר.\n" +
            "כדי להסיר את התוכנה צריך קוד חד-פעמי מהמוקד.",
            "אודות SafeMe",
            MessageBoxButton.OK,
            MessageBoxImage.Information);

    // ------------------------------------------------------------ סטטוס

    private void OnStatusChanged(StatusSnapshot snapshot)
    {
        try
        {
            _icon.Icon = _icons[snapshot.Status];

            // מגבלת מערכת: הטקסט של אייקון מגש מוגבל ל-63 תווים
            _icon.Text = TrayText.Tooltip(snapshot);

            if (snapshot.Status != _lastStatus)
            {
                NotifyStatusChange(snapshot);
                _lastStatus = snapshot.Status;
            }
        }
        catch (Exception)
        {
            // אייקון המגש עשוי להיות בתהליך סגירה
        }
    }

    /// <summary>
    /// מתריע רק על הרעה במצב. שיפור אינו מצדיק הפרעה למשתמש.
    /// </summary>
    private void NotifyStatusChange(StatusSnapshot snapshot)
    {
        var (title, icon) = snapshot.Status switch
        {
            SecurityStatus.Unfiltered => ("החיבור לא מסונן", ToolTipIcon.Error),
            SecurityStatus.LowFilter => ("הסינון חלקי", ToolTipIcon.Warning),
            SecurityStatus.Blocked => ("נעילת חירום פעילה", ToolTipIcon.Warning),
            SecurityStatus.Unknown => ("לא ידוע מה מצב ההגנה", ToolTipIcon.Warning),
            _ => ("", ToolTipIcon.Info)
        };

        if (string.IsNullOrEmpty(title)) return;

        _icon.ShowBalloonTip(6000, $"SafeMe — {title}", snapshot.Headline, icon);
    }


    /*
     * הניסוח יושב ב-Core.
     *
     * הוא לוגיקה טהורה, והוא המקום היחיד שההורה קורא בלי שביקש —
     * ולכן דווקא הוא צריך להיות נבדק. פרויקט הבדיקות אינו יכול
     * להפנות ל-TrayApp בלי להתנגש ב-Application היחיד לכל AppDomain
     * שעליו רצות בדיקות האינסטולר.
     */
    public static string StatusText(SecurityStatus status) => TrayText.Status(status);

    public static Color StatusColor(SecurityStatus status) => ShieldRenderer.StatusColor(status);

    // ------------------------------------------------------------ ציור

    /// <summary>
    /// מצייר אייקון לכל סטטוס פעם אחת ושומר במטמון.
    /// הציור עצמו ב-ShieldRenderer, המשותף עם אייקון התוכנה ועם התג הצף.
    /// </summary>
    private void BuildIcons()
    {
        foreach (SecurityStatus status in Enum.GetValues<SecurityStatus>())
            _icons[status] = ShieldRenderer.RenderStatusIcon(status, 32);
    }

    public void Dispose()
    {
        _poller.StatusChanged -= OnStatusChanged;

        _icon.Visible = false;
        _icon.Dispose();

        foreach (var icon in _icons.Values)
            icon.Dispose();
    }
}
