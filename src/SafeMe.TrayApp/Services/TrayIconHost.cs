using System.Drawing;
using System.Drawing.Drawing2D;
using System.Runtime.InteropServices;
using System.Windows;
using SafeMe.Core.Models;
using SafeMe.TrayApp.Rendering;
using SafeMe.TrayApp.Views;
using Application = System.Windows.Application;
using MessageBox = System.Windows.MessageBox;

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
            if (_window is { IsLoaded: true })
            {
                _window.Activate();
                _window.WindowState = WindowState.Normal;

                return;
            }

            _window = new StatusWindow(_poller);
            _window.Show();
        });
    }

    private async Task RunAuditAsync()
    {
        _icon.ShowBalloonTip(3000, "SafeMe", "מבצע בדיקת חיבור...", ToolTipIcon.Info);

        var report = await _poller.RequestAuditAsync();

        if (report is null)
        {
            _icon.ShowBalloonTip(4000, "SafeMe", "לא ניתן לבצע בדיקה. השירות אינו מגיב.", ToolTipIcon.Warning);
            return;
        }

        await _poller.PollOnceAsync(CancellationToken.None);

        _icon.ShowBalloonTip(4000, "SafeMe", report.Headline, ToolTipIcon.Info);
    }

    private void ShowAbout() =>
        MessageBox.Show(
            "SafeMe — סוכן אכיפת גלישה בטוחה\n\n" +
            "הסוכן מוודא שהמחשב מחובר לחיבור אינטרנט מסונן ומאושר.\n" +
            "להסרת התוכנה נדרש קוד חד-פעמי מהמוקד.",
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
            var tooltip = $"SafeMe — {StatusText(snapshot.Status)}\n{snapshot.Headline}";
            _icon.Text = tooltip.Length > 62 ? tooltip[..62] : tooltip;

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
            SecurityStatus.Unfiltered => ("החיבור אינו מסונן", ToolTipIcon.Error),
            SecurityStatus.LowFilter => ("הסינון חלקי", ToolTipIcon.Warning),
            SecurityStatus.Blocked => ("נעילת חירום פעילה", ToolTipIcon.Warning),
            SecurityStatus.Unknown => ("מצב ההגנה אינו ידוע", ToolTipIcon.Warning),
            _ => ("", ToolTipIcon.Info)
        };

        if (string.IsNullOrEmpty(title)) return;

        _icon.ShowBalloonTip(6000, $"SafeMe — {title}", snapshot.Headline, icon);
    }

    public static string StatusText(SecurityStatus status) => status switch
    {
        SecurityStatus.Safe => "מוגן",
        SecurityStatus.LowFilter => "סינון חלקי",
        SecurityStatus.Unfiltered => "אינו מסונן",
        SecurityStatus.Blocked => "חסום",
        _ => "לא ידוע"
    };

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
