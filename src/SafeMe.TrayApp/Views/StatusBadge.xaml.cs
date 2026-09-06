using System.IO;
using System.Windows;
using System.Windows.Input;
using System.Windows.Interop;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using Microsoft.Win32;
using SafeMe.Core.Models;
using System.Windows.Threading;

using SafeMe.TrayApp.Rendering;
using SafeMe.TrayApp.Services;
using Color = System.Windows.Media.Color;
using Size = System.Windows.Size;

namespace SafeMe.TrayApp.Views;

/// <summary>
/// תג צף שנצמד לפינת המסך ומראה בכל רגע אם המחשב מוגן.
///
/// למה בנוסף לאייקון המגש: אייקון במגש מוסתר כברירת מחדל ב-Windows 11,
/// והמשתמש צריך ללחוץ על חץ כדי לראות אותו. עקרון הנראות המלאה
/// (סעיף 1.1 באפיון) מחייב שמצב ההגנה יהיה גלוי בלי שום פעולה.
///
/// התג אינו נועל את המשתמש: אפשר להזיז אותו בין הפינות ולכווץ אותו
/// למגן בלבד. מה שאי אפשר זה לסגור אותו לגמרי, כי אז אובד כל הערך.
/// </summary>
public partial class StatusBadge : Window
{
    /// <summary>מרחק מקצה שטח העבודה. מספיק כדי לא להיצמד לשורת המשימות.</summary>
    private const double Margin = 10;

    /// <summary>תזוזה קטנה מזו נחשבת לחיצה ולא לגרירה.</summary>
    private const double DragThreshold = 5;

    private readonly StatusPoller _poller;
    private readonly BadgeSettings _settings;

    private bool _shuttingDown;

    private readonly bool _previewOnly;

    public StatusBadge(StatusPoller poller, bool previewOnly = false)
    {
        InitializeComponent();

        _poller = poller;
        _previewOnly = previewOnly;
        _settings = previewOnly ? new BadgeSettings() : BadgeSettings.Load();

        ApplyCollapsedState();

        // במצב תצוגה מקדימה אין מנוי לאירועים ואין קיבוע מיקום:
        // החלון לעולם אינו מוצג, רק מרונדר לתמונה
        if (previewOnly)
        {
            Render(_poller.Current);
            return;
        }

        /*
         * המנוי נרשם לפני הציור הראשון, ולא אחריו.
         *
         * בסדר ההפוך נפתח חלון מרוץ: התג נוצר עם עליית התוכנה, לפני
         * שהשירות הספיק לענות, וצייר תמונה ריקה. אם התשובה הראשונה
         * הגיעה בין הציור להרשמה — היא אבדה, ולא הייתה עוד "שינוי"
         * שיפעיל ציור נוסף.
         *
         * זה מה שנראה בשטח: אחרי עדכון או אתחול התג עלה בלי שם
         * הספק, והופיע רק אחרי כיווץ והרחבה — כלומר רק אחרי שמשהו
         * אילץ ציור מחדש.
         */
        _poller.StatusChanged += OnStatusChanged;

        Render(_poller.Current);

        // שטח העבודה משתנה כשמחברים מסך, מסובבים אותו, או כששורת
        // המשימות עוברת צד. בלי זה התג נשאר תלוי באוויר.
        SystemEvents.DisplaySettingsChanged += OnDisplayChanged;

        /*
         * וציור נוסף כשהחלון נטען.
         *
         * רשת ביטחון למקרה שהתשובה הראשונה הגיעה בזמן שהחלון עוד
         * לא היה מוכן להציג. ציור מיותר עולה כלום.
         */
        Loaded += (_, _) =>
        {
            Render(_poller.Current);
            Reposition();
        };
        SizeChanged += (_, _) => Reposition();
    }

    /// <summary>
    /// מרנדר את התג לתמונה בלי להציג אותו. הפריסה מחושבת ידנית,
    /// כי חלון שלא הוצג מעולם אין לו גודל בפועל.
    /// </summary>
    internal BitmapSource RenderPreview(StatusSnapshot snapshot, bool collapsed, double dpi)
    {
        _settings.Collapsed = collapsed;

        ApplyCollapsedState();
        Render(snapshot);

        var root = (FrameworkElement)Content;

        root.Measure(new Size(double.PositiveInfinity, double.PositiveInfinity));
        root.Arrange(new Rect(root.DesiredSize));
        root.UpdateLayout();

        var scale = dpi / 96.0;

        var target = new RenderTargetBitmap(
            (int)Math.Ceiling(root.DesiredSize.Width * scale),
            (int)Math.Ceiling(root.DesiredSize.Height * scale),
            dpi, dpi, PixelFormats.Pbgra32);

        target.Render(root);
        target.Freeze();

        return target;
    }

    // ---------------------------------------------------------------- מיקום

    private void OnDisplayChanged(object? sender, EventArgs e) =>
        Dispatcher.BeginInvoke(Reposition);

    internal void Reposition()
    {
        /*
         * מדידה מחדש לפני חישוב המיקום.
         *
         * ActualWidth משקף את הפריסה האחרונה שהושלמה, ולא את מה
         * שהשתנה זה עתה. כיווץ והרחבה משנים את רוחב התג — ובלי
         * המדידה, המיקום חושב לפי הרוחב הקודם והתג נדחף אל מחוץ
         * לשטח הנראה.
         *
         * זו הייתה "ההיעלמות": הוא לא נסגר ולא קרס, הוא פשוט הוצב
         * במקום שאי אפשר לראות.
         */
        UpdateLayout();

        var area = SystemParameters.WorkArea;

        var onRight = _settings.Corner is BadgeCorner.BottomRight or BadgeCorner.TopRight;
        var onBottom = _settings.Corner is BadgeCorner.BottomRight or BadgeCorner.BottomLeft;

        var left = onRight ? area.Right - ActualWidth - Margin : area.Left + Margin;
        var top = onBottom ? area.Bottom - ActualHeight - Margin : area.Top + Margin;

        /*
         * ורשת ביטחון: התג לעולם אינו יוצא מהשטח הנראה.
         *
         * מדידה שגויה, מסך שנותק, או שינוי רזולוציה — כל אחד מהם
         * יכול לייצר מיקום שלילי או מעבר לקצה. חלון מצב שאי אפשר
         * לראות אינו חלון מצב, וההידוק הזה זול מכל אבחון.
         */
        Left = Clamp(left, area.Left, area.Right - ActualWidth);
        Top = Clamp(top, area.Top, area.Bottom - ActualHeight);
    }

    private static double Clamp(double value, double min, double max) =>
        max < min ? min : Math.Clamp(value, min, max);

    /// <summary>נצמד לפינה הקרובה ביותר למרכז התג לאחר גרירה.</summary>
    private void SnapToNearestCorner()
    {
        var area = SystemParameters.WorkArea;
        var centerX = Left + ActualWidth / 2;
        var centerY = Top + ActualHeight / 2;

        var right = centerX > (area.Left + area.Right) / 2;
        var bottom = centerY > (area.Top + area.Bottom) / 2;

        _settings.Corner = (right, bottom) switch
        {
            (true, true) => BadgeCorner.BottomRight,
            (false, true) => BadgeCorner.BottomLeft,
            (true, false) => BadgeCorner.TopRight,
            _ => BadgeCorner.TopLeft
        };

        _settings.Save();
        Reposition();
    }

    // ---------------------------------------------------------------- תצוגה

    private void OnStatusChanged(StatusSnapshot snapshot) =>
        Dispatcher.Invoke(() => Render(snapshot));

    private void Render(StatusSnapshot snapshot)
    {
        ShieldImage.Source = ToImageSource(snapshot.Status);
        StatusText.Text = TrayIconHost.StatusText(snapshot.Status);

        DetailText.Text = TrayText.BadgeDetail(snapshot);

        // גבול התג נצבע בצבע הסטטוס. זה מה שנקלט בעין הצידית,
        // עוד לפני שקוראים את הטקסט.
        var color = ShieldRenderer.StatusColor(snapshot.Status);

        Pill.BorderBrush = new SolidColorBrush(
            Color.FromArgb(0xB0, color.R, color.G, color.B));

        ToolTip = $"{TrayIconHost.StatusText(snapshot.Status)} — {snapshot.Headline}";
    }


    /// <summary>
    /// ממיר את המגן ל-ImageSource דרך PNG בזיכרון.
    ///
    /// הדרך הישירה, CreateBitmapSourceFromHBitmap, מחייבת שחרור ידני של
    /// ה-HBITMAP וזולגת בשקט אם שוכחים. כאן אין משאב לא מנוהל בכלל.
    /// </summary>
    private static ImageSource ToImageSource(SecurityStatus status)
    {
        using var bitmap = ShieldRenderer.RenderShield(64, ShieldRenderer.StatusColor(status));
        using var stream = new MemoryStream();

        bitmap.Save(stream, System.Drawing.Imaging.ImageFormat.Png);
        stream.Position = 0;

        var image = new BitmapImage();

        image.BeginInit();
        image.CacheOption = BitmapCacheOption.OnLoad;
        image.StreamSource = stream;
        image.EndInit();
        image.Freeze();

        return image;
    }

    private void ApplyCollapsedState()
    {
        TextPanel.Visibility = _settings.Collapsed ? Visibility.Collapsed : Visibility.Visible;
        Pill.Padding = _settings.Collapsed
            ? new Thickness(7)
            : new Thickness(9, 6, 14, 6);

        CollapseItem.Header = _settings.Collapsed ? "הרחב" : "כווץ";
    }

    // ---------------------------------------------------------------- אינטראקציה

    protected override void OnMouseLeftButtonDown(MouseButtonEventArgs e)
    {
        base.OnMouseLeftButtonDown(e);

        var startLeft = Left;
        var startTop = Top;

        try
        {
            // DragMove חוסם עד שחרור הכפתור, ולכן ההשוואה שאחריו
            // מבדילה בין גרירה ללחיצה
            DragMove();
        }
        catch (InvalidOperationException)
        {
            // קורה כשהכפתור שוחרר לפני שהגרירה התחילה
        }

        var moved = Math.Abs(Left - startLeft) + Math.Abs(Top - startTop);

        if (moved < DragThreshold)
        {
            ShowDetails();
            return;
        }

        SnapToNearestCorner();
    }

    private void OnShowDetails(object sender, RoutedEventArgs e) => ShowDetails();

    private void ShowDetails() => BadgeActions.ShowStatusWindow?.Invoke();

    private async void OnRunAudit(object sender, RoutedEventArgs e)
    {
        DetailText.Text = "מבצע בדיקה...";

        await _poller.RequestAuditAsync();
        await _poller.PollOnceAsync(CancellationToken.None);
    }

    private async void OnRefreshFromServer(object sender, RoutedEventArgs e)
    {
        DetailText.Text = "מרענן מול השרת...";

        var ok = await _poller.RequestRefreshAsync();

        if (!ok)
        {
            DetailText.Text = "השירות לא מגיב.";
            return;
        }

        // נותנים לפעימה לצאת ולחזור, ואז מרעננים את התצוגה.
        await Task.Delay(TimeSpan.FromSeconds(1.5));
        await _poller.PollOnceAsync(CancellationToken.None);
    }

    private void OnToggleCollapse(object sender, RoutedEventArgs e)
    {
        _settings.Collapsed = !_settings.Collapsed;
        _settings.Save();

        ApplyCollapsedState();

        /*
         * הטקסט מצויר מחדש בהרחבה.
         *
         * במצב מכווץ הוא מוסתר, ולכן עדכוני מצב שהגיעו בזמן הזה
         * כתבו לתוך רכיב שאיש לא רואה. בלי הציור הזה, ההרחבה הייתה
         * מגלה את מה שהיה נכון בפעם האחרונה שהתג היה פתוח.
         */
        Render(_poller.Current);

        // Loaded ולא Normal: המדידה מחדש חייבת להסתיים לפני שמחשבים
        // מיקום שמסתמך עליה
        Dispatcher.BeginInvoke(DispatcherPriority.Loaded, Reposition);
    }

    private void OnFlipSide(object sender, RoutedEventArgs e)
    {
        _settings.Corner = _settings.Corner switch
        {
            BadgeCorner.BottomRight => BadgeCorner.BottomLeft,
            BadgeCorner.BottomLeft => BadgeCorner.BottomRight,
            BadgeCorner.TopRight => BadgeCorner.TopLeft,
            _ => BadgeCorner.TopRight
        };

        _settings.Save();
        Reposition();
    }

    // ---------------------------------------------------------------- סגירה

    /// <summary>מאפשר סגירה אמיתית רק כשהאפליקציה כולה נסגרת.</summary>
    public void ShutdownAndClose()
    {
        _shuttingDown = true;
        Close();
    }

    protected override void OnClosing(System.ComponentModel.CancelEventArgs e)
    {
        // Alt+F4 על התג לא אמור להעלים את מחוון ההגנה. במקום זאת
        // הוא מכווץ אותו למגן בלבד — פשרה בין נראות לבין שליטת המשתמש.
        if (!_shuttingDown)
        {
            e.Cancel = true;

            if (!_settings.Collapsed)
            {
                _settings.Collapsed = true;
                _settings.Save();

                ApplyCollapsedState();
                Dispatcher.BeginInvoke(Reposition);
            }

            return;
        }

        _poller.StatusChanged -= OnStatusChanged;
        SystemEvents.DisplaySettingsChanged -= OnDisplayChanged;

        base.OnClosing(e);
    }

    /// <summary>
    /// מונע מהתג להופיע ברשימת Alt+Tab. חלון כלי אינו נכלל בה,
    /// ואין סיבה שמחוון סטטוס יופיע כחלון לכל דבר.
    /// </summary>
    protected override void OnSourceInitialized(EventArgs e)
    {
        base.OnSourceInitialized(e);

        var handle = new WindowInteropHelper(this).Handle;
        var style = NativeMethods.GetWindowLong(handle, NativeMethods.GWL_EXSTYLE);

        NativeMethods.SetWindowLong(
            handle,
            NativeMethods.GWL_EXSTYLE,
            style | NativeMethods.WS_EX_TOOLWINDOW | NativeMethods.WS_EX_NOACTIVATE);
    }
}

/// <summary>גשר בין התג לבין שאר האפליקציה, בלי תלות הדדית בין המחלקות.</summary>
public static class BadgeActions
{
    public static Action? ShowStatusWindow { get; set; }
}

internal static partial class NativeMethods
{
    public const int GWL_EXSTYLE = -20;
    public const int WS_EX_TOOLWINDOW = 0x00000080;
    public const int WS_EX_NOACTIVATE = 0x08000000;

    [System.Runtime.InteropServices.LibraryImport("user32.dll", EntryPoint = "GetWindowLongW")]
    public static partial int GetWindowLong(IntPtr hWnd, int nIndex);

    [System.Runtime.InteropServices.LibraryImport("user32.dll", EntryPoint = "SetWindowLongW")]
    public static partial int SetWindowLong(IntPtr hWnd, int nIndex, int dwNewLong);
}
