using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using SafeMe.Core.Models;
using SafeMe.TrayApp.Services;
using Brush = System.Windows.Media.Brush;

namespace SafeMe.TrayApp.Views;

/// <summary>
/// חלון הסטטוס. תצוגה בלבד: אין בו שום פעולת אכיפה או שינוי מדיניות.
/// המטרה שהמשתמש יראה בכל רגע מה נבדק, מה עבר ומה נכשל.
/// </summary>
public partial class StatusWindow : Window
{
    private readonly StatusPoller _poller;

    public StatusWindow(StatusPoller poller)
    {
        InitializeComponent();

        _poller = poller;
        _poller.StatusChanged += OnStatusChanged;

        Render(_poller.Current);
    }

    private void OnStatusChanged(StatusSnapshot snapshot) =>
        Dispatcher.Invoke(() => Render(snapshot));

    private void Render(StatusSnapshot snapshot)
    {
        var color = ToBrush(snapshot.Status);

        /*
         * הכותרת אומרת דרך מה המחשב יוצא.
         *
         * "מצב החיבור" לבדו אינו אומר דבר, והכותרת היא מה שנראה
         * בשורת המשימות וב-Alt+Tab — כלומר במקומות שבהם המשתמש
         * מסתכל בלי לפתוח.
         */
        Title = snapshot.ProviderDisplayName is { } provider
            ? $"SafeMe — {TrayIconHost.StatusText(snapshot.Status)} דרך {provider}"
            : $"SafeMe — {TrayIconHost.StatusText(snapshot.Status)}";

        StatusDot.Fill = color;
        StatusTitle.Text = TrayIconHost.StatusText(snapshot.Status);
        StatusTitle.Foreground = color;
        Headline.Text = snapshot.Headline;

        RenderScore(snapshot, color);
        RenderDetails(snapshot);
        RenderFailures(snapshot);

        FooterText.Text = snapshot.LastAuditUtc is { } audited
            ? $"נבדק לאחרונה: {audited.ToLocalTime():HH:mm}"
            : "עוד לא נבדק";
    }

    private void RenderScore(StatusSnapshot snapshot, Brush color)
    {
        var score = Math.Clamp(snapshot.Score, 0, 100);

        // היחס נמדד מול המסלול עצמו. חישוב מרוחב החלון היה צריך לנחש
        // כמה תופסים התווית והשוליים, והניחוש היה שגוי בכל רוחב.
        ScoreFilled.Width = new GridLength(score, GridUnitType.Star);
        ScoreEmpty.Width = new GridLength(100 - score, GridUnitType.Star);

        ScoreBar.Background = color;

        /*
         * ציון אפס אינו היעדר נתונים.
         *
         * בדיקה שרצה ולא מצאה סינון מחזירה אפס, וזו תשובה — ההפך
         * הגמור מ"עוד לא נבדק". הצגתם כאותו דבר הסתירה בדיוק את המצב
         * שהמוצר קיים כדי להתריע עליו.
         */
        ScoreText.Text = snapshot.Status == SecurityStatus.Unknown
            ? "אין נתוני בדיקה"
            : $"{score} מתוך 100";
    }

    private void RenderDetails(StatusSnapshot snapshot)
    {
        DetailsPanel.Children.Clear();

        AddRow("ספק סינון", snapshot.ProviderDisplayName ?? snapshot.ProviderId ?? "לא זוהה");
        AddRow("רמת ביטחון בזיהוי", TrustText(snapshot.ProviderTrust));
        AddRow("רמת הסינון בחשבון", LevelText(snapshot));
        AddRow("רשת פעילה", BuildNetworkText(snapshot));
        AddRow("כתובת ציבורית", snapshot.PublicIp ?? "לא ידועה");
        AddRow("מצב אכיפה", EnforcementText(snapshot.Enforcement));
        AddRow("גרסת SafeMe", snapshot.AgentVersion);
        AddRow("גרסת מדיניות", snapshot.PolicyVersion > 0 ? snapshot.PolicyVersion.ToString() : "עוד לא התקבלה");
        AddRow("חוקי רשת פעילים", snapshot.WfpFilterCount.ToString());

        if (snapshot.LockoutActive)
            AddRow("סיבת הנעילה", snapshot.LockoutReason ?? "לא צוינה");

        if (!snapshot.LicenseValid)
            AddRow("רישיון", "פג תוקף");
    }

    private void RenderFailures(StatusSnapshot snapshot)
    {
        FailureList.ItemsSource = snapshot.FailedProbes;

        var hasFailures = snapshot.FailedProbes.Count > 0;

        NoFailures.Visibility = hasFailures ? Visibility.Collapsed : Visibility.Visible;
        FailureList.Visibility = hasFailures ? Visibility.Visible : Visibility.Collapsed;
    }

    private void AddRow(string label, string value)
    {
        var grid = new Grid { Margin = new Thickness(0, 0, 0, 8) };

        grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(130) });
        grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });

        var labelBlock = new TextBlock
        {
            Text = label,
            FontSize = 12,
            Foreground = (Brush)FindResource("FgMuted")
        };

        var valueBlock = new TextBlock
        {
            Text = value,
            FontSize = 12,
            TextWrapping = TextWrapping.Wrap,
            Foreground = (Brush)FindResource("Fg")
        };

        Grid.SetColumn(labelBlock, 0);
        Grid.SetColumn(valueBlock, 1);

        grid.Children.Add(labelBlock);
        grid.Children.Add(valueBlock);

        DetailsPanel.Children.Add(grid);
    }

    private static string BuildNetworkText(StatusSnapshot snapshot)
    {
        if (snapshot.WifiSsid is { } ssid) return $"{snapshot.ActiveAdapter} ({ssid})";

        return snapshot.ActiveAdapter ?? "לא ידועה";
    }

    /// <summary>
    /// רמת הסינון כפי שהספק מדווח.
    ///
    /// בלי פרשנות. היה כאן תרגום למילים, והוא הומצא ולא נבדק מול
    /// הדרגות שרימון מציגה — חשבון "בסיסי" הוצג כ"סינון מחמיר",
    /// כלומר ההפך.
    ///
    /// "לא נקראה" אינו "אין סינון": הראשון הוא מה שלא ידוע, השני
    /// הוא מסקנה.
    /// </summary>
    private static string LevelText(StatusSnapshot snapshot)
    {
        if (snapshot.FilterLevel is not { } level) return "לא נקראה";

        return TrayText.LevelAsReported(level);
    }

    private static string TrustText(TrustLevel trust) => trust switch
    {
        TrustLevel.High => "גבוהה — זוהה בשתי דרכים ומעלה",
        TrustLevel.Medium => "בינונית — זוהה בדרך אחת",
        TrustLevel.Low => "נמוכה",
        _ => "אין זיהוי"
    };

    private static string EnforcementText(EnforcementMode mode) => mode switch
    {
        EnforcementMode.Enforce => "אכיפה מלאה",
        EnforcementMode.Warn => "התראה בלבד",
        _ => "ניטור בלבד"
    };

    private Brush ToBrush(SecurityStatus status) => status switch
    {
        SecurityStatus.Safe => (Brush)FindResource("StatusSafe"),
        SecurityStatus.LowFilter => (Brush)FindResource("StatusLow"),
        SecurityStatus.Unfiltered => (Brush)FindResource("StatusBad"),
        SecurityStatus.Blocked => (Brush)FindResource("StatusGray"),
        _ => (Brush)FindResource("StatusGray")
    };

    private async void OnAuditClick(object sender, RoutedEventArgs e)
    {
        AuditButton.IsEnabled = false;
        FooterText.Text = "בודק…";

        try
        {
            await _poller.RequestAuditAsync();
            await _poller.PollOnceAsync(CancellationToken.None);
        }
        finally
        {
            AuditButton.IsEnabled = true;
        }
    }

    private async void OnRefreshClick(object sender, RoutedEventArgs e)
    {
        RefreshButton.IsEnabled = false;
        FooterText.Text = "מרענן מול השרת…";

        try
        {
            var ok = await _poller.RequestRefreshAsync();

            if (!ok)
            {
                FooterText.Text = "אי אפשר לרענן עכשיו — השירות לא מגיב.";
                return;
            }

            // נותנים לפעימה לצאת ולחזור, ואז מרעננים את התצוגה.
            await Task.Delay(TimeSpan.FromSeconds(1.5));
            await _poller.PollOnceAsync(CancellationToken.None);
            FooterText.Text = "עודכן מהשרת.";
        }
        finally
        {
            RefreshButton.IsEnabled = true;
        }
    }

    private void OnCloseClick(object sender, RoutedEventArgs e) => Close();

    protected override void OnClosed(EventArgs e)
    {
        _poller.StatusChanged -= OnStatusChanged;
        base.OnClosed(e);
    }
}
