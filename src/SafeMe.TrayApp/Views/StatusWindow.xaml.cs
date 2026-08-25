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

        StatusDot.Fill = color;
        StatusTitle.Text = TrayIconHost.StatusText(snapshot.Status);
        StatusTitle.Foreground = color;
        Headline.Text = snapshot.Headline;

        RenderScore(snapshot, color);
        RenderDetails(snapshot);
        RenderFailures(snapshot);

        FooterText.Text = snapshot.LastAuditUtc is { } audited
            ? $"נבדק לאחרונה: {audited.ToLocalTime():HH:mm}"
            : "טרם בוצעה בדיקה";
    }

    private void RenderScore(StatusSnapshot snapshot, Brush color)
    {
        // רוחב הפס נגזר מרוחב החלון, ולכן מחושב יחסית ולא בערך קבוע
        var available = Math.Max(0, ActualWidth - 190);

        ScoreBar.Width = available * Math.Clamp(snapshot.Score / 100.0, 0, 1);
        ScoreBar.Background = color;

        ScoreText.Text = snapshot.Score > 0
            ? $"{snapshot.Score} מתוך 100"
            : "אין נתוני בדיקה";
    }

    private void RenderDetails(StatusSnapshot snapshot)
    {
        DetailsPanel.Children.Clear();

        AddRow("ספק סינון", snapshot.ProviderDisplayName ?? snapshot.ProviderId ?? "לא זוהה");
        AddRow("רמת ביטחון בזיהוי", TrustText(snapshot.ProviderTrust));
        AddRow("רשת פעילה", BuildNetworkText(snapshot));
        AddRow("כתובת ציבורית", snapshot.PublicIp ?? "לא ידועה");
        AddRow("מצב אכיפה", EnforcementText(snapshot.Enforcement));
        AddRow("גרסת מדיניות", snapshot.PolicyVersion > 0 ? snapshot.PolicyVersion.ToString() : "טרם התקבלה");
        AddRow("חוקי רשת פעילים", snapshot.WfpFilterCount.ToString());

        if (snapshot.LockoutActive)
            AddRow("סיבת הנעילה", snapshot.LockoutReason ?? "לא צוינה");

        if (!snapshot.LicenseValid)
            AddRow("רישיון", "אינו בתוקף");
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

    private static string TrustText(TrustLevel trust) => trust switch
    {
        TrustLevel.High => "גבוהה (שני וקטורים ומעלה)",
        TrustLevel.Medium => "בינונית (וקטור אחד)",
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
        FooterText.Text = "מבצע בדיקה...";

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

    private void OnCloseClick(object sender, RoutedEventArgs e) => Close();

    protected override void OnClosed(EventArgs e)
    {
        _poller.StatusChanged -= OnStatusChanged;
        base.OnClosed(e);
    }
}
