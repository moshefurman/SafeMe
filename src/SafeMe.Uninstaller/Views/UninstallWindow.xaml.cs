using System.Diagnostics;
using System.IO;
using System.Text;
using System.Windows;
using System.Windows.Media;
using SafeMe.Core.Ipc;

namespace SafeMe.Uninstaller.Views;

/// <summary>
/// מסך ההסרה. חשוב להבין את גבולות האחריות שלו: המסך אינו מאמת דבר.
/// הוא מציג אתגר שהופק על ידי השירות, ומעביר את הקוד שהמשתמש הקליד
/// לאימות בתוך השירות שרץ כ-SYSTEM. החלפת המסך אינה מקנה שום יתרון לתוקף.
/// </summary>
public partial class UninstallWindow : Window
{
    private readonly IpcClient _client = new();

    private string? _challenge;
    private DateTimeOffset? _expiresUtc;

    public UninstallWindow()
    {
        InitializeComponent();
        Loaded += OnLoaded;
    }

    private async void OnLoaded(object sender, RoutedEventArgs e)
    {
        if (!await _client.IsServiceAliveAsync())
        {
            ShowMessage(
                "שירות SafeMe אינו פעיל. יש להפעילו לפני ההסרה. " +
                "אם השירות אינו עולה, פנו לתמיכה.",
                isError: true);

            GenerateButton.IsEnabled = false;

            return;
        }

        await RefreshLockoutStateAsync();

        /*
         * הקוד מופק מיד, בלי להמתין ללחיצה.
         *
         * מי שפתח את מסך ההסרה כבר ביקש להסיר — אין שום החלטה
         * מאחורי הכפתור, רק צעד נוסף. הוא נשאר במסך כדי להפיק קוד
         * חדש אחרי שהקודם פג, וזה השימוש היחיד שיש לו.
         *
         * לא כשהמחשב נעול: שם ההודעה כבר מסבירה מה קורה, וניסיון
         * אוטומטי היה מחליף אותה בשגיאה ומעלה את מונה הניסיונות
         * בלי שאיש ביקש דבר.
         */
        if (GenerateButton.IsEnabled) await IssueChallengeAsync();
    }

    // ------------------------------------------------------------ שלב 1

    private async void OnGenerateClick(object sender, RoutedEventArgs e) =>
        await IssueChallengeAsync();

    private async Task IssueChallengeAsync()
    {
        GenerateButton.IsEnabled = false;
        HideMessage();

        try
        {
            var result = await _client.SendAsync<UninstallChallengeResult>(
                IpcOps.UninstallChallenge, new UninstallChallengePayload { Reason = "בקשת משתמש" });

            if (result is null)
            {
                ShowMessage("לא התקבלה תשובה מהשירות.", isError: true);
                return;
            }

            _challenge = result.Challenge;
            _expiresUtc = result.ExpiresUtc;

            ChallengeBox.Text = result.Challenge;
            CopyButton.IsEnabled = true;
            ExpiryText.Text = $"בתוקף עד {result.ExpiresUtc.ToLocalTime():HH:mm}";

            ModeHint.Text = result.Mode.Equals("Rsa", StringComparison.OrdinalIgnoreCase)
                ? "קוד ההסרה ארוך. הדביקו אותו במלואו בשדה למעלה."
                : "קוד ההסרה הוא 24 תווים בארבע קבוצות. ניתן להקליד עם או בלי מקפים.";

            UpdateVerifyButton();
        }
        catch (Exception ex)
        {
            // הודעת השירות כבר מנוסחת בעברית וכוללת את סיבת הדחייה
            ShowMessage(ex.Message, isError: true);
        }
        finally
        {
            GenerateButton.IsEnabled = true;
        }
    }

    private void OnCopyClick(object sender, RoutedEventArgs e)
    {
        if (string.IsNullOrWhiteSpace(_challenge)) return;

        try
        {
            Clipboard.SetText(_challenge);
            ShowMessage("קוד הזיהוי הועתק.", isError: false);
        }
        catch (Exception)
        {
            // לוח ההעתקה עלול להיות נעול על ידי יישום אחר
            ShowMessage("לא ניתן להעתיק. סמנו את הקוד והעתיקו ידנית.", isError: true);
        }
    }

    // ------------------------------------------------------------ שלב 2

    private void OnResponseChanged(object sender, System.Windows.Controls.TextChangedEventArgs e) =>
        UpdateVerifyButton();

    private void UpdateVerifyButton() =>
        VerifyButton.IsEnabled =
            !string.IsNullOrWhiteSpace(_challenge) &&
            ResponseBox.Text.Trim().Length >= 8;

    private async void OnVerifyClick(object sender, RoutedEventArgs e)
    {
        if (string.IsNullOrWhiteSpace(_challenge)) return;

        VerifyButton.IsEnabled = false;
        HideMessage();

        try
        {
            var result = await _client.SendAsync<UninstallVerifyResult>(
                IpcOps.UninstallVerify,
                new UninstallVerifyPayload
                {
                    Challenge = _challenge,
                    Response = ResponseBox.Text.Trim()
                });

            if (result is null)
            {
                ShowMessage("לא התקבלה תשובה מהשירות.", isError: true);
                return;
            }

            if (result.Granted)
            {
                /*
                 * מסירים כאן ועכשיו.
                 *
                 * הכפתור אומר "אמת והסר", והמסך היה מאמת ומבקש מהמשתמש
                 * לסגור אותו ולהריץ סקריפט בעצמו — ואם פתח אותו שוב הוא
                 * נתבקש קוד חדש, כי האישור נכתב ואיש לא פעל לפיו.
                 *
                 * שלב ידני בין האימות לביצוע אינו מוסיף שום הגנה: האישור
                 * כבר ניתן, והסקריפט אינו בודק דבר מעבר לו. הוא רק מוסיף
                 * דרך להיתקע.
                 */
                ResponseBox.IsEnabled = false;
                GenerateButton.IsEnabled = false;
                CopyButton.IsEnabled = false;
                AttemptsText.Text = "";

                await RemoveAsync();

                return;
            }

            ShowMessage(result.Message, isError: true);

            AttemptsText.Text = result.LockoutUntil is { } until
                ? $"נעול עד {until.ToLocalTime():HH:mm}"
                : $"נותרו {result.AttemptsLeft} ניסיונות";

            if (result.LockoutUntil is not null)
            {
                ResponseBox.IsEnabled = false;
                GenerateButton.IsEnabled = false;
            }
        }
        catch (Exception ex)
        {
            ShowMessage(ex.Message, isError: true);
        }
        finally
        {
            UpdateVerifyButton();
        }
    }

    private void OnCancelClick(object sender, RoutedEventArgs e) => Close();

    // ------------------------------------------------------------ עזר

    /// <summary>
    /// מריץ את ההסרה בפועל ומדווח מה קרה.
    ///
    /// המסך רץ כמנהל מערכת ממילא, ולכן אין צורך בהעלאת הרשאות נוספת.
    /// הפלט נלכד ולא מוצג בחלון קונסול: הסקריפט מדפיס עברית, וחלון
    /// שקופץ ונסגר אינו מקום שאפשר לקרוא בו שגיאה.
    /// </summary>
    private async Task RemoveAsync()
    {
        var script = Path.Combine(AppContext.BaseDirectory, "uninstall.ps1");

        if (!File.Exists(script))
        {
            ShowMessage(
                $"ההסרה אושרה, אך לא נמצא קובץ ההסרה:\n{script}\nפנו לתמיכה.",
                isError: true);

            return;
        }

        ShowMessage("הקוד אומת. מסיר את SafeMe...", isError: false);

        var info = new ProcessStartInfo
        {
            FileName = "powershell.exe",
            UseShellExecute = false,
            CreateNoWindow = true,

            /*
             * ספריית עבודה מחוץ לתיקיית ההתקנה.
             *
             * תהליך בן יורש את ספריית העבודה שלנו, ואנחנו רצים מתוך
             * מה שמוחקים — כלומר PowerShell היה מחזיק את התיקייה
             * פתוחה ו-rmdir היה נכשל ב-"because it is in use".
             *
             * נצפה בדיוק כך כשקונסולה נשארה פתוחה בתיקייה.
             */
            WorkingDirectory = Environment.GetFolderPath(Environment.SpecialFolder.System),
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            StandardOutputEncoding = Encoding.UTF8,
            StandardErrorEncoding = Encoding.UTF8
        };

        info.ArgumentList.Add("-NoProfile");
        info.ArgumentList.Add("-ExecutionPolicy");
        info.ArgumentList.Add("Bypass");
        info.ArgumentList.Add("-File");
        info.ArgumentList.Add(script);

        try
        {
            using var process = Process.Start(info)
                ?? throw new InvalidOperationException("לא ניתן להפעיל את תהליך ההסרה.");

            var stdout = process.StandardOutput.ReadToEndAsync();
            var stderr = process.StandardError.ReadToEndAsync();

            await process.WaitForExitAsync();

            if (process.ExitCode != 0)
            {
                var detail = (await stderr).Trim();

                if (detail.Length == 0) detail = (await stdout).Trim();

                ShowMessage(
                    "ההסרה לא הושלמה.\n" +
                    (detail.Length > 0 ? detail : $"קוד יציאה {process.ExitCode}."),
                    isError: true);

                return;
            }
        }
        catch (Exception ex)
        {
            ShowMessage($"ההסרה לא הושלמה: {ex.Message}", isError: true);
            return;
        }

        ShowMessage("SafeMe הוסר מהמחשב. החלון ייסגר.", isError: false);
        VerifyButton.IsEnabled = false;

        /*
         * שהייה קצרה כדי שההודעה תיקרא, ואז סגירה.
         *
         * הסקריפט מוחק את תיקיית ההתקנה חמש שניות אחרי שהתהליך הזה
         * מת — ואנחנו רצים ממנה. יציאה מהירה היא מה שמאפשר את זה.
         */
        await Task.Delay(TimeSpan.FromSeconds(2));

        Close();
    }

    private async Task RefreshLockoutStateAsync()
    {
        try
        {
            var state = await _client.SendAsync<LockoutStateResult>(IpcOps.LockoutState);

            if (state is { Active: true, Until: { } until })
            {
                ShowMessage(
                    $"{state.Reason ?? "המחשב נעול"}. ניתן יהיה לנסות שוב ב-{until.ToLocalTime():HH:mm}.",
                    isError: true);

                GenerateButton.IsEnabled = false;
            }
        }
        catch (Exception)
        {
            // אין מצב נעילה לדווח עליו
        }
    }

    private void ShowMessage(string text, bool isError)
    {
        MessageText.Text = text;

        MessageText.Foreground = isError
            ? (Brush)FindResource("Danger")
            : (Brush)FindResource("Success");

        MessageBorder.Visibility = Visibility.Visible;
    }

    private void HideMessage() => MessageBorder.Visibility = Visibility.Collapsed;
}
