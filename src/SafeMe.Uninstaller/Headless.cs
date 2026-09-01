using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Text;

using SafeMe.Core.Ipc;

namespace SafeMe.Uninstaller;

/// <summary>
/// מסלול הסרה בלי חלון, לבדיקות ולפריסה מרוכזת.
///
/// נבנה כדי ש-verify-cycle.ps1 יוכל להריץ מחזור חיים מלא בלי אדם
/// שלוחץ. בלעדיו שלב ההסרה במחזור לא היה ניתן לבדיקה אוטומטית —
/// כלומר בדיוק השלב שנשבר שלוש פעמים ביום אחד היה נשאר היחיד שאיש
/// אינו בודק לפני שחרור.
///
/// ---
///
/// שני שלבים, ובכוונה, כי כך זה עובד גם אצל אדם:
///
///   --new-challenge                    מדפיס קוד זיהוי טרי ויוצא.
///   --challenge &lt;C&gt; --code &lt;K&gt;   מאמת ומסיר.
///
/// אי אפשר לאחד אותם. קוד ההסרה נחתם מול קוד זיהוי מסוים שכולל
/// nonce אקראי, ולכן חייב להיות רגע שבו מישהו לוקח את הזיהוי,
/// מנפיק מולו קוד, ומחזיר אותו. זה אינו סיבוך שאפשר לוותר עליו —
/// זו כל ההגנה מפני קוד שנשמר ומשמש שוב.
///
/// והזיהוי חוזר מהקורא ולא נשלף מהשירות: השירות אינו מחזיק "אתגר
/// פתוח" שאפשר לשאול עליו, ובקשה חדשה הייתה מייצרת nonce אחר וכל
/// קוד תקין היה נדחה. החלון הגרפי עושה בדיוק את אותו דבר — הוא
/// שומר את הזיהוי בזיכרון ומחזיר אותו באימות.
///
/// והמסלול הזה אינו עוקף דבר: האימות מתבצע בשירות שרץ כ-SYSTEM,
/// בדיוק כמו מהחלון. מי שמפעיל אותו עם קוד תקף היה יכול להסיר גם
/// דרך הממשק. מה שהוא חוסך זה לחיצות, לא הרשאות.
/// </summary>
[SupportedOSPlatform("windows")]
public static class Headless
{
    /// <summary>ההפעלה בוקשה בלי חלון.</summary>
    public static bool Requested(string[] args) =>
        args.Contains("--new-challenge") || args.Contains("--code");

    /*
     * הקובץ נבנה כ-WinExe ואין לו מסוף משלו.
     *
     * במצב הזה הוא מתחבר למסוף של מי שהריץ אותו, אם יש כזה.
     * כשאין — הכתיבה נבלעת, וזה המצב הרצוי.
     */
    [DllImport("kernel32.dll")]
    private static extern bool AttachConsole(int processId);

    private const int AttachParentProcess = -1;

    public static int Run(string[] args)
    {
        AttachConsole(AttachParentProcess);

        try { Console.OutputEncoding = Encoding.UTF8; }
        catch (IOException) { /* אין מסוף מחובר. */ }

        var client = new IpcClient();

        if (!client.IsServiceAliveAsync().GetAwaiter().GetResult())
        {
            Write("✗ שירות SafeMe אינו פעיל. אין מול מי לאמת.");
            return 2;
        }

        return args.Contains("--new-challenge")
            ? PrintChallenge(client)
            : Verify(client, ValueAfter(args, "--challenge"), ValueAfter(args, "--code"));
    }

    private static string? ValueAfter(string[] args, string name)
    {
        var i = Array.IndexOf(args, name);

        return i >= 0 && i + 1 < args.Length ? args[i + 1] : null;
    }

    private static int PrintChallenge(IpcClient client)
    {
        var result = client.SendAsync<UninstallChallengeResult>(
            IpcOps.UninstallChallenge,
            new UninstallChallengePayload { Reason = "בדיקת מחזור" })
            .GetAwaiter().GetResult();

        if (result is null)
        {
            Write("✗ לא התקבלה תשובה מהשירות.");
            return 2;
        }

        /*
         * הקוד לבדו בשורה נפרדת, בלי קישוט.
         *
         * סקריפט קורא את השורה האחרונה, וכל תו נוסף בה הופך את
         * הקוד לשגוי בלי שאיש יבין למה.
         */
        Write($"· בתוקף עד {result.ExpiresUtc.ToLocalTime():HH:mm} · מצב {result.Mode}");
        Write(result.Challenge);

        return 0;
    }

    private static int Verify(IpcClient client, string? challenge, string? code)
    {
        if (string.IsNullOrWhiteSpace(code) || string.IsNullOrWhiteSpace(challenge))
        {
            Write("✗ נדרשים גם --challenge וגם --code.");
            Write("  יש להריץ תחילה --new-challenge, להנפיק קוד מולו, ולהחזיר את שניהם.");

            return 2;
        }

        var result = client.SendAsync<UninstallVerifyResult>(
            IpcOps.UninstallVerify,
            new UninstallVerifyPayload { Challenge = challenge.Trim(), Response = code.Trim() })
            .GetAwaiter().GetResult();

        if (result is null)
        {
            Write("✗ לא התקבלה תשובה מהשירות.");
            return 2;
        }

        if (!result.Granted)
        {
            Write($"✗ {result.Message}");
            return 3;
        }

        Write("✓ הקוד אומת. מריץ את ההסרה...");

        return RunScript();
    }

    /// <summary>
    /// מריץ את uninstall.ps1, בדיוק כמו החלון.
    ///
    /// ספריית העבודה מחוץ לתיקיית ההתקנה: תהליך בן יורש אותה,
    /// ואנחנו רצים מתוך מה שנמחק — מה שנעל את התיקייה והפיל את
    /// המחיקה על "because it is being used by another process".
    /// </summary>
    private static int RunScript()
    {
        var script = Path.Combine(AppContext.BaseDirectory, "uninstall.ps1");

        if (!File.Exists(script))
        {
            Write($"✗ לא נמצא קובץ ההסרה: {script}");
            return 4;
        }

        var info = new ProcessStartInfo
        {
            FileName = "powershell.exe",
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            StandardOutputEncoding = Encoding.UTF8,
            StandardErrorEncoding = Encoding.UTF8,
            WorkingDirectory = Environment.GetFolderPath(Environment.SpecialFolder.System)
        };

        foreach (var a in new[] { "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", script })
            info.ArgumentList.Add(a);

        using var process = Process.Start(info);

        if (process is null)
        {
            Write("✗ הפעלת תהליך ההסרה נכשלה.");
            return 4;
        }

        var stdout = process.StandardOutput.ReadToEndAsync();
        var stderr = process.StandardError.ReadToEndAsync();

        process.WaitForExit();

        if (process.ExitCode != 0)
        {
            var detail = stderr.GetAwaiter().GetResult().Trim();

            if (detail.Length == 0) detail = stdout.GetAwaiter().GetResult().Trim();

            Write($"✗ ההסרה נכשלה (קוד {process.ExitCode}).");

            if (detail.Length > 0) Write(detail);

            return process.ExitCode;
        }

        Write("✓ SafeMe הוסר מהמחשב.");

        return 0;
    }

    private static void Write(string text)
    {
        try { Console.WriteLine(text); }
        catch (IOException) { /* אין מסוף. */ }
    }
}
