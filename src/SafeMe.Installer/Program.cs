using System.Diagnostics;
using System.IO.Compression;
using System.Reflection;
using System.Runtime.Versioning;
using System.Text;

using SafeMe.Core.Security;

namespace SafeMe.Installer;

/// <summary>
/// מתקין SafeMe.
///
/// הרעיון שמאחורי כל התהליך: הקובץ שהמשתמש הוריד נקרא
/// SafeMe-Setup-ENR-XXXX.exe, והאסימון שבשמו הוא שמקשר את המחשב
/// לחשבון. אין מה להקליד ואין מה להעתיק.
///
/// המתקין אינו מיישם את ההתקנה בעצמו אלא פורס את install.ps1 ומריץ
/// אותו. הסקריפט כבר מטפל בהקשחת הרשאות, ברישום ל-Safe Mode,
/// בהתאוששות מכשלים ובמשימת הגיבוי — ושכפול ההיגיון הזה ב-C# היה
/// יוצר שני מקורות אמת שיסטו זה מזה.
/// </summary>
[SupportedOSPlatform("windows")]
public static class Program
{
    /// <summary>כתובת השרת. ניתנת לעקיפה בשורת הפקודה לצורכי בדיקה.</summary>
    private const string DefaultServerUrl = "https://safeme-h7h4.onrender.com";

    /// <summary>סביבת ההרצה שהסוכן זקוק לה.</summary>
    private const string RequiredRuntime = "Microsoft.WindowsDesktop.App";
    private const int RequiredMajor = 9;

    /// <summary>המפנה הרשמי לגרסה היציבה האחרונה בענף 9.</summary>
    private const string RuntimeInstallerUrl =
        "https://aka.ms/dotnet/9.0/windowsdesktop-runtime-win-x64.exe";

    private const string RuntimeDownloadPage =
        "https://dotnet.microsoft.com/download/dotnet/9.0/runtime";

    public static int Main(string[] args)
    {
        Console.OutputEncoding = Encoding.UTF8;

        try
        {
            return Run(args);
        }
        catch (Exception ex)
        {
            Fail(ex.Message);
            return 1;
        }
        finally
        {
            if (!args.Contains("--quiet"))
            {
                Console.WriteLine();
                Console.WriteLine("הקש Enter לסגירה.");
                Console.ReadLine();
            }
        }
    }

    private static int Run(string[] args)
    {
        Banner();

        // ---- 1. לאיזה חשבון ----

        var token = ArgValue(args, "--token") ?? InstallerToken.FromFileName(Environment.ProcessPath);

        if (token is null)
        {
            Fail("לא נמצא קוד התקנה.");
            Console.WriteLine();
            Console.WriteLine("  הקובץ שהורדת אמור להיקרא כך:");
            Console.WriteLine("    SafeMe-Setup-ENR-XXXXXXXXXXXXXXXXXXXXXXXX.exe");
            Console.WriteLine();
            Console.WriteLine("  אם שינית את שמו, הורד אותו מחדש מהאתר.");
            Console.WriteLine("  אם קיבלת קוד בנפרד, הרץ כך:");
            Console.WriteLine("    SafeMe-Setup.exe --token ENR-...");

            return 2;
        }

        var serverUrl = ArgValue(args, "--server") ?? DefaultServerUrl;

        Step($"חשבון:  {Mask(token)}");
        Step($"שרת:    {serverUrl}");
        Console.WriteLine();

        // ---- 2. סביבת ההרצה ----

        if (!RuntimeInstalled())
        {
            Warn($"סביבת ההרצה .NET {RequiredMajor} אינה מותקנת.");
            Console.WriteLine();
            Console.WriteLine("  מתקין אותה עכשיו. זו הורדה חד-פעמית ממיקרוסופט,");
            Console.WriteLine("  ואחריה כל עדכון של SafeMe שוקל מגה וקצת בלבד.");
            Console.WriteLine();

            if (!InstallRuntime())
            {
                Fail("התקנת סביבת ההרצה נכשלה.");
                Console.WriteLine();
                Console.WriteLine("  התקן ידנית ולאחר מכן הרץ שוב את המתקין:");
                Console.WriteLine($"  {RuntimeDownloadPage}");

                return 3;
            }

            if (!RuntimeInstalled())
            {
                Fail("סביבת ההרצה הותקנה אך אינה מזוהה. ייתכן שנדרשת הפעלה מחדש.");
                return 3;
            }

            Ok("סביבת ההרצה הותקנה.");
        }
        else
        {
            Step("סביבת ההרצה קיימת.");
        }

        // ---- 3. פריסת המטען ----

        var staging = Path.Combine(Path.GetTempPath(), "SafeMe-Setup-" + Guid.NewGuid().ToString("N")[..8]);

        try
        {
            ExtractPayload(staging);

            var script = Path.Combine(staging, "install.ps1");

            if (!File.Exists(script))
                throw new InvalidOperationException("המטען פגום: install.ps1 חסר.");

            Step("הקבצים נפרסו.");
            Console.WriteLine();

            // ---- 4. ההתקנה עצמה ----

            var exit = RunInstallScript(script, staging, serverUrl, token);

            if (exit != 0)
            {
                Fail($"ההתקנה נכשלה (קוד {exit}).");
                Console.WriteLine();
                Console.WriteLine("  פרטים נוספים ביומן האירועים של Windows, תחת המקור SafeMe.");

                return exit;
            }

            Console.WriteLine();
            Ok("SafeMe הותקן.");
            Console.WriteLine();
            Console.WriteLine("  תג המצב יופיע בפינת המסך תוך כמה שניות,");
            Console.WriteLine("  והמחשב יופיע במרכז הניהול שלך.");

            Console.WriteLine();
            // ההמלצות המפורטות מודפסות על ידי install.ps1, שכבר
            // בדק אילו חשבונות הם מנהלים. כאן רק מפנים אליהן, כדי
            // שהן לא ייבלעו בין שורות ההתקנה.
            Console.WriteLine("  שים לב להמלצות שמופיעות למעלה — הן סוגרות");
            Console.WriteLine("  את שתי הדרכים שהתוכנה אינה יכולה לסגור בעצמה.");

            return 0;
        }
        finally
        {
            // הסתרת האסימון: התיקייה הזמנית מכילה תצורה עם קוד ההתקנה
            try { Directory.Delete(staging, recursive: true); }
            catch (IOException) { /* קובץ נעול. ימחק בניקוי הבא של המערכת. */ }
            catch (UnauthorizedAccessException) { }
        }
    }

    // ---------------------------------------------------------------- מטען

    private static void ExtractPayload(string destination)
    {
        using var stream = Assembly.GetExecutingAssembly()
            .GetManifestResourceStream("payload.zip");

        if (stream is null)
        {
            throw new InvalidOperationException(
                "המתקין נבנה בלי מטען. יש להריץ את סקריפט האריזה: build/pack.ps1");
        }

        Directory.CreateDirectory(destination);

        using var archive = new ZipArchive(stream, ZipArchiveMode.Read);

        foreach (var entry in archive.Entries)
        {
            // שם ערך בארכיון עלול להכיל מעבר לתיקיית אב. ארכיון פגום
            // או זדוני היה כותב מחוץ ליעד.
            var target = Path.GetFullPath(Path.Combine(destination, entry.FullName));

            if (!target.StartsWith(destination, StringComparison.OrdinalIgnoreCase))
                throw new InvalidOperationException($"נתיב חורג בארכיון: {entry.FullName}");

            if (entry.Name.Length == 0)
            {
                Directory.CreateDirectory(target);
                continue;
            }

            Directory.CreateDirectory(Path.GetDirectoryName(target)!);
            entry.ExtractToFile(target, overwrite: true);
        }
    }

    // ---------------------------------------------------------------- הרצה

    private static int RunInstallScript(string script, string payloadDir, string serverUrl, string token)
    {
        var info = new ProcessStartInfo
        {
            FileName = "powershell.exe",
            UseShellExecute = false,
        };

        // ArgumentList ולא מחרוזת אחת: הבריחה נעשית על ידי המערכת,
        // ואסימון או נתיב עם רווח לא ישברו את הפקודה.
        info.ArgumentList.Add("-NoProfile");
        info.ArgumentList.Add("-NonInteractive");
        info.ArgumentList.Add("-ExecutionPolicy");
        info.ArgumentList.Add("Bypass");
        info.ArgumentList.Add("-File");
        info.ArgumentList.Add(script);
        info.ArgumentList.Add("-SourcePath");
        info.ArgumentList.Add(payloadDir);
        info.ArgumentList.Add("-ServerUrl");
        info.ArgumentList.Add(serverUrl);
        info.ArgumentList.Add("-EnrollToken");
        info.ArgumentList.Add(token);

        using var process = Process.Start(info)
            ?? throw new InvalidOperationException("הפעלת PowerShell נכשלה.");

        process.WaitForExit();

        return process.ExitCode;
    }

    // ---------------------------------------------------------------- בדיקות

    /// <summary>
    /// בודק אם סביבת ההרצה קיימת, לפי תיקיות הגרסאות המשותפות.
    ///
    /// בדיקה בתיקייה ולא הרצת dotnet --list-runtimes: הפקודה תלויה
    /// ב-PATH, שעשוי להיות שונה בהקשר מורם.
    /// </summary>
    /// <summary>
    /// מוריד ומתקין את סביבת ההרצה, בשקט.
    ///
    /// הכתובת היא המפנה הרשמי של מיקרוסופט לגרסה היציבה האחרונה
    /// בענף. קיבוע גרסה מדויקת היה מזדקן ומפנה בהמשך לגרסה שכבר
    /// אינה מקבלת עדכוני אבטחה.
    ///
    /// ההורדה היא לתיקייה זמנית שהמשתמש אינו שולט בה, והקובץ מורץ
    /// מיד. הוא מגיע מ-Microsoft וחתום על ידה; Windows יאמת את
    /// החתימה בהרצה.
    /// </summary>
    private static bool InstallRuntime()
    {
        var target = Path.Combine(Path.GetTempPath(),
            $"windowsdesktop-runtime-{Guid.NewGuid().ToString("N")[..8]}.exe");

        try
        {
            Step("מוריד...");

            using (var http = new HttpClient { Timeout = TimeSpan.FromMinutes(15) })
            using (var response = http.GetAsync(RuntimeInstallerUrl).GetAwaiter().GetResult())
            {
                if (!response.IsSuccessStatusCode)
                {
                    Fail($"ההורדה נכשלה: {(int)response.StatusCode}");
                    return false;
                }

                using var file = File.Create(target);
                response.Content.CopyToAsync(file).GetAwaiter().GetResult();
            }

            Step("מתקין...");

            var info = new ProcessStartInfo { FileName = target, UseShellExecute = false };

            // /quiet ללא ממשק, /norestart כדי שהמחשב לא יאותחל
            // באמצע ההתקנה שלנו ויותיר אותה חלקית
            info.ArgumentList.Add("/install");
            info.ArgumentList.Add("/quiet");
            info.ArgumentList.Add("/norestart");

            using var process = Process.Start(info);

            if (process is null) return false;

            process.WaitForExit();

            // 3010 פירושו הצלחה שדורשת אתחול. סביבת ההרצה כבר שמישה,
            // ולכן ממשיכים.
            return process.ExitCode is 0 or 3010;
        }
        catch (Exception ex) when (ex is HttpRequestException or IOException or TaskCanceledException)
        {
            Fail(ex.Message);
            return false;
        }
        finally
        {
            try { File.Delete(target); } catch (IOException) { }
        }
    }
    private static bool RuntimeInstalled()
    {
        foreach (var root in RuntimeRoots())
        {
            var shared = Path.Combine(root, "shared", RequiredRuntime);

            if (!Directory.Exists(shared)) continue;

            foreach (var dir in Directory.GetDirectories(shared))
            {
                var name = Path.GetFileName(dir);
                var dot = name.IndexOf('.');

                if (dot > 0
                    && int.TryParse(name[..dot], out var major)
                    && major >= RequiredMajor)
                {
                    return true;
                }
            }
        }

        return false;
    }

    private static IEnumerable<string> RuntimeRoots()
    {
        var installed = Environment.GetEnvironmentVariable("DOTNET_ROOT");

        if (!string.IsNullOrWhiteSpace(installed)) yield return installed;

        yield return Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "dotnet");
    }

    // ---------------------------------------------------------------- עזר

    private static string? ArgValue(string[] args, string name)
    {
        var index = Array.IndexOf(args, name);

        return index >= 0 && index + 1 < args.Length ? args[index + 1] : null;
    }

    /// <summary>
    /// מסתיר את רוב האסימון בפלט. הוא מעניק גישה לחשבון, ואין סיבה
    /// שיישאר בצילום מסך או בהקלטת תמיכה.
    /// </summary>
    private static string Mask(string token) =>
        token.Length <= 10 ? token : $"{token[..8]}…{token[^4..]}";

    private static void Banner()
    {
        Console.WriteLine();
        Console.WriteLine("  SafeMe");
        Console.WriteLine("  אכיפת חיבור אינטרנט מסונן");
        Console.WriteLine("  " + new string('─', 42));
        Console.WriteLine();
    }

    private static void Step(string text) => Console.WriteLine($"  · {text}");

    private static void Ok(string text)
    {
        Console.ForegroundColor = ConsoleColor.Green;
        Console.WriteLine($"  ✓ {text}");
        Console.ResetColor();
    }

    private static void Warn(string text)
    {
        Console.ForegroundColor = ConsoleColor.Yellow;
        Console.WriteLine($"  ! {text}");
        Console.ResetColor();
    }

    private static void Fail(string text)
    {
        Console.ForegroundColor = ConsoleColor.Red;
        Console.WriteLine($"  ✗ {text}");
        Console.ResetColor();
    }
}
