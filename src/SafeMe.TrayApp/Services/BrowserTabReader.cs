using System.Diagnostics;
using System.Runtime.Versioning;
using System.Windows.Automation;

using SafeMe.Core.Browsing;

namespace SafeMe.TrayApp.Services;

/// <summary>
/// קורא את הלשוניות הפתוחות בדפדפנים.
///
/// כאן, במגש, ולא בשירות — וזו אינה העדפה אלא אילוץ. שירות Windows
/// רץ ב-session 0, שמבודד מחלונות המשתמש מאז Vista. הוא אינו רואה
/// את הדפדפן ולא יוכל לראות אותו לעולם, ולכן הקריאה חייבת להתבצע
/// בתהליך שרץ בהפעלה של המשתמש.
///
/// מה שהמחלקה הזו **אינה**: חסימה הרמטית. היא רואה לשונית אחרי
/// שנפתחה, אינה רואה גלישה בחלון פרטי בחלק מהדפדפנים, ומי שיודע
/// מה הוא עושה יעקוף אותה. היא קיימת בשביל המקרה שבו אין ספק סינון
/// כלל — במקום עבודה, ברשת אורחים — ושם היא ההבדל בין משהו לכלום.
///
/// והכי חשוב: **מה שהיא קוראת אינו עוזב את המחשב.** הכותרות
/// והכתובות נבדקות כאן ונשארות כאן. מה שנשלח הוא ספירה בלבד, דרך
/// טיפוס שאין בו מקום לתוכן.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class BrowserTabReader
{
    /// <summary>
    /// הדפדפנים הנתמכים, לפי שם התהליך.
    ///
    /// כולם חושפים את מבנה הלשוניות דרך UI Automation, אך לא באותה
    /// צורה — ולכן החיפוש הוא על תפקידי נגישות ולא על מבנה חלון
    /// ספציפי. מבנה משתנה בכל גרסה; התפקידים אינם.
    /// </summary>
    private static readonly Dictionary<string, string> Browsers = new(StringComparer.OrdinalIgnoreCase)
    {
        ["chrome"] = "Chrome",
        ["msedge"] = "Edge",
        ["firefox"] = "Firefox",
        ["brave"] = "Brave",
        ["opera"] = "Opera",
        ["vivaldi"] = "Vivaldi",
    };

    /// <summary>
    /// תקרת זמן לסריקה אחת.
    ///
    /// UI Automation איטי, והוא נעשה איטי במיוחד כשלדפדפן עשרות
    /// לשוניות. סריקה שנתקעת תתפוס את חוט הממשק ותקפיא את המגש,
    /// ולכן היא נעצרת ומחזירה את מה שהספיקה.
    /// </summary>
    private static readonly TimeSpan Budget = TimeSpan.FromSeconds(4);

    /// <summary>
    /// מחזיר את הלשוניות שנמצאו. רשימה ריקה כשאין דפדפן פתוח, או
    /// כשהקריאה נכשלה — ואלה שני מצבים שונים שאין דרך להבחין ביניהם
    /// מבחוץ, ולכן אין מסיקים מהיעדר תוצאה שהמחשב נקי.
    /// </summary>
    public IReadOnlyList<OpenTab> Read()
    {
        var tabs = new List<OpenTab>();
        var clock = Stopwatch.StartNew();

        foreach (var process in Process.GetProcesses())
        {
            if (clock.Elapsed > Budget) break;

            if (!Browsers.TryGetValue(process.ProcessName, out var browser)) continue;

            try
            {
                if (process.MainWindowHandle == IntPtr.Zero) continue;

                ReadWindow(process.MainWindowHandle, browser, tabs, clock);
            }
            catch (Exception)
            {
                /*
                 * נבלע במכוון.
                 *
                 * דפדפן שנסגר באמצע הסריקה, חלון שנעלם, או גרסה
                 * שמבנה הנגישות שלה שונה — כולם מסתיימים בחריגה, ואף
                 * אחד מהם אינו סיבה להפיל את המגש. מה שנקרא עד כה
                 * נשמר.
                 */
            }
            finally
            {
                process.Dispose();
            }
        }

        return tabs;
    }

    private static void ReadWindow(
        IntPtr handle, string browser, List<OpenTab> tabs, Stopwatch clock)
    {
        var root = AutomationElement.FromHandle(handle);

        if (root is null) return;

        /*
         * חיפוש לפי תפקיד ולא לפי מבנה.
         *
         * TabItem הוא תפקיד נגישות סטנדרטי, וכל הדפדפנים מסמנים בו
         * את הלשוניות. חיפוש לפי שמות מחלקות או היררכיה היה נשבר
         * בכל עדכון גרסה.
         */
        var found = root.FindAll(
            TreeScope.Descendants,
            new PropertyCondition(AutomationElement.ControlTypeProperty, ControlType.TabItem));

        foreach (AutomationElement element in found)
        {
            if (clock.Elapsed > Budget) return;

            var title = element.Current.Name;

            if (string.IsNullOrWhiteSpace(title)) continue;

            tabs.Add(new OpenTab { Browser = browser, Title = title, Host = null });
        }

        // כתובת הלשונית הפעילה, כשהיא זמינה. היא הראיה החזקה, ולכן
        // שווה את החיפוש הנוסף — אך אינה קיימת לכל לשונית.
        var host = ReadAddressBar(root);

        if (host is null || tabs.Count == 0) return;

        var last = tabs[^1];

        tabs[^1] = last with { Host = host };
    }

    /// <summary>
    /// שם המארח משורת הכתובת.
    ///
    /// שורת הכתובת היא Edit עם AutomationId ידוע ברוב הדפדפנים
    /// מבוססי Chromium. כשהיא אינה נמצאת, נשארים עם הכותרת — וזה
    /// המצב השכיח, לא חריג.
    /// </summary>
    private static string? ReadAddressBar(AutomationElement root)
    {
        try
        {
            var bar = root.FindFirst(
                TreeScope.Descendants,
                new AndCondition(
                    new PropertyCondition(
                        AutomationElement.ControlTypeProperty, ControlType.Edit),
                    new PropertyCondition(
                        AutomationElement.IsKeyboardFocusableProperty, true)));

            var text = bar?.Current.Name;

            if (string.IsNullOrWhiteSpace(text)) return null;

            // הדפדפן מציג לעיתים כתובת בלי סכימה. Uri דורש אחת.
            var candidate = text.Contains("://", StringComparison.Ordinal)
                ? text
                : "https://" + text;

            return Uri.TryCreate(candidate, UriKind.Absolute, out var uri) ? uri.Host : null;
        }
        catch (Exception)
        {
            return null;
        }
    }
}
