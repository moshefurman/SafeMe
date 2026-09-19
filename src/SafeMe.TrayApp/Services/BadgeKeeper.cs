using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Windows;
using System.Windows.Interop;
using System.Windows.Threading;
using Microsoft.Win32;
using SafeMe.Core.Models;

namespace SafeMe.TrayApp.Services;

/// <summary>
/// שומר על התג גלוי, ורושם מה הסתיר אותו.
///
/// "האייקון נעלם" חזר שוב ושוב, ובכל מדידה התהליך היה חי והחלון
/// מוצג. כלומר ההיעלמות קורית בין המדידות, ומשהו מסתיר חלון שקיים:
/// חלון topmost אחר שנפתח מעליו (התג לעולם אינו מופעל, ולכן שוקע
/// לתחתית רצועת ה-topmost), שולחן עבודה וירטואלי אחר, שטח עבודה
/// שהשתנה עם חיבור מסך, או משטח שכבה שלא צויר מחדש אחרי שינה.
///
/// השומר בודק כל כמה שניות, מתקן, ורושם. הרישום הוא העיקר: בלעדיו
/// הדיווח הבא יהיה שוב "נעלם" בלי שום דרך לדעת למה.
/// </summary>
public sealed partial class BadgeKeeper : IDisposable
{
    private static readonly TimeSpan Interval = TimeSpan.FromSeconds(5);

    /// <summary>
    /// כמה בדיקות רצופות המכסה צריך להחזיק לפני שמטפסים מעליו.
    ///
    /// תפריט הקשר, בלון התראה, או חלון שנגרר לרגע מעל הפינה — כולם
    /// מכסים לשנייה. טיפוס מיידי היה נלחם בהם לשווא. שתי בדיקות הן
    /// עשר שניות: מספיק כדי שמה שנשאר הוא באמת חלון שמסתיר.
    /// </summary>
    private const int TicksBeforeRaise = 2;

    /// <summary>
    /// ממשק המערכת שמעליו לא מטפסים.
    ///
    /// תפריט התחלה, חיפוש, מרכז ההתראות, מסך הנעילה — מוצגים לרגע
    /// ובכוונת המשתמש. תג שמטפס מעל תפריט ההתחלה אינו "תמיד גלוי",
    /// הוא מטרד.
    /// </summary>
    private static readonly HashSet<string> ShellProcesses = new(StringComparer.OrdinalIgnoreCase)
    {
        "explorer", "StartMenuExperienceHost", "ShellExperienceHost", "SearchHost",
        "SearchApp", "LockApp", "LogonUI", "ShellHost", "TextInputHost", "dwm", "csrss",
    };

    private readonly Window _badge;
    private readonly Action _reposition;
    private readonly Action<string>? _relayout;
    private readonly Action? _healSize;
    private readonly DispatcherTimer _timer;

    private string? _pendingCover;
    private int _coverTicks;

    /// <summary>נורה אחרי שינה או פתיחת נעילה, כדי שגם אייקון המגש ייבנה מחדש.</summary>
    public event Action? Revived;

    public BadgeKeeper(Window badge, Action reposition, Action<string>? relayout = null, Action? healSize = null)
    {
        _badge = badge;
        _reposition = reposition;
        _relayout = relayout;
        _healSize = healSize;

        _timer = new DispatcherTimer(DispatcherPriority.Background, badge.Dispatcher)
        {
            Interval = Interval
        };

        _timer.Tick += (_, _) => Tick();
    }

    public void Start()
    {
        _timer.Start();

        /*
         * שינה ונעילה הם הרגעים שבהם חלון שכבה (AllowsTransparency)
         * מאבד לפעמים את המשטח שלו ומוצג ריק — "קיים" לכל בדיקה,
         * ובלתי נראה לעין. בונים אותו מחדש במקום לחכות שיתגלה.
         */
        SystemEvents.PowerModeChanged += OnPowerModeChanged;
        SystemEvents.SessionSwitch += OnSessionSwitch;
    }

    private void OnPowerModeChanged(object sender, PowerModeChangedEventArgs e)
    {
        if (e.Mode == PowerModes.Resume) ScheduleRevive("חזרה משינה");
    }

    private void OnSessionSwitch(object sender, SessionSwitchEventArgs e)
    {
        if (e.Reason is SessionSwitchReason.SessionUnlock
            or SessionSwitchReason.ConsoleConnect
            or SessionSwitchReason.RemoteConnect)
        {
            ScheduleRevive("פתיחת נעילה");
        }
    }

    private void ScheduleRevive(string why)
    {
        // שתי שניות: המסך והשולחן עדיין מתייצבים ברגע האירוע עצמו.
        var once = new DispatcherTimer(DispatcherPriority.Background, _badge.Dispatcher)
        {
            Interval = TimeSpan.FromSeconds(2)
        };

        once.Tick += (_, _) =>
        {
            once.Stop();
            Revive(why);
        };

        once.Start();
    }

    /// <summary>בונה את משטח החלון מחדש, ממקם, ומרים. גם אייקון המגש נבנה מחדש.</summary>
    public void Revive(string why)
    {
        try
        {
            _badge.Visibility = Visibility.Hidden;
            _badge.Visibility = Visibility.Visible;
            _badge.InvalidateVisual();

            // מרנדר מחדש ומאלץ התאמה לגודל התוכן. החלפת הנראות לבדה
            // אינה מבטיחה ש-SizeToContent יחשב שוב, וזה החשד לגודל
            // הביניים שדווח. גם רושם את המצב שהתקבל.
            _relayout?.Invoke($"בנייה מחדש ({why})");

            _reposition();
            Raise();

            Revived?.Invoke();

            TrayDiagnostics.Warn("revive", $"התג נבנה מחדש אחרי {why}.");
        }
        catch (Exception ex)
        {
            TrayDiagnostics.Warn("revive-failed", $"בניית התג מחדש אחרי {why} נכשלה: {ex.Message}");
        }
    }

    // ---------------------------------------------------------------- בדיקה

    private void Tick()
    {
        try
        {
            // לפני התצפית: מיקום ושטח עבודה נמדדים לפי הגודל המתוקן
            _healSize?.Invoke();

            var observation = Observe();
            var repair = BadgeKeeperPlan.Decide(observation);

            /*
             * מכסה חייב להחזיק כמה בדיקות. נרשם מהראשונה, מטפסים
             * מהשנייה — כך גם מכסה חולף מותיר עקבות ביומן בלי
             * שנילחם בו.
             */
            if (repair.HasFlag(BadgeRepair.RaiseAboveCover))
            {
                if (observation.CoveredBy == _pendingCover) _coverTicks++;
                else
                {
                    _pendingCover = observation.CoveredBy;
                    _coverTicks = 1;
                }

                if (_coverTicks < TicksBeforeRaise) repair &= ~BadgeRepair.RaiseAboveCover;
            }
            else
            {
                _pendingCover = null;
                _coverTicks = 0;
            }

            if (repair == BadgeRepair.None) return;

            if (repair.HasFlag(BadgeRepair.Show)) _badge.Show();
            if (repair.HasFlag(BadgeRepair.MoveToCurrentDesktop)) MoveToCurrentDesktop();
            if (repair.HasFlag(BadgeRepair.Reposition)) _reposition();
            if (repair.HasFlag(BadgeRepair.RaiseAboveCover)) Raise();

            TrayDiagnostics.Warn("repair:" + repair, BadgeKeeperPlan.Describe(repair, observation));
        }
        catch (Exception ex)
        {
            TrayDiagnostics.Warn("tick-failed", $"בדיקת התג נכשלה: {ex.Message}");
        }
    }

    private BadgeObservation Observe()
    {
        var hwnd = new WindowInteropHelper(_badge).Handle;

        if (hwnd == IntPtr.Zero)
            return new BadgeObservation(false, true, true, null);

        var visible = _badge.IsVisible && Native.IsWindowVisible(hwnd);
        var onDesktop = VirtualDesktop.IsOnCurrent(hwnd);
        var inside = InsideWorkArea();
        var (cover, isShell) = visible ? CoverOf(hwnd) : (null, false);

        return new BadgeObservation(visible, onDesktop, inside, cover, isShell);
    }

    private bool InsideWorkArea()
    {
        var area = SystemParameters.WorkArea;

        return _badge.Left >= area.Left - 1
            && _badge.Top >= area.Top - 1
            && _badge.Left + _badge.ActualWidth <= area.Right + 1
            && _badge.Top + _badge.ActualHeight <= area.Bottom + 1;
    }

    /// <summary>
    /// מי נמצא במרכז התג. אם זה לא אנחנו — התג מכוסה.
    ///
    /// WindowFromPoint מחזיר את החלון העליון בנקודה, ולכן זו מדידה
    /// של מה שהעין רואה ולא של מה שהמערכת מדווחת. המרכז ולא הפינה:
    /// לחלון יש שוליים שקופים, ונקודה בהם הייתה מחזירה את מה שמתחת.
    /// </summary>
    private (string? Cover, bool IsShell) CoverOf(IntPtr hwnd)
    {
        if (!Native.GetWindowRect(hwnd, out var rect)) return (null, false);

        var point = new Native.POINT
        {
            X = (rect.Left + rect.Right) / 2,
            Y = (rect.Top + rect.Bottom) / 2
        };

        var at = Native.WindowFromPoint(point);

        if (at == IntPtr.Zero) return (null, false);

        var root = Native.GetAncestor(at, Native.GA_ROOT);

        if (root == hwnd || at == hwnd) return (null, false);

        Native.GetWindowThreadProcessId(root, out var pid);

        // חלון של התהליך שלנו — תפריט, בלון, חלון המצב. לא מכסה.
        if (pid == Environment.ProcessId) return (null, false);

        string process;

        try
        {
            process = Process.GetProcessById((int)pid).ProcessName;
        }
        catch (Exception)
        {
            process = $"pid {pid}";
        }

        var title = Native.WindowText(root);
        var cover = string.IsNullOrWhiteSpace(title) ? $"{process}.exe" : $"{process}.exe: {title}";

        return (cover, ShellProcesses.Contains(process));
    }

    // ---------------------------------------------------------------- תיקונים

    private void Raise()
    {
        var hwnd = new WindowInteropHelper(_badge).Handle;

        if (hwnd == IntPtr.Zero) return;

        // לראש רצועת ה-topmost, בלי להפעיל ובלי להזיז.
        Native.SetWindowPos(hwnd, Native.HWND_TOPMOST, 0, 0, 0, 0,
            Native.SWP_NOMOVE | Native.SWP_NOSIZE | Native.SWP_NOACTIVATE | Native.SWP_SHOWWINDOW);
    }

    private void MoveToCurrentDesktop()
    {
        var hwnd = new WindowInteropHelper(_badge).Handle;

        if (hwnd == IntPtr.Zero) return;

        VirtualDesktop.MoveToCurrent(hwnd);
    }

    public void Dispose()
    {
        _timer.Stop();
        SystemEvents.PowerModeChanged -= OnPowerModeChanged;
        SystemEvents.SessionSwitch -= OnSessionSwitch;
    }

    // ---------------------------------------------------------------- Win32

    private static partial class Native
    {
        public static readonly IntPtr HWND_TOPMOST = new(-1);

        public const uint SWP_NOSIZE = 0x0001;
        public const uint SWP_NOMOVE = 0x0002;
        public const uint SWP_NOACTIVATE = 0x0010;
        public const uint SWP_SHOWWINDOW = 0x0040;
        public const uint GA_ROOT = 2;

        [StructLayout(LayoutKind.Sequential)]
        public struct POINT { public int X; public int Y; }

        [StructLayout(LayoutKind.Sequential)]
        public struct RECT { public int Left; public int Top; public int Right; public int Bottom; }

        [LibraryImport("user32.dll")]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static partial bool IsWindowVisible(IntPtr hWnd);

        [LibraryImport("user32.dll")]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static partial bool GetWindowRect(IntPtr hWnd, out RECT rect);

        [LibraryImport("user32.dll")]
        public static partial IntPtr WindowFromPoint(POINT point);

        [LibraryImport("user32.dll")]
        public static partial IntPtr GetAncestor(IntPtr hWnd, uint flags);

        [LibraryImport("user32.dll")]
        public static partial uint GetWindowThreadProcessId(IntPtr hWnd, out uint processId);

        [LibraryImport("user32.dll")]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static partial bool SetWindowPos(
            IntPtr hWnd, IntPtr hWndInsertAfter, int x, int y, int cx, int cy, uint flags);

        [LibraryImport("user32.dll", EntryPoint = "GetWindowTextW", StringMarshalling = StringMarshalling.Utf16)]
        private static partial int GetWindowText(IntPtr hWnd, [Out] char[] text, int maxCount);

        [LibraryImport("user32.dll")]
        public static partial IntPtr GetForegroundWindow();

        public static string WindowText(IntPtr hWnd)
        {
            var buffer = new char[256];
            var length = GetWindowText(hWnd, buffer, buffer.Length);

            return length <= 0 ? "" : new string(buffer, 0, length);
        }
    }

    /// <summary>
    /// שולחנות עבודה וירטואליים.
    ///
    /// חלון שייך לשולחן אחד. משתמש שעבר שולחן — Task View, Win+Ctrl+חץ —
    /// "איבד" את התג בלי ששום דבר קרה לו. הממשק הציבורי היחיד של
    /// Windows לזה הוא IVirtualDesktopManager: לשאול אם החלון בשולחן
    /// הנוכחי, ולהעביר אותו לשולחן של חלון אחר שכן שם.
    /// </summary>
    private static class VirtualDesktop
    {
        private static readonly Guid ClsidManager = new("aa509086-5ca9-4c25-8f95-589d3c07b48a");

        [ComImport]
        [Guid("a5cd92ff-29be-454c-8d04-d82879fb3f1b")]
        [InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
        private interface IVirtualDesktopManager
        {
            [PreserveSig] int IsWindowOnCurrentVirtualDesktop(IntPtr topLevelWindow, out int onCurrent);
            [PreserveSig] int GetWindowDesktopId(IntPtr topLevelWindow, out Guid desktopId);
            [PreserveSig] int MoveWindowToDesktop(IntPtr topLevelWindow, in Guid desktopId);
        }

        private static IVirtualDesktopManager? Manager()
        {
            try
            {
                var type = Type.GetTypeFromCLSID(ClsidManager);

                return type is null ? null : Activator.CreateInstance(type) as IVirtualDesktopManager;
            }
            catch (Exception)
            {
                return null;
            }
        }

        /// <summary>true גם כשאי אפשר לדעת — היעדר ידיעה אינו סיבה לתקן.</summary>
        public static bool IsOnCurrent(IntPtr hwnd)
        {
            var manager = Manager();

            if (manager is null) return true;

            try
            {
                return manager.IsWindowOnCurrentVirtualDesktop(hwnd, out var on) != 0 || on != 0;
            }
            catch (Exception)
            {
                return true;
            }
        }

        public static void MoveToCurrent(IntPtr hwnd)
        {
            var manager = Manager();

            if (manager is null) return;

            try
            {
                /*
                 * השולחן הנוכחי אינו נשאל ישירות — הממשק אינו חושף
                 * אותו. החלון בחזית נמצא בו בהכרח, ולכן השולחן שלו
                 * הוא הנוכחי.
                 */
                var foreground = Native.GetForegroundWindow();

                if (foreground == IntPtr.Zero || foreground == hwnd) return;
                if (manager.GetWindowDesktopId(foreground, out var current) != 0) return;
                if (current == Guid.Empty) return;

                manager.MoveWindowToDesktop(hwnd, in current);
            }
            catch (Exception)
            {
                // אין שולחנות וירטואליים, או שהממשק השתנה. הבדיקה הבאה תנסה שוב.
            }
        }
    }
}
