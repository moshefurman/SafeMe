using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using Microsoft.Extensions.Logging;

namespace FilterPlus.Service.Watchdog;

/// <summary>
/// מפעיל תהליך בסשן של משתמש מחובר, מתוך שירות שרץ ב-Session 0.
///
/// זהו הצינור היחיד שדרכו השירות יכול להחיות את אייקון המגש. התהליך
/// שנוצר רץ בהרשאות המשתמש בלבד, ואין לו סמכות אכיפה כלשהי.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed partial class SessionLauncher
{
    private readonly ILogger _log;

    public SessionLauncher(ILogger log) => _log = log;

    // ------------------------------------------------------------ קבועים

    private const int WTS_CURRENT_SERVER_HANDLE = 0;
    private const uint MAXIMUM_ALLOWED = 0x02000000;
    private const uint CREATE_UNICODE_ENVIRONMENT = 0x00000400;
    private const uint CREATE_NO_WINDOW = 0x08000000;
    private const uint NORMAL_PRIORITY_CLASS = 0x00000020;

    private enum WTS_CONNECTSTATE_CLASS
    {
        WTSActive = 0,
        WTSConnected = 1,
        WTSConnectQuery = 2,
        WTSShadow = 3,
        WTSDisconnected = 4
    }

    private enum SECURITY_IMPERSONATION_LEVEL
    {
        SecurityAnonymous = 0,
        SecurityIdentification = 1,
        SecurityImpersonation = 2,
        SecurityDelegation = 3
    }

    private enum TOKEN_TYPE
    {
        TokenPrimary = 1,
        TokenImpersonation = 2
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct WTS_SESSION_INFO
    {
        public uint SessionId;
        public IntPtr pWinStationName;
        public WTS_CONNECTSTATE_CLASS State;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct STARTUPINFO
    {
        public int cb;
        public IntPtr lpReserved;
        public IntPtr lpDesktop;
        public IntPtr lpTitle;
        public int dwX, dwY, dwXSize, dwYSize;
        public int dwXCountChars, dwYCountChars, dwFillAttribute, dwFlags;
        public short wShowWindow, cbReserved2;
        public IntPtr lpReserved2, hStdInput, hStdOutput, hStdError;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct PROCESS_INFORMATION
    {
        public IntPtr hProcess, hThread;
        public int dwProcessId, dwThreadId;
    }

    // ------------------------------------------------------------ P/Invoke

    [DllImport("wtsapi32.dll", SetLastError = true)]
    private static extern bool WTSEnumerateSessions(
        IntPtr server, int reserved, int version, out IntPtr sessionInfo, out int count);

    [DllImport("wtsapi32.dll")]
    private static extern void WTSFreeMemory(IntPtr memory);

    [DllImport("wtsapi32.dll", SetLastError = true)]
    private static extern bool WTSQueryUserToken(uint sessionId, out IntPtr token);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool DuplicateTokenEx(
        IntPtr existingToken, uint desiredAccess, IntPtr attributes,
        SECURITY_IMPERSONATION_LEVEL impersonationLevel, TOKEN_TYPE tokenType, out IntPtr newToken);

    [DllImport("userenv.dll", SetLastError = true)]
    private static extern bool CreateEnvironmentBlock(out IntPtr environment, IntPtr token, bool inherit);

    [DllImport("userenv.dll", SetLastError = true)]
    private static extern bool DestroyEnvironmentBlock(IntPtr environment);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool CreateProcessAsUser(
        IntPtr token, string? applicationName, string? commandLine,
        IntPtr processAttributes, IntPtr threadAttributes, bool inheritHandles,
        uint creationFlags, IntPtr environment, string? currentDirectory,
        ref STARTUPINFO startupInfo, out PROCESS_INFORMATION processInformation);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr handle);

    // ------------------------------------------------------------ API ציבורי

    /// <summary>מחזיר את מזהי הסשנים שיש בהם משתמש מחובר.</summary>
    public List<uint> GetActiveUserSessions()
    {
        var sessions = new List<uint>();
        var buffer = IntPtr.Zero;

        try
        {
            if (!WTSEnumerateSessions(WTS_CURRENT_SERVER_HANDLE, 0, 1, out buffer, out var count))
                return sessions;

            var size = Marshal.SizeOf<WTS_SESSION_INFO>();

            for (var i = 0; i < count; i++)
            {
                var info = Marshal.PtrToStructure<WTS_SESSION_INFO>(buffer + i * size);

                // סשן 0 הוא סשן השירותים ואין בו שולחן עבודה של משתמש
                if (info.SessionId == 0) continue;

                if (info.State is WTS_CONNECTSTATE_CLASS.WTSActive or WTS_CONNECTSTATE_CLASS.WTSConnected)
                    sessions.Add(info.SessionId);
            }
        }
        catch (Exception ex)
        {
            _log.LogDebug(ex, "מניית סשנים נכשלה.");
        }
        finally
        {
            if (buffer != IntPtr.Zero) WTSFreeMemory(buffer);
        }

        return sessions;
    }

    /// <summary>
    /// מפעיל תהליך בסשן נתון תחת זהות המשתמש המחובר.
    /// מחזיר את מזהה התהליך שנוצר, או null בכישלון.
    /// </summary>
    public int? LaunchInSession(uint sessionId, string exePath, string? arguments = null)
    {
        var userToken = IntPtr.Zero;
        var primaryToken = IntPtr.Zero;
        var environment = IntPtr.Zero;

        try
        {
            if (!WTSQueryUserToken(sessionId, out userToken))
            {
                _log.LogDebug("קבלת אסימון משתמש לסשן {Session} נכשלה (שגיאה {Error}).",
                    sessionId, Marshal.GetLastWin32Error());

                return null;
            }

            // נדרש אסימון ראשי כדי ליצור תהליך; אסימון ההתחזות אינו מספיק
            if (!DuplicateTokenEx(userToken, MAXIMUM_ALLOWED, IntPtr.Zero,
                    SECURITY_IMPERSONATION_LEVEL.SecurityIdentification,
                    TOKEN_TYPE.TokenPrimary, out primaryToken))
            {
                _log.LogWarning("שכפול אסימון לסשן {Session} נכשל (שגיאה {Error}).",
                    sessionId, Marshal.GetLastWin32Error());

                return null;
            }

            CreateEnvironmentBlock(out environment, primaryToken, false);

            var startup = new STARTUPINFO
            {
                cb = Marshal.SizeOf<STARTUPINFO>(),
                // חובה לציין את שולחן העבודה האינטראקטיבי, אחרת החלון לא ייווצר
                lpDesktop = Marshal.StringToHGlobalUni(@"winsta0\default")
            };

            var commandLine = arguments is null ? $"\"{exePath}\"" : $"\"{exePath}\" {arguments}";

            try
            {
                var created = CreateProcessAsUser(
                    primaryToken,
                    null,
                    commandLine,
                    IntPtr.Zero,
                    IntPtr.Zero,
                    false,
                    CREATE_UNICODE_ENVIRONMENT | NORMAL_PRIORITY_CLASS | CREATE_NO_WINDOW,
                    environment,
                    Path.GetDirectoryName(exePath),
                    ref startup,
                    out var processInfo);

                if (!created)
                {
                    _log.LogWarning("הפעלת {Exe} בסשן {Session} נכשלה (שגיאה {Error}).",
                        Path.GetFileName(exePath), sessionId, Marshal.GetLastWin32Error());

                    return null;
                }

                CloseHandle(processInfo.hProcess);
                CloseHandle(processInfo.hThread);

                _log.LogInformation("הופעל {Exe} בסשן {Session} (PID {Pid}).",
                    Path.GetFileName(exePath), sessionId, processInfo.dwProcessId);

                return processInfo.dwProcessId;
            }
            finally
            {
                if (startup.lpDesktop != IntPtr.Zero) Marshal.FreeHGlobal(startup.lpDesktop);
            }
        }
        catch (Exception ex)
        {
            _log.LogError(ex, "הפעלת תהליך בסשן {Session} נכשלה.", sessionId);
            return null;
        }
        finally
        {
            if (environment != IntPtr.Zero) DestroyEnvironmentBlock(environment);
            if (primaryToken != IntPtr.Zero) CloseHandle(primaryToken);
            if (userToken != IntPtr.Zero) CloseHandle(userToken);
        }
    }
}
