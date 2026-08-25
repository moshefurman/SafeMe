using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;

namespace SafeMe.Service.Ipc;

/// <summary>
/// בודק אם התהליך שבצד השני של הצינור רץ בהרשאות מורמות.
///
/// זו נקודת ההרשאה היחידה לפעולות רגישות כמו הפקת אתגר הסרה.
/// לא מסתמכים על זהות המשתמש בלבד, כי משתמש שהוא מנהל אך אינו מורם
/// אינו אמור לקבל גישה לפעולות האלה.
/// </summary>
[SupportedOSPlatform("windows")]
internal static partial class ClientElevation
{
    private const uint TOKEN_QUERY = 0x0008;
    private const uint PROCESS_QUERY_LIMITED_INFORMATION = 0x1000;
    private const int TokenElevation = 20;

    [StructLayout(LayoutKind.Sequential)]
    private struct TOKEN_ELEVATION
    {
        public uint TokenIsElevated;
    }

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool GetNamedPipeClientProcessId(IntPtr pipe, out uint clientProcessId);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    private static partial IntPtr OpenProcess(uint desiredAccess,
        [MarshalAs(UnmanagedType.Bool)] bool inheritHandle, uint processId);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool CloseHandle(IntPtr handle);

    [LibraryImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool OpenProcessToken(IntPtr process, uint desiredAccess, out IntPtr tokenHandle);

    [LibraryImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool GetTokenInformation(IntPtr token, int informationClass,
        IntPtr information, uint informationLength, out uint returnLength);

    /// <summary>מזהה התהליך של הלקוח, או null אם לא ניתן לקבוע.</summary>
    public static uint? GetClientProcessId(NamedPipeServerStream pipe)
    {
        try
        {
            var handle = pipe.SafePipeHandle.DangerousGetHandle();

            return GetNamedPipeClientProcessId(handle, out var pid) ? pid : null;
        }
        catch (Exception)
        {
            return null;
        }
    }

    /// <summary>
    /// מחזיר true רק אם הוכח שהלקוח מורם. כל ספק או כישלון מוביל ל-false,
    /// כלומר ברירת המחדל היא דחייה.
    /// </summary>
    public static bool IsClientElevated(NamedPipeServerStream pipe)
    {
        var pid = GetClientProcessId(pipe);
        if (pid is null) return false;

        var process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid.Value);
        if (process == IntPtr.Zero) return false;

        var token = IntPtr.Zero;
        var buffer = IntPtr.Zero;

        try
        {
            if (!OpenProcessToken(process, TOKEN_QUERY, out token)) return false;

            var size = (uint)Marshal.SizeOf<TOKEN_ELEVATION>();
            buffer = Marshal.AllocHGlobal((int)size);

            if (!GetTokenInformation(token, TokenElevation, buffer, size, out _)) return false;

            var elevation = Marshal.PtrToStructure<TOKEN_ELEVATION>(buffer);

            return elevation.TokenIsElevated != 0;
        }
        catch (Exception)
        {
            return false;
        }
        finally
        {
            if (buffer != IntPtr.Zero) Marshal.FreeHGlobal(buffer);
            if (token != IntPtr.Zero) CloseHandle(token);

            CloseHandle(process);
        }
    }
}
