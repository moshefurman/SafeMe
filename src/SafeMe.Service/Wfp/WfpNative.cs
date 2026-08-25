using System.Runtime.InteropServices;

namespace SafeMe.Service.Wfp;

// ---------------------------------------------------------------------------
// עטיפת P/Invoke ל-Windows Filtering Platform (fwpuclnt.dll).
//
// הערות מבנה קריטיות (x64):
//   * GUID מיושר ל-4 בתים, ולכן FWPM_ACTION0 הוא 20 בתים בדיוק.
//   * FWP_VALUE0 ו-FWP_CONDITION_VALUE0 מיושרים ל-8 בתים (סוג + מצביע).
//   * איחודים (unions) מיוצגים על ידי החבר הגדול ביותר, כפי שהמהדר הנייטיבי בונה.
// כל שינוי בסדר השדות כאן ישבור את המרשלינג בשקט, ולכן אין לשנות ללא בדיקה.
// ---------------------------------------------------------------------------

internal static class WfpConstants
{
    public const uint RPC_C_AUTHN_DEFAULT = 0xFFFFFFFF;
    public const uint RPC_C_AUTHN_WINNT = 10;

    public const uint FWPM_SESSION_FLAG_DYNAMIC = 0x00000001;

    public const uint FWPM_PROVIDER_FLAG_PERSISTENT = 0x00000001;
    public const uint FWPM_SUBLAYER_FLAG_PERSISTENT = 0x00000001;

    public const uint FWPM_FILTER_FLAG_PERSISTENT = 0x00000001;
    public const uint FWPM_FILTER_FLAG_BOOTTIME = 0x00000002;
    public const uint FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT = 0x00000010;

    public const uint FWP_ACTION_FLAG_TERMINATING = 0x00001000;
    public const uint FWP_ACTION_BLOCK = 0x00000001 | FWP_ACTION_FLAG_TERMINATING;
    public const uint FWP_ACTION_PERMIT = 0x00000002 | FWP_ACTION_FLAG_TERMINATING;

    public const uint FWP_CONDITION_FLAG_IS_LOOPBACK = 0x00000001;

    public const uint ERROR_SUCCESS = 0;
    public const uint FWP_E_ALREADY_EXISTS = 0x80320009;
    public const uint FWP_E_FILTER_NOT_FOUND = 0x80320003;
    public const uint FWP_E_PROVIDER_NOT_FOUND = 0x80320005;
    public const uint FWP_E_SUBLAYER_NOT_FOUND = 0x80320007;
    public const uint FWP_E_IN_USE = 0x80320016;

    public const byte IPPROTO_ICMP = 1;
    public const byte IPPROTO_TCP = 6;
    public const byte IPPROTO_UDP = 17;
}

/// <summary>מזהי שכבות ותנאים של WFP. הערכים לקוחים מ-fwpmu.h.</summary>
internal static class WfpGuids
{
    // שכבות ALE - נקודת ההחלטה עבור connect ו-accept
    public static readonly Guid FWPM_LAYER_ALE_AUTH_CONNECT_V4 =
        new("c38d57d1-05a7-4c33-904f-7fbceee60e82");

    public static readonly Guid FWPM_LAYER_ALE_AUTH_CONNECT_V6 =
        new("4a72393b-319f-44bc-84c3-ba54dcb3b6b4");

    public static readonly Guid FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4 =
        new("e1cd9fe7-f4b5-4273-96c0-592e487b8650");

    public static readonly Guid FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6 =
        new("a3b42c97-9f04-4672-b87e-cee9c483257f");

    // תנאים
    public static readonly Guid FWPM_CONDITION_IP_REMOTE_ADDRESS =
        new("b235ae9a-1d64-49b8-a44c-5ff3d9095045");

    public static readonly Guid FWPM_CONDITION_IP_LOCAL_ADDRESS =
        new("d9ee00de-c1ef-4617-bfe3-ffd8f5a08957");

    public static readonly Guid FWPM_CONDITION_IP_PROTOCOL =
        new("3971ef2b-623e-4f9a-8cb1-6e79b806b9a7");

    public static readonly Guid FWPM_CONDITION_IP_REMOTE_PORT =
        new("c35a604d-d22b-4e1a-91b4-68f674ee674b");

    public static readonly Guid FWPM_CONDITION_IP_LOCAL_PORT =
        new("0c1ba1af-5765-453f-af22-a8f791ac775b");

    public static readonly Guid FWPM_CONDITION_ALE_APP_ID =
        new("d78e1e87-8644-4ea5-9437-d809ecefc971");

    public static readonly Guid FWPM_CONDITION_FLAGS =
        new("632ce23b-5167-435c-86d7-e903684aa80c");
}

internal enum FWP_DATA_TYPE : uint
{
    FWP_EMPTY = 0,
    FWP_UINT8 = 1,
    FWP_UINT16 = 2,
    FWP_UINT32 = 3,
    FWP_UINT64 = 4,
    FWP_BYTE_ARRAY16_TYPE = 11,
    FWP_BYTE_BLOB_TYPE = 12,
    FWP_V4_ADDR_MASK = 0x100,
    FWP_V6_ADDR_MASK = 0x101,
    FWP_RANGE_TYPE = 0x102
}

internal enum FWP_MATCH_TYPE : uint
{
    FWP_MATCH_EQUAL = 0,
    FWP_MATCH_GREATER = 1,
    FWP_MATCH_LESS = 2,
    FWP_MATCH_GREATER_OR_EQUAL = 3,
    FWP_MATCH_LESS_OR_EQUAL = 4,
    FWP_MATCH_RANGE = 5,
    FWP_MATCH_FLAGS_ALL_SET = 6,
    FWP_MATCH_FLAGS_ANY_SET = 7,
    FWP_MATCH_FLAGS_NONE_SET = 8,
    FWP_MATCH_EQUAL_CASE_INSENSITIVE = 9,
    FWP_MATCH_NOT_EQUAL = 10
}

[StructLayout(LayoutKind.Sequential)]
internal struct FWPM_DISPLAY_DATA0
{
    [MarshalAs(UnmanagedType.LPWStr)] public string name;
    [MarshalAs(UnmanagedType.LPWStr)] public string description;
}

[StructLayout(LayoutKind.Sequential)]
internal struct FWP_BYTE_BLOB
{
    public uint size;
    public IntPtr data;
}

/// <summary>FWP_VALUE0 - סוג בן 4 בתים ואחריו איחוד מיושר ל-8. סה"כ 16 בתים ב-x64.</summary>
[StructLayout(LayoutKind.Sequential)]
internal struct FWP_VALUE0
{
    public FWP_DATA_TYPE type;
    public IntPtr value;
}

[StructLayout(LayoutKind.Sequential)]
internal struct FWP_CONDITION_VALUE0
{
    public FWP_DATA_TYPE type;
    public IntPtr value;
}

/// <summary>כתובת IPv4 ומסכה, בסדר בתים של המארח (host order) כנדרש על ידי WFP.</summary>
[StructLayout(LayoutKind.Sequential)]
internal struct FWP_V4_ADDR_AND_MASK
{
    public uint addr;
    public uint mask;
}

[StructLayout(LayoutKind.Sequential)]
internal struct FWP_V6_ADDR_AND_MASK
{
    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
    public byte[] addr;

    public byte prefixLength;
}

[StructLayout(LayoutKind.Sequential)]
internal struct FWPM_FILTER_CONDITION0
{
    public Guid fieldKey;
    public FWP_MATCH_TYPE matchType;
    public FWP_CONDITION_VALUE0 conditionValue;
}

/// <summary>FWPM_ACTION0 - סוג בן 4 בתים ואחריו איחוד שגודלו GUID. סה"כ 20 בתים.</summary>
[StructLayout(LayoutKind.Sequential)]
internal struct FWPM_ACTION0
{
    public uint type;
    public Guid filterTypeOrCalloutKey;
}

[StructLayout(LayoutKind.Sequential)]
internal struct FWPM_PROVIDER0
{
    public Guid providerKey;
    public FWPM_DISPLAY_DATA0 displayData;
    public uint flags;
    public FWP_BYTE_BLOB providerData;
    [MarshalAs(UnmanagedType.LPWStr)] public string? serviceName;
}

[StructLayout(LayoutKind.Sequential)]
internal struct FWPM_SUBLAYER0
{
    public Guid subLayerKey;
    public FWPM_DISPLAY_DATA0 displayData;
    public uint flags;
    public IntPtr providerKey;
    public FWP_BYTE_BLOB providerData;
    public ushort weight;
}

[StructLayout(LayoutKind.Sequential)]
internal struct FWPM_FILTER0
{
    public Guid filterKey;
    public FWPM_DISPLAY_DATA0 displayData;
    public uint flags;
    public IntPtr providerKey;
    public FWP_BYTE_BLOB providerData;
    public Guid layerKey;
    public Guid subLayerKey;
    public FWP_VALUE0 weight;
    public uint numFilterConditions;
    public IntPtr filterCondition;
    public FWPM_ACTION0 action;

    // איחוד { UINT64 rawContext; GUID providerContextKey; } מיושר ל-8, גודל 16
    public ulong rawContextLow;
    public ulong rawContextHigh;

    public IntPtr reserved;
    public ulong filterId;
    public FWP_VALUE0 effectiveWeight;
}

[StructLayout(LayoutKind.Sequential)]
internal struct FWPM_SESSION0
{
    public Guid sessionKey;
    public FWPM_DISPLAY_DATA0 displayData;
    public uint flags;
    public uint txnWaitTimeoutInMSec;
    public uint processId;
    public IntPtr sid;
    [MarshalAs(UnmanagedType.LPWStr)] public string? username;
    [MarshalAs(UnmanagedType.Bool)] public bool kernelMode;
}

internal static partial class WfpNative
{
    private const string Fwpuclnt = "fwpuclnt.dll";

    [LibraryImport(Fwpuclnt, StringMarshalling = StringMarshalling.Utf16)]
    internal static partial uint FwpmEngineOpen0(
        string? serverName,
        uint authnService,
        IntPtr authIdentity,
        IntPtr session,
        out IntPtr engineHandle);

    [LibraryImport(Fwpuclnt)]
    internal static partial uint FwpmEngineClose0(IntPtr engineHandle);

    [LibraryImport(Fwpuclnt)]
    internal static partial uint FwpmTransactionBegin0(IntPtr engineHandle, uint flags);

    [LibraryImport(Fwpuclnt)]
    internal static partial uint FwpmTransactionCommit0(IntPtr engineHandle);

    [LibraryImport(Fwpuclnt)]
    internal static partial uint FwpmTransactionAbort0(IntPtr engineHandle);

    [DllImport(Fwpuclnt, CharSet = CharSet.Unicode)]
    internal static extern uint FwpmProviderAdd0(IntPtr engineHandle, ref FWPM_PROVIDER0 provider, IntPtr sd);

    [DllImport(Fwpuclnt)]
    internal static extern uint FwpmProviderDeleteByKey0(IntPtr engineHandle, ref Guid key);

    [DllImport(Fwpuclnt, CharSet = CharSet.Unicode)]
    internal static extern uint FwpmSubLayerAdd0(IntPtr engineHandle, ref FWPM_SUBLAYER0 subLayer, IntPtr sd);

    [DllImport(Fwpuclnt)]
    internal static extern uint FwpmSubLayerDeleteByKey0(IntPtr engineHandle, ref Guid key);

    [DllImport(Fwpuclnt, CharSet = CharSet.Unicode)]
    internal static extern uint FwpmFilterAdd0(
        IntPtr engineHandle, ref FWPM_FILTER0 filter, IntPtr sd, out ulong id);

    [LibraryImport(Fwpuclnt)]
    internal static partial uint FwpmFilterDeleteById0(IntPtr engineHandle, ulong id);

    [LibraryImport(Fwpuclnt)]
    internal static partial uint FwpmFilterGetById0(IntPtr engineHandle, ulong id, out IntPtr filter);

    [LibraryImport(Fwpuclnt)]
    internal static partial void FwpmFreeMemory0(ref IntPtr p);

    /// <summary>ממיר נתיב קובץ לפורמט ה-App ID שמצופה על ידי FWPM_CONDITION_ALE_APP_ID.</summary>
    [DllImport(Fwpuclnt, CharSet = CharSet.Unicode)]
    internal static extern uint FwpmGetAppIdFromFileName0(string fileName, out IntPtr appId);
}
