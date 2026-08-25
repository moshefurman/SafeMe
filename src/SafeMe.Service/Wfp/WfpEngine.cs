using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using Microsoft.Extensions.Logging;

namespace SafeMe.Service.Wfp;

/// <summary>
/// עטיפה ברמה נמוכה מעל Windows Filtering Platform.
/// אחראית על פתיחת מנוע, ניהול Provider ו-SubLayer, והוספה או מחיקה של חוקים.
/// המחלקה אינה יודעת דבר על מדיניות; היא רק מתרגמת בקשות לחוקי WFP.
/// </summary>
[SupportedOSPlatform("windows")]
internal sealed class WfpEngine : IDisposable
{
    /// <summary>מזהי ה-Provider וה-SubLayer של SafeMe. קבועים לאורך חיי המוצר.</summary>
    public static readonly Guid ProviderKey = new("8F2A6C31-4B7D-4E19-9C55-1A2B3C4D5E60");

    public static readonly Guid SubLayerKey = new("4D1E77A5-9C31-4F82-B0A7-6E5D4C3B2A19");

    /// <summary>
    /// משקל ה-SubLayer. גבוה מספיק כדי לגבור על שכבות ברירת המחדל של חומת האש,
    /// אך מתחת לשכבות מערכת קריטיות.
    /// </summary>
    private const ushort SubLayerWeight = 0xFF00;

    private readonly ILogger _log;
    private readonly List<ulong> _filterIds = new();
    private readonly object _sync = new();

    private IntPtr _engine = IntPtr.Zero;

    public WfpEngine(ILogger log) => _log = log;

    public bool IsOpen => _engine != IntPtr.Zero;

    public int FilterCount
    {
        get { lock (_sync) return _filterIds.Count; }
    }

    // ------------------------------------------------------------ מחזור חיים

    /// <summary>
    /// פותח את המנוע. ב-dynamic=true כל החוקים נמחקים אוטומטית כשהתהליך מסתיים,
    /// וזו הגנת Fail-Safe מפני מצב שבו השירות קורס והמכשיר נשאר חסום.
    /// </summary>
    public bool Open(bool dynamic = true)
    {
        lock (_sync)
        {
            if (IsOpen) return true;

            using var arena = new NativeArena();
            var sessionPtr = IntPtr.Zero;

            if (dynamic)
            {
                var session = new FWPM_SESSION0
                {
                    displayData = new FWPM_DISPLAY_DATA0
                    {
                        name = "SafeMe Agent Session",
                        description = "SafeMe enforcement session"
                    },
                    flags = WfpConstants.FWPM_SESSION_FLAG_DYNAMIC,
                    txnWaitTimeoutInMSec = 5000
                };

                sessionPtr = arena.AllocStruct(session);
            }

            var status = WfpNative.FwpmEngineOpen0(
                null, WfpConstants.RPC_C_AUTHN_DEFAULT, IntPtr.Zero, sessionPtr, out var handle);

            if (status != WfpConstants.ERROR_SUCCESS)
            {
                _log.LogError("פתיחת מנוע WFP נכשלה. קוד שגיאה 0x{Status:X8}. ייתכן ששירות BFE מושבת.", status);
                return false;
            }

            _engine = handle;
            _log.LogInformation("מנוע WFP נפתח בהצלחה (מצב {Mode}).", dynamic ? "דינמי" : "פרסיסטנטי");

            return true;
        }
    }

    public void Close()
    {
        lock (_sync)
        {
            if (!IsOpen) return;

            WfpNative.FwpmEngineClose0(_engine);
            _engine = IntPtr.Zero;
            _filterIds.Clear();
        }
    }

    public void Dispose() => Close();

    // ------------------------------------------------------- Provider ו-SubLayer

    /// <summary>
    /// רושם את ה-Provider וה-SubLayer של SafeMe. קיים כבר אינו שגיאה.
    /// ה-SubLayer הייעודי הוא מה שמאפשר לחוקים שלנו לגבור על חוקי משתמש.
    /// </summary>
    public bool EnsureInfrastructure()
    {
        lock (_sync)
        {
            if (!IsOpen) return false;

            using var arena = new NativeArena();

            var provider = new FWPM_PROVIDER0
            {
                providerKey = ProviderKey,
                displayData = new FWPM_DISPLAY_DATA0
                {
                    name = "SafeMe Agent",
                    description = "SafeMe filtered-connection enforcement provider"
                },
                flags = 0,
                serviceName = null
            };

            var status = WfpNative.FwpmProviderAdd0(_engine, ref provider, IntPtr.Zero);

            if (status != WfpConstants.ERROR_SUCCESS && status != WfpConstants.FWP_E_ALREADY_EXISTS)
            {
                _log.LogError("רישום Provider נכשל. קוד 0x{Status:X8}.", status);
                return false;
            }

            var subLayer = new FWPM_SUBLAYER0
            {
                subLayerKey = SubLayerKey,
                displayData = new FWPM_DISPLAY_DATA0
                {
                    name = "SafeMe Enforcement",
                    description = "SafeMe policy enforcement sub-layer"
                },
                flags = 0,
                providerKey = arena.AllocStruct(ProviderKey),
                weight = SubLayerWeight
            };

            status = WfpNative.FwpmSubLayerAdd0(_engine, ref subLayer, IntPtr.Zero);

            if (status != WfpConstants.ERROR_SUCCESS && status != WfpConstants.FWP_E_ALREADY_EXISTS)
            {
                _log.LogError("רישום SubLayer נכשל. קוד 0x{Status:X8}.", status);
                return false;
            }

            return true;
        }
    }

    /// <summary>מסיר את התשתית. נקרא רק בהסרה מאושרת של המוצר.</summary>
    public void RemoveInfrastructure()
    {
        lock (_sync)
        {
            if (!IsOpen) return;

            var subLayer = SubLayerKey;
            var provider = ProviderKey;

            WfpNative.FwpmSubLayerDeleteByKey0(_engine, ref subLayer);
            WfpNative.FwpmProviderDeleteByKey0(_engine, ref provider);
        }
    }

    // ------------------------------------------------------------ טרנזקציות

    /// <summary>
    /// מריץ קבוצת שינויים בטרנזקציה אחת. כישלון באמצע מבטל את כל השינויים,
    /// כדי שלא ייווצר מצב ביניים שבו יש חסימה בלי החריגים שמלווים אותה.
    /// </summary>
    public bool RunInTransaction(Action body)
    {
        lock (_sync)
        {
            if (!IsOpen) return false;

            var status = WfpNative.FwpmTransactionBegin0(_engine, 0);

            if (status != WfpConstants.ERROR_SUCCESS)
            {
                _log.LogError("פתיחת טרנזקציית WFP נכשלה. קוד 0x{Status:X8}.", status);
                return false;
            }

            try
            {
                body();

                status = WfpNative.FwpmTransactionCommit0(_engine);

                if (status != WfpConstants.ERROR_SUCCESS)
                {
                    _log.LogError("שמירת טרנזקציית WFP נכשלה. קוד 0x{Status:X8}.", status);
                    return false;
                }

                return true;
            }
            catch (Exception ex)
            {
                WfpNative.FwpmTransactionAbort0(_engine);
                _log.LogError(ex, "טרנזקציית WFP בוטלה עקב חריגה.");

                return false;
            }
        }
    }

    // ------------------------------------------------------------ הוספת חוקים

    /// <summary>חוסם את כל התעבורה היוצאת ב-IPv4 וב-IPv6. משקל נמוך כדי שחוקי ההיתר יגברו.</summary>
    public void AddBlockAllOutbound(ulong weight = 100)
    {
        AddFilter(WfpGuids.FWPM_LAYER_ALE_AUTH_CONNECT_V4, [], WfpConstants.FWP_ACTION_BLOCK, weight,
            "SafeMe - חסימת כל היוצא IPv4");

        AddFilter(WfpGuids.FWPM_LAYER_ALE_AUTH_CONNECT_V6, [], WfpConstants.FWP_ACTION_BLOCK, weight,
            "SafeMe - חסימת כל היוצא IPv6");
    }

    /// <summary>חוסם גם תעבורה נכנסת. משמש בנעילת חירום מלאה.</summary>
    public void AddBlockAllInbound(ulong weight = 100)
    {
        AddFilter(WfpGuids.FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4, [], WfpConstants.FWP_ACTION_BLOCK, weight,
            "SafeMe - חסימת כל הנכנס IPv4");

        AddFilter(WfpGuids.FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6, [], WfpConstants.FWP_ACTION_BLOCK, weight,
            "SafeMe - חסימת כל הנכנס IPv6");
    }

    /// <summary>מתיר תעבורה ליעד לפי CIDR. תומך ב-IPv4 וב-IPv6.</summary>
    public bool AddPermitRemoteCidr(string cidr, ulong weight, NativeArena arena)
    {
        if (!TryParseCidr(cidr, out var address, out var prefix))
        {
            _log.LogWarning("טווח כתובות לא תקין ולכן דולג: {Cidr}", cidr);
            return false;
        }

        if (address!.AddressFamily == AddressFamily.InterNetwork)
        {
            var addrValue = ToHostOrderUInt32(address);
            var mask = prefix == 0 ? 0u : uint.MaxValue << (32 - prefix);

            var blob = arena.AllocStruct(new FWP_V4_ADDR_AND_MASK { addr = addrValue, mask = mask });

            var condition = new FWPM_FILTER_CONDITION0
            {
                fieldKey = WfpGuids.FWPM_CONDITION_IP_REMOTE_ADDRESS,
                matchType = FWP_MATCH_TYPE.FWP_MATCH_EQUAL,
                conditionValue = new FWP_CONDITION_VALUE0
                {
                    type = FWP_DATA_TYPE.FWP_V4_ADDR_MASK,
                    value = blob
                }
            };

            AddFilter(WfpGuids.FWPM_LAYER_ALE_AUTH_CONNECT_V4, [condition],
                WfpConstants.FWP_ACTION_PERMIT, weight, $"SafeMe - היתר {cidr}");

            return true;
        }

        // IPv6: המבנה מכיל מערך בתים, ולכן נכתב ידנית לזיכרון הנייטיבי
        var v6 = arena.Alloc(17);
        var bytes = address.GetAddressBytes();

        Marshal.Copy(bytes, 0, v6, 16);
        Marshal.WriteByte(v6, 16, (byte)prefix);

        var v6Condition = new FWPM_FILTER_CONDITION0
        {
            fieldKey = WfpGuids.FWPM_CONDITION_IP_REMOTE_ADDRESS,
            matchType = FWP_MATCH_TYPE.FWP_MATCH_EQUAL,
            conditionValue = new FWP_CONDITION_VALUE0
            {
                type = FWP_DATA_TYPE.FWP_V6_ADDR_MASK,
                value = v6
            }
        };

        AddFilter(WfpGuids.FWPM_LAYER_ALE_AUTH_CONNECT_V6, [v6Condition],
            WfpConstants.FWP_ACTION_PERMIT, weight, $"SafeMe - היתר {cidr}");

        return true;
    }

    /// <summary>מתיר תעבורה לפורט יעד מסוים בפרוטוקול נתון.</summary>
    public void AddPermitRemotePort(ushort port, byte protocol, ulong weight)
    {
        FWPM_FILTER_CONDITION0[] conditions =
        [
            new()
            {
                fieldKey = WfpGuids.FWPM_CONDITION_IP_PROTOCOL,
                matchType = FWP_MATCH_TYPE.FWP_MATCH_EQUAL,
                // ערכים בני 8 ו-16 ביט נשמרים בתוך האיחוד עצמו ולא כמצביע
                conditionValue = new FWP_CONDITION_VALUE0
                {
                    type = FWP_DATA_TYPE.FWP_UINT8,
                    value = (IntPtr)(long)protocol
                }
            },
            new()
            {
                fieldKey = WfpGuids.FWPM_CONDITION_IP_REMOTE_PORT,
                matchType = FWP_MATCH_TYPE.FWP_MATCH_EQUAL,
                conditionValue = new FWP_CONDITION_VALUE0
                {
                    type = FWP_DATA_TYPE.FWP_UINT16,
                    value = (IntPtr)(long)port
                }
            }
        ];

        AddFilter(WfpGuids.FWPM_LAYER_ALE_AUTH_CONNECT_V4, conditions,
            WfpConstants.FWP_ACTION_PERMIT, weight, $"SafeMe - היתר פורט {port}");

        AddFilter(WfpGuids.FWPM_LAYER_ALE_AUTH_CONNECT_V6, conditions,
            WfpConstants.FWP_ACTION_PERMIT, weight, $"SafeMe - היתר פורט {port} IPv6");
    }

    /// <summary>מתיר תעבורת לולאה מקומית. בלעדיה נשברת תקשורת פנימית של המערכת.</summary>
    public void AddPermitLoopback(ulong weight)
    {
        var condition = new FWPM_FILTER_CONDITION0
        {
            fieldKey = WfpGuids.FWPM_CONDITION_FLAGS,
            matchType = FWP_MATCH_TYPE.FWP_MATCH_FLAGS_ANY_SET,
            conditionValue = new FWP_CONDITION_VALUE0
            {
                type = FWP_DATA_TYPE.FWP_UINT32,
                value = (IntPtr)(long)WfpConstants.FWP_CONDITION_FLAG_IS_LOOPBACK
            }
        };

        AddFilter(WfpGuids.FWPM_LAYER_ALE_AUTH_CONNECT_V4, [condition],
            WfpConstants.FWP_ACTION_PERMIT, weight, "SafeMe - היתר לולאה מקומית");

        AddFilter(WfpGuids.FWPM_LAYER_ALE_AUTH_CONNECT_V6, [condition],
            WfpConstants.FWP_ACTION_PERMIT, weight, "SafeMe - היתר לולאה מקומית IPv6");
    }

    /// <summary>
    /// מתיר לתהליך מסוים לתקשר, לפי נתיב קובץ ההרצה.
    /// חיוני כדי שהשירות עצמו ימשיך לדבר עם שרת הניהול גם בזמן נעילה.
    /// </summary>
    public bool AddPermitApplication(string exePath, ulong weight, NativeArena arena)
    {
        if (!File.Exists(exePath))
        {
            _log.LogWarning("נתיב הרצה לא נמצא ולכן דולג: {Path}", exePath);
            return false;
        }

        var status = WfpNative.FwpmGetAppIdFromFileName0(exePath, out var appIdPtr);

        if (status != WfpConstants.ERROR_SUCCESS || appIdPtr == IntPtr.Zero)
        {
            _log.LogWarning("קבלת App ID עבור {Path} נכשלה. קוד 0x{Status:X8}.", exePath, status);
            return false;
        }

        try
        {
            // מעתיקים את ה-blob לזיכרון שבשליטתנו כדי לשחרר מיד את זה של WFP
            var native = Marshal.PtrToStructure<FWP_BYTE_BLOB>(appIdPtr);
            var data = new byte[native.size];

            Marshal.Copy(native.data, data, 0, (int)native.size);

            var copyPtr = arena.AllocBytes(data);
            var blobPtr = arena.AllocStruct(new FWP_BYTE_BLOB { size = native.size, data = copyPtr });

            var condition = new FWPM_FILTER_CONDITION0
            {
                fieldKey = WfpGuids.FWPM_CONDITION_ALE_APP_ID,
                matchType = FWP_MATCH_TYPE.FWP_MATCH_EQUAL,
                conditionValue = new FWP_CONDITION_VALUE0
                {
                    type = FWP_DATA_TYPE.FWP_BYTE_BLOB_TYPE,
                    value = blobPtr
                }
            };

            var name = $"SafeMe - היתר יישום {Path.GetFileName(exePath)}";

            AddFilter(WfpGuids.FWPM_LAYER_ALE_AUTH_CONNECT_V4, [condition],
                WfpConstants.FWP_ACTION_PERMIT, weight, name);

            AddFilter(WfpGuids.FWPM_LAYER_ALE_AUTH_CONNECT_V6, [condition],
                WfpConstants.FWP_ACTION_PERMIT, weight, name + " IPv6");

            return true;
        }
        finally
        {
            WfpNative.FwpmFreeMemory0(ref appIdPtr);
        }
    }

    /// <summary>הוספת חוק גולמי. מחזיר את מזהה החוק, או 0 בכישלון.</summary>
    public ulong AddFilter(
        Guid layer,
        IReadOnlyList<FWPM_FILTER_CONDITION0> conditions,
        uint action,
        ulong weight,
        string name,
        bool persistent = false)
    {
        if (!IsOpen) return 0;

        using var arena = new NativeArena();

        var filter = new FWPM_FILTER0
        {
            filterKey = Guid.NewGuid(),
            displayData = new FWPM_DISPLAY_DATA0 { name = name, description = name },
            flags = persistent ? WfpConstants.FWPM_FILTER_FLAG_PERSISTENT : 0,
            providerKey = arena.AllocStruct(ProviderKey),
            layerKey = layer,
            subLayerKey = SubLayerKey,
            // משקל בן 64 ביט נמסר כמצביע, בשונה מערכים קטנים שנשמרים באיחוד
            weight = new FWP_VALUE0
            {
                type = FWP_DATA_TYPE.FWP_UINT64,
                value = arena.AllocUInt64(weight)
            },
            numFilterConditions = (uint)conditions.Count,
            filterCondition = conditions.Count == 0 ? IntPtr.Zero : arena.AllocArray(conditions),
            action = new FWPM_ACTION0 { type = action }
        };

        var status = WfpNative.FwpmFilterAdd0(_engine, ref filter, IntPtr.Zero, out var id);

        if (status != WfpConstants.ERROR_SUCCESS)
        {
            _log.LogError("הוספת חוק '{Name}' נכשלה. קוד 0x{Status:X8}.", name, status);
            return 0;
        }

        lock (_sync) _filterIds.Add(id);
        _log.LogDebug("נוסף חוק WFP {Id}: {Name}", id, name);

        return id;
    }

    // ------------------------------------------------------------ מחיקה ואימות

    /// <summary>מוחק את כל החוקים שנרשמו על ידי המופע הזה.</summary>
    public void DeleteAllFilters()
    {
        lock (_sync)
        {
            if (!IsOpen)
            {
                _filterIds.Clear();
                return;
            }

            foreach (var id in _filterIds)
            {
                var status = WfpNative.FwpmFilterDeleteById0(_engine, id);

                if (status != WfpConstants.ERROR_SUCCESS && status != WfpConstants.FWP_E_FILTER_NOT_FOUND)
                    _log.LogWarning("מחיקת חוק {Id} נכשלה. קוד 0x{Status:X8}.", id, status);
            }

            _filterIds.Clear();
        }
    }

    /// <summary>
    /// מוודא שכל החוקים שנרשמו עדיין קיימים ב-BFE.
    /// מחיקה ידנית של חוקים היא אירוע חבלה שדורש בנייה מחדש ודיווח.
    /// </summary>
    public bool VerifyIntegrity(out int missing)
    {
        missing = 0;

        lock (_sync)
        {
            if (!IsOpen) return false;

            foreach (var id in _filterIds)
            {
                var status = WfpNative.FwpmFilterGetById0(_engine, id, out var ptr);

                if (status == WfpConstants.ERROR_SUCCESS && ptr != IntPtr.Zero)
                    WfpNative.FwpmFreeMemory0(ref ptr);
                else
                    missing++;
            }

            return missing == 0;
        }
    }

    // ------------------------------------------------------------ עזר

    /// <summary>WFP מצפה לכתובות IPv4 בסדר בתים של המארח, ולא בסדר הרשת.</summary>
    private static uint ToHostOrderUInt32(IPAddress address)
    {
        var bytes = address.GetAddressBytes();
        return ((uint)bytes[0] << 24) | ((uint)bytes[1] << 16) | ((uint)bytes[2] << 8) | bytes[3];
    }

    public static bool TryParseCidr(string cidr, out IPAddress? address, out int prefixLength)
    {
        address = null;
        prefixLength = 0;

        if (string.IsNullOrWhiteSpace(cidr)) return false;

        var parts = cidr.Trim().Split('/');

        if (!IPAddress.TryParse(parts[0], out address)) return false;

        var maxPrefix = address.AddressFamily == AddressFamily.InterNetwork ? 32 : 128;

        if (parts.Length == 1)
        {
            prefixLength = maxPrefix;
            return true;
        }

        if (!int.TryParse(parts[1], out prefixLength)) return false;

        return prefixLength >= 0 && prefixLength <= maxPrefix;
    }
}
