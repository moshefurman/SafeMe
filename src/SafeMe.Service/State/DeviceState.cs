using System.Runtime.Versioning;
using SafeMe.Core.Models;

namespace SafeMe.Service.State;

/// <summary>זהות המכשיר וחומר המפתח שהתקבל מהשרת ברישום.</summary>
public sealed class DeviceState
{
    public Guid InstallId { get; set; } = Guid.NewGuid();
    public Guid? DeviceId { get; set; }
    public string? DeviceToken { get; set; }
    public string? LicenseKey { get; set; }
    public DateTimeOffset? LicenseExpiresUtc { get; set; }
    public bool LicenseValid { get; set; }

    public UninstallKeyMode UninstallKeyMode { get; set; } = UninstallKeyMode.Rsa;

    /// <summary>פרופיל ההתקנה שנקבע ברישום ואינו משתנה.</summary>
    public string? InstallProfile { get; set; }

    /// <summary>מצב האכיפה ההתחלתי מההתקנה.</summary>
    public EnforcementMode EnforcementMode { get; set; } = EnforcementMode.Enforce;

    /// <summary>מפתח ציבורי של השרת, לאימות קודי הסרה ולאימות חתימת מדיניות.</summary>
    public string? ServerPublicKeyPem { get; set; }

    /// <summary>מפתח ציבורי נפרד, לאימות קודי הסרה בלבד.</summary>
    public string? UninstallPublicKeyPem { get; set; }

    /// <summary>מפתח ציבורי נפרד, לאימות היתרי הקלה בלבד.</summary>
    public string? LooseningPublicKeyPem { get; set; }

    /// <summary>סוד המכשיר במצב HMAC, מקודד Base64. ריק במצב RSA.</summary>
    public string? DeviceSecretBase64 { get; set; }

    public string? PolicyEtag { get; set; }
    public long HeartbeatSequence { get; set; }
    public DateTimeOffset? LastServerContactUtc { get; set; }

    /// <summary>עוגן זמן שמתקבל מהשרת, לזיהוי הזזת שעון מקומית.</summary>
    public DateTimeOffset? LastServerUtc { get; set; }

    public byte[]? GetDeviceSecret() =>
        string.IsNullOrEmpty(DeviceSecretBase64) ? null : Convert.FromBase64String(DeviceSecretBase64);
}

/// <summary>גישה מרוכזת ומסונכרנת למצב המכשיר.</summary>
[SupportedOSPlatform("windows")]
public sealed class DeviceStateStore
{
    private readonly object _sync = new();
    private DeviceState? _cached;

    public DeviceState Load()
    {
        lock (_sync)
        {
            _cached ??= SecureStore.Read<DeviceState>(SafeMePaths.DeviceStateFile) ?? new DeviceState();
            return _cached;
        }
    }

    public void Save(DeviceState state)
    {
        lock (_sync)
        {
            _cached = state;
            SecureStore.Write(SafeMePaths.DeviceStateFile, state);
        }
    }

    public void Update(Action<DeviceState> mutate)
    {
        lock (_sync)
        {
            var state = Load();
            mutate(state);
            Save(state);
        }
    }
}
