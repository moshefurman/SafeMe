using System.Management;
using System.Runtime.Versioning;
using Microsoft.Extensions.Logging;
using Microsoft.Win32;
using SafeMe.Core.Abstractions;
using SafeMe.Core.Security;

namespace SafeMe.Service.State;

/// <summary>
/// אוסף רכיבי חומרה יציבים ובונה מהם מזהה מחשב.
///
/// נבחרו במכוון רכיבים שאינם משתנים בהחלפת דיסק או כרטיס רשת,
/// כדי שרישיון לא ינותק בגלל שדרוג חומרה שגרתי.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class WindowsHardwareIdProvider : IHardwareIdProvider
{
    private readonly ILogger<WindowsHardwareIdProvider> _log;
    private readonly Lock _sync = new();

    private string? _cached;

    public WindowsHardwareIdProvider(ILogger<WindowsHardwareIdProvider> log) => _log = log;

    public string GetHardwareId()
    {
        lock (_sync)
        {
            if (_cached is not null) return _cached;

            var components = new List<string?>
            {
                ReadMachineGuid(),
                QueryWmi("Win32_ComputerSystemProduct", "UUID"),
                QueryWmi("Win32_BaseBoard", "SerialNumber"),
                QueryWmi("Win32_Processor", "ProcessorId")
            };

            var usable = components.Count(c => HardwareIdBuilder.Normalize(c) is not null);

            if (usable == 0)
            {
                // נפילה אחורה למזהה יציב פחות, כדי שהסוכן לא ייתקע לגמרי.
                // המקרה מדווח כדי שהשרת יוכל לסמן את המחשב כבעל זיהוי חלש.
                _log.LogWarning("לא נמצא רכיב חומרה יציב. נעשה שימוש בזיהוי חלופי.");
                components.Add(Environment.MachineName + "|" + Environment.ProcessorCount);
            }
            else if (usable < 2)
            {
                _log.LogWarning("נמצא רק רכיב חומרה יציב אחד. עוצמת הזיהוי נמוכה מהרגיל.");
            }

            _cached = HardwareIdBuilder.Build(components);
            _log.LogInformation("מזהה חומרה נבנה מ-{Count} רכיבים.", usable);

            return _cached;
        }
    }

    private string? ReadMachineGuid()
    {
        try
        {
            using var key = RegistryKey
                .OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64)
                .OpenSubKey(@"SOFTWARE\Microsoft\Cryptography");

            return key?.GetValue("MachineGuid") as string;
        }
        catch (Exception ex)
        {
            _log.LogDebug(ex, "קריאת MachineGuid נכשלה.");
            return null;
        }
    }

    private string? QueryWmi(string className, string property)
    {
        try
        {
            using var searcher = new ManagementObjectSearcher($"SELECT {property} FROM {className}");

            foreach (var item in searcher.Get())
            {
                using var mo = (ManagementObject)item;
                var value = mo[property]?.ToString();

                if (!string.IsNullOrWhiteSpace(value)) return value;
            }
        }
        catch (Exception ex)
        {
            _log.LogDebug(ex, "שאילתת WMI {Class}.{Property} נכשלה.", className, property);
        }

        return null;
    }

    /// <summary>מדווח אם המחשב מזוהה כמכונה וירטואלית, לצורך ניטור בצד השרת.</summary>
    public bool LooksLikeVirtualMachine()
    {
        var model = QueryWmi("Win32_ComputerSystem", "Model") ?? "";
        var manufacturer = QueryWmi("Win32_ComputerSystem", "Manufacturer") ?? "";
        var haystack = (model + " " + manufacturer).ToLowerInvariant();

        string[] markers = ["virtualbox", "vmware", "kvm", "qemu", "xen", "virtual machine", "hyper-v", "parallels"];

        return markers.Any(haystack.Contains);
    }
}
