using System.Diagnostics;
using System.Net;
using System.Runtime.InteropServices;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Runtime.Versioning;
using System.Text.RegularExpressions;
using Microsoft.Extensions.Logging;
using FilterPlus.Core.Models;
using FilterPlus.Core.Policy;

namespace FilterPlus.Service.Audit;

/// <summary>
/// מזהה את הרשת שהמחשב מחובר אליה: כתובת ציבורית, Reverse DNS,
/// שיוך לטווחי כתובות של ספקים, ומאפייני המתאמים הפעילים.
///
/// שלושה מארבעת וקטורי הזיהוי מטופלים כאן, ולכן זהו הרכיב המרכזי בהכרעת זהות הספק.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed partial class NetworkIdentityAuditor
{
    private readonly ILogger<NetworkIdentityAuditor> _log;
    private readonly IHttpClientFactory _httpFactory;

    /// <summary>שירותים ניטרליים לגילוי הכתובת הציבורית. מנוסים לפי הסדר.</summary>
    private static readonly string[] PublicIpServices =
    [
        "https://api.ipify.org",
        "https://checkip.amazonaws.com",
        "https://ifconfig.me/ip"
    ];

    /// <summary>
    /// שירות זיהוי ספק האינטרנט.
    ///
    /// אחד ולא רשימה, בכוונה: כתובת ציבורית היא אותו מספר מכל
    /// שירות, ולכן אפשר לנסות כמה. שם ספק הוא טקסט שכל מאגר כותב
    /// אחרת, ושני מקורות היו נראים כשתי החלפות ספק.
    /// </summary>
    private const string IspService = "https://ipinfo.io/json";

    public NetworkIdentityAuditor(ILogger<NetworkIdentityAuditor> log, IHttpClientFactory httpFactory)
    {
        _log = log;
        _httpFactory = httpFactory;
    }

    /// <summary>מגלה את הכתובת הציבורית של המחשב.</summary>
    public async Task<string?> GetPublicIpAsync(CancellationToken ct)
    {
        var client = _httpFactory.CreateClient("probe");

        foreach (var service in PublicIpServices)
        {
            try
            {
                using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
                cts.CancelAfter(TimeSpan.FromSeconds(5));

                var text = (await client.GetStringAsync(service, cts.Token)).Trim();

                if (IPAddress.TryParse(text, out var ip)) return ip.ToString();
            }
            catch (Exception ex)
            {
                _log.LogDebug(ex, "גילוי כתובת ציבורית דרך {Service} נכשל.", service);
            }
        }

        return null;
    }

    /// <summary>
    /// מי מספק את האינטרנט ברגע זה.
    ///
    /// ipinfo.io מחזיר את השדה org, ובו מספר ה-ASN ושם הספק יחד.
    /// הפירוק יושב ב-<see cref="IspIdentity"/> ונבדק שם; כאן רק
    /// היציאה החוצה.
    ///
    /// כישלון מחזיר <see cref="IspIdentity.Unknown"/> ולא זורק.
    /// הבדיקה הזו נכשלת בדיוק כשהרשת חסומה — ומחשב שנחסם אינו
    /// אמור להיראות כאילו עבר לספק חדש.
    /// </summary>
    public async Task<IspIdentity> GetIspAsync(CancellationToken ct)
    {
        try
        {
            var client = _httpFactory.CreateClient("probe");

            using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            cts.CancelAfter(TimeSpan.FromSeconds(5));

            return IspIdentity.Read(await client.GetStringAsync(IspService, cts.Token));
        }
        catch (Exception ex)
        {
            _log.LogDebug(ex, "זיהוי ספק האינטרנט נכשל.");
            return IspIdentity.Unknown;
        }
    }

    public async Task<string?> GetReverseDnsAsync(string? publicIp, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(publicIp)) return null;

        try
        {
            var entry = await Dns.GetHostEntryAsync(publicIp, ct);
            return entry.HostName;
        }
        catch (Exception ex)
        {
            _log.LogDebug(ex, "Reverse DNS עבור {Ip} נכשל.", publicIp);
            return null;
        }
    }

    /// <summary>בודק אם כתובת נמצאת באחד מטווחי ה-CIDR של הספק.</summary>
    public static bool IsInAnyCidr(string? ip, IEnumerable<string> cidrs)
    {
        if (!IPAddress.TryParse(ip, out var address)) return false;

        return cidrs.Any(cidr => IsInCidr(address, cidr));
    }

    public static bool IsInCidr(IPAddress address, string cidr)
    {
        var parts = cidr.Split('/');

        if (!IPAddress.TryParse(parts[0], out var network)) return false;
        if (network.AddressFamily != address.AddressFamily) return false;

        var maxPrefix = address.AddressFamily == AddressFamily.InterNetwork ? 32 : 128;
        var prefix = maxPrefix;

        if (parts.Length > 1 && !int.TryParse(parts[1], out prefix)) return false;
        if (prefix < 0 || prefix > maxPrefix) return false;

        var addressBytes = address.GetAddressBytes();
        var networkBytes = network.GetAddressBytes();

        var fullBytes = prefix / 8;
        var remainingBits = prefix % 8;

        for (var i = 0; i < fullBytes; i++)
            if (addressBytes[i] != networkBytes[i]) return false;

        if (remainingBits == 0) return true;

        var mask = (byte)(0xFF << (8 - remainingBits));

        return (addressBytes[fullBytes] & mask) == (networkBytes[fullBytes] & mask);
    }

    /// <summary>
    /// מריץ את בדיקת סמני ה-HTTP של הספק: כותרות תשובה ותוכן מזהה.
    /// חלק מהספקים מוסיפים כותרת ייחודית לכל תשובה שעוברת דרכם.
    /// </summary>
    public async Task<bool> CheckHttpMarkersAsync(ProviderRule provider, CancellationToken ct)
    {
        if (provider.HttpMarkers is not { } markers) return false;

        /*
         * היציאה המוקדמת בדקה את Url וחזרה מיד כשהוא ריק — ואז
         * ספק שכל הזיהוי שלו יושב ב-Probes לא היה נבדק כלל.
         * הבדיקה הראשית מדלגת על עצמה, והגששים ממשיכים.
         */
        if (!string.IsNullOrWhiteSpace(markers.Url))
        {
            var url = markers.Url;

            try
            {
                var client = _httpFactory.CreateClient("probe");

                using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
                cts.CancelAfter(TimeSpan.FromSeconds(6));

                using var response = await client.GetAsync(
                    url, HttpCompletionOption.ResponseHeadersRead, cts.Token);

                foreach (var (name, expected) in markers.Headers)
                {
                    if (!response.Headers.TryGetValues(name, out var values) &&
                        !response.Content.Headers.TryGetValues(name, out values))
                        continue;

                    if (values.Any(v => expected == "*" || Wildcard.IsMatch(v, expected)))
                        return true;
                }

                if (markers.BodyContains.Count > 0)
                {
                    var body = await response.Content.ReadAsStringAsync(cts.Token);

                    if (markers.BodyContains.Any(marker =>
                            body.Contains(marker, StringComparison.OrdinalIgnoreCase)))
                        return true;
                }
            }
            catch (Exception ex)
            {
                _log.LogDebug(ex, "בדיקת סמני HTTP עבור {Provider} נכשלה.", provider.Id);
            }
        }

        /*
         * הגששים הנוספים, אחרי הבדיקה הראשית.
         *
         * מוצאים רק אם הראשונה לא הספיקה: כל אחד מהם הוא
         * בקשת רשת, ואין טעם לשלוח את כולם כשהתשובה כבר ידועה.
         */
        foreach (var probe in markers.Probes)
        {
            if (await MatchesProbeAsync(probe, provider.Id, ct)) return true;
        }

        return false;
    }

    /// <summary>
    /// גשש בודד. כל תנאי שהוגדר חייב להתקיים, וגשש בלי תנאים
    /// אינו מתאים לעולם.
    /// </summary>
    private async Task<bool> MatchesProbeAsync(HttpProbeRule probe, string providerId, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(probe.Url)) return false;

        var hasCondition = probe.Status is not null
            || probe.BodyContains.Count > 0
            || probe.BodyNotContains.Count > 0;

        if (!hasCondition) return false;

        try
        {
            var client = _httpFactory.CreateClient("probe");

            using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            cts.CancelAfter(TimeSpan.FromSeconds(6));

            using var response = await client.GetAsync(probe.Url, cts.Token);

            if (probe.Status is { } expected && (int)response.StatusCode != expected) return false;

            if (probe.BodyContains.Count == 0 && probe.BodyNotContains.Count == 0) return true;

            var body = await response.Content.ReadAsStringAsync(cts.Token);

            if (probe.BodyNotContains.Any(m => body.Contains(m, StringComparison.OrdinalIgnoreCase)))
                return false;

            if (probe.BodyContains.Count > 0 &&
                !probe.BodyContains.Any(m => body.Contains(m, StringComparison.OrdinalIgnoreCase)))
                return false;

            return true;
        }
        catch (Exception ex)
        {
            /*
             * כישלון רשת אינו התאמה, גם כשהגשש מוגדר בשלילה.
             *
             * זו הנקודה המסוכנת בגשש מהסוג הזה: "הטקסט אינו מופיע"
             * מתקיים גם כשלא הגיעה שום תשובה. חריגה חוזרת false,
             * ולא נופלת לבדיקת הגוף.
             */
            _log.LogDebug(ex, "גשש {Url} עבור {Provider} נכשל.", probe.Url, providerId);

            return false;
        }
    }

    /// <summary>אוסף מידע על המתאמים הפעילים, כולל שם רשת אלחוטית.</summary>
    public List<NetworkAdapterInfo> GetActiveAdapters()
    {
        var adapters = new List<NetworkAdapterInfo>();
        var ssid = GetCurrentWifiSsid();

        foreach (var nic in NetworkInterface.GetAllNetworkInterfaces())
        {
            if (nic.OperationalStatus != OperationalStatus.Up) continue;
            if (nic.NetworkInterfaceType == NetworkInterfaceType.Loopback) continue;

            var properties = nic.GetIPProperties();
            var gateway = properties.GatewayAddresses
                .FirstOrDefault(g => g.Address.AddressFamily == AddressFamily.InterNetwork)?.Address;

            // מתאם ללא שער ברירת מחדל בדרך כלל אינו נתיב היציאה לאינטרנט
            if (gateway is null) continue;

            var local = properties.UnicastAddresses
                .FirstOrDefault(a => a.Address.AddressFamily == AddressFamily.InterNetwork)?.Address;

            adapters.Add(new NetworkAdapterInfo
            {
                Name = nic.Name,
                Description = nic.Description,
                Gateway = gateway.ToString(),
                GatewayMac = GetGatewayMac(gateway),
                LocalIp = local?.ToString(),
                Ssid = nic.NetworkInterfaceType == NetworkInterfaceType.Wireless80211 ? ssid : null,
                IsVirtualVpn = LooksLikeVpnAdapter(nic)
            });
        }

        return adapters;
    }

    /// <summary>
    /// שולף את כתובת החומרה של השער מטבלת ה-ARP.
    ///
    /// זה מה שמבדיל בין נתב לבין טלפון: כתובת השער היא מספר שאפשר
    /// לשנות בהגדרות, אבל כתובת החומרה מזוהה ליצרן. שילוב השניים
    /// הוא טביעת האצבע של הרשת הפיזית.
    ///
    /// מוחזר null כשהערך אינו זמין. שער שלא נענה ל-ARP, או ממשק
    /// שאינו אתרנט, אינם תקלה — הם פשוט חסרים.
    /// </summary>
    private static string? GetGatewayMac(IPAddress gateway)
    {
        var address = new byte[6];
        var length = address.Length;

        // SendARP מחזיר 0 בהצלחה. כל ערך אחר פירושו שהכתובת אינה
        // בטבלה ולא ניתן היה לפתור אותה.
        if (SendARP(BitConverter.ToUInt32(gateway.GetAddressBytes(), 0), 0, address, ref length) != 0)
            return null;

        if (length != 6) return null;

        return string.Join(":", address.Select(b => b.ToString("X2")));
    }

    [LibraryImport("iphlpapi.dll", SetLastError = true)]
    private static partial int SendARP(
        uint destIp,
        uint srcIp,
        [Out] byte[] macAddr,
        ref int physicalAddrLen);
    /// <summary>
    /// מתאמי VPN וירטואליים הם דרך העקיפה הנפוצה ביותר, ולכן נוכחותם מדווחת לשרת.
    /// </summary>
    private static bool LooksLikeVpnAdapter(NetworkInterface nic)
    {
        string[] markers =
        [
            "tap-", "tap adapter", "wintun", "wireguard", "openvpn", "nordlynx",
            "proton", "expressvpn", "cisco anyconnect", "fortinet", "pangp", "zerotier",
            "hamachi", "softether", "psiphon"
        ];

        var haystack = (nic.Description + " " + nic.Name).ToLowerInvariant();

        return markers.Any(haystack.Contains);
    }

    /// <summary>
    /// מחלץ את שם הרשת האלחוטית באמצעות netsh.
    /// זו הדרך היציבה ביותר ללא תלות ב-Native WiFi API ובחבילות חיצוניות.
    /// </summary>
    public string? GetCurrentWifiSsid()
    {
        try
        {
            var psi = new ProcessStartInfo
            {
                FileName = "netsh.exe",
                Arguments = "wlan show interfaces",
                RedirectStandardOutput = true,
                UseShellExecute = false,
                CreateNoWindow = true,
                StandardOutputEncoding = System.Text.Encoding.UTF8
            };

            using var process = Process.Start(psi);
            if (process is null) return null;

            var output = process.StandardOutput.ReadToEnd();
            process.WaitForExit(4000);

            // מותאם גם לפלט אנגלי וגם לפלט מקומי, ולכן מחפשים את המפריד ולא מילה מסוימת
            var match = Regex.Match(output, @"^\s*SSID\s*:\s*(?<ssid>.+)$",
                RegexOptions.Multiline | RegexOptions.IgnoreCase);

            if (!match.Success) return null;

            var value = match.Groups["ssid"].Value.Trim();

            return string.IsNullOrWhiteSpace(value) ? null : value;
        }
        catch (Exception ex)
        {
            _log.LogDebug(ex, "קריאת שם הרשת האלחוטית נכשלה.");
            return null;
        }
    }
}
