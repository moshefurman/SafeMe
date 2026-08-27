using SafeMe.Core.Abstractions;
using SafeMe.Core.Models;

namespace SafeMe.Core.Policy;

/// <summary>
/// בונה את תוכנית היציאה: מה מותר לצאת אליו, ומה נחסם.
///
/// העיקרון הוא היפוך של ברירת המחדל. עד כה נחסם מה שידענו לזהות
/// כרע, וכל השאר עבר. רשימה כזו תמיד מפגרת אחרי הכלי הבא — נכתבת
/// אחרי שהוא כבר בשימוש. כאן ההיתר הוא החריג: מותר מה שדפדוף מסונן
/// צריך, וכל השאר חסום, כולל מה שעדיין לא נולד.
///
/// שתי צורות סינון, ושתי תוצאות שונות לגמרי:
///
/// בסינון ברמת הספק המחשב יוצא לכל האינטרנט והסינון קורה בדרך.
/// רשימת יעדים מותרים היא חסרת משמעות שם — היעד הוא כל האינטרנט.
/// מה שאפשר לאכוף הוא **הדרך**: פורטים שדפדפן צריך, שרתי DNS
/// מאושרים בלבד, וחסימה של כל מה שבונה מנהרה החוצה.
///
/// בסינון דרך שרתי הספק המחשב מדבר רק איתם. שם "רק הספק מותר"
/// הוא אכיפה מילולית וזו הצורה החזקה. לא כל הספקים עובדים כך.
///
/// המחלקה טהורה במכוון: אין בה WFP ואין בה Windows, ולכן אפשר
/// לבדוק כל צירוף בלי מכונה.
/// </summary>
public static class EgressPlanner
{
    /// <summary>
    /// כלי המנהור שנחסמים גם בלי רשימה מהשרת.
    ///
    /// הרשימה מהשרת היא המקור המתעדכן, אבל סוכן שלא הצליח למשוך
    /// מדיניות אינו אמור להישאר בלי הגנה בסיסית. אלה השמות שהיו
    /// נכונים ביום הבנייה, ותפקידם לכסות את הפער עד המשיכה הראשונה.
    /// </summary>
    public static readonly string[] BaselineBlockedProcesses =
    [
        // VPN
        "openvpn.exe", "openvpn-gui.exe", "wireguard.exe", "wg.exe",
        "nordvpn.exe", "expressvpn.exe", "protonvpn.exe", "surfshark.exe",
        "cyberghost.exe", "hotspotshield.exe", "windscribe.exe", "tunnelbear.exe",
        "psiphon.exe", "psiphon3.exe", "hola.exe", "softether.exe", "vpnclient.exe",

        // Tor ומה שמבוסס עליו
        "tor.exe", "firefox.exe.tor", "torbrowser.exe", "start-tor-browser.exe",

        // שליטה מרחוק
        "anydesk.exe", "teamviewer.exe", "tvnserver.exe", "rustdesk.exe",
        "vncviewer.exe", "winvnc.exe", "ultravnc.exe", "radmin.exe",
        "logmein.exe", "gotomypc.exe", "supremo.exe", "ammyy.exe",
        "dwagent.exe", "splashtop.exe", "chromoting.exe",

        // מנהור כללי
        "ngrok.exe", "plink.exe", "putty.exe", "ssh.exe", "stunnel.exe",
        "cloudflared.exe", "frpc.exe", "chisel.exe", "socat.exe",

        // שיתוף אינטרנט מהמחשב עצמו
        "connectify.exe"
    ];

    /// <summary>
    /// פורטים שנחסמים מפורשות.
    ///
    /// רובם מיותרים כשהחסימה הכללית פעילה, והם נרשמים בכל זאת משתי
    /// סיבות: הם גוברים גם על היתר רחב שנוסף בטעות, והם נותנים
    /// שם לחסימה ביומן — "OpenVPN" ולא "פורט 1194".
    /// </summary>
    public static readonly PortBlock[] BaselineBlockedPorts =
    [
        new() { Port = 1194, Protocol = "any", Label = "OpenVPN" },
        new() { Port = 51820, Protocol = "udp", Label = "WireGuard" },
        new() { Port = 500,  Protocol = "udp", Label = "IPsec IKE" },
        new() { Port = 4500, Protocol = "udp", Label = "IPsec NAT-T" },
        new() { Port = 1701, Protocol = "any", Label = "L2TP" },
        new() { Port = 1723, Protocol = "tcp", Label = "PPTP" },
        new() { Port = 3389, Protocol = "any", Label = "שולחן עבודה מרוחק" },
        new() { Port = 5900, Protocol = "tcp", Label = "VNC" },
        new() { Port = 22,   Protocol = "tcp", Label = "SSH — משמש למנהור" },
        new() { Port = 853,  Protocol = "any", Label = "DNS מוצפן (DoT)" },
        new() { Port = 5938, Protocol = "any", Label = "TeamViewer" },
        new() { Port = 9001, Protocol = "tcp", Label = "Tor" },
        new() { Port = 9050, Protocol = "tcp", Label = "Tor SOCKS" }
    ];

    /// <summary>מה שהתוכנית צריכה לדעת מעבר לכלל עצמו.</summary>
    public sealed class Context
    {
        /// <summary>כתובות שרת הניהול, כבר מיושבות.</summary>
        public IReadOnlyList<string> ServerIps { get; init; } = [];

        /// <summary>נתיבי ההרצה של הסוכן עצמו.</summary>
        public IReadOnlyList<string> AgentPaths { get; init; } = [];

        /// <summary>הספק שזוהה, אם זוהה.</summary>
        public ProviderDetection? Detection { get; init; }

        /// <summary>האם הרשת הנוכחית נחסמה על ידי הרשימה הלבנה.</summary>
        public bool NetworkBlocked { get; init; }

        /// <summary>
        /// סיבה לנעילה שנקבעה מחוץ לתכנון הזה: נעילה יזומה מהשרת,
        /// חלון זמן מתוזמן, או סטטוס אדום. ריק משמעו שאין.
        ///
        /// היא נבדקת ראשונה. כל שיקול אחר יכול רק לצמצם היתרים,
        /// לעולם לא להחזיר אותם.
        /// </summary>
        public string? ForcedLockdownReason { get; init; }
    }

    /// <summary>
    /// בונה את התוכנית.
    ///
    /// סדר ההכרעה אינו שרירותי: כל מדרגה למטה היא הרפיה, ולכן
    /// הבדיקות המחמירות קודמות. רשת חסומה גוברת על ספק מזוהה,
    /// כי אישור הרשת הוא שאלה נפרדת מזהות הספק.
    /// </summary>
    public static EnforcementPlan Build(EgressRule rule, Context context)
    {
        ArgumentNullException.ThrowIfNull(rule);
        ArgumentNullException.ThrowIfNull(context);

        if (!rule.Enabled)
            return EnforcementPlan.Disabled;

        var blockedProcesses = Merge(BaselineBlockedProcesses, rule.BlockedProcessNames);
        var blockedPorts = MergePorts(BaselineBlockedPorts, rule.BlockedPorts);

        // ---- 1. נעילה שנקבעה מחוץ לכאן ----
        if (!string.IsNullOrWhiteSpace(context.ForcedLockdownReason))
            return LockedDown(rule, context, blockedProcesses, blockedPorts,
                context.ForcedLockdownReason);

        // ---- 2. הרשת עצמה חסומה ----
        if (context.NetworkBlocked)
            return LockedDown(rule, context, blockedProcesses, blockedPorts,
                "הרשת הנוכחית אינה מאושרת.");

        // ---- 3. לא זוהה ספק מאושר ----
        //
        // כאן ההבדל מהגרסה הקודמת. קודם, ספק שלא זוהה היה מוריד
        // את הציון ומפעיל את מצב החסימה. עכשיו הוא פשוט אינו
        // פותח שום היתר: הברירה היא סגור.
        if (!IsTrusted(context.Detection))
            return LockedDown(rule, context, blockedProcesses, blockedPorts,
                "לא זוהה ספק סינון מאושר.");

        // ---- 4. סינון דרך שרתי הספק ----
        if (rule.Mode == ProviderEgressMode.ProxyEndpoint)
        {
            // בלי רשימת יעדים אין מה לאשר, והתוצאה היא נעילה.
            // זו אינה תקלה שמותר לעגל אותה כלפי מטה.
            if (rule.ProviderCidrs.Count == 0)
                return LockedDown(rule, context, blockedProcesses, blockedPorts,
                    "מצב שרתי ספק בלי רשימת כתובות. אין מה להתיר.");

            return new EnforcementPlan
            {
                BlockAllOutbound = true,
                Posture = EgressPosture.ProviderOnly,
                AllowedRemoteCidrs = [.. rule.ProviderCidrs],
                AllowedPortRules = [.. WebRules(rule, rule.ProviderCidrs)],
                AllowedResolvers = [.. rule.Resolvers],
                ServerIps = [.. context.ServerIps],
                AllowedAppPaths = [.. context.AgentPaths],
                BlockedPorts = blockedPorts,
                BlockedRemoteCidrs = [.. rule.BlockedCidrs],
                BlockedProcessNames = blockedProcesses,
                BlockAllInbound = rule.BlockInbound,
                AllowDns = rule.Resolvers.Count > 0,
                AllowDhcp = true,
                AllowLoopback = true,
                Reason = $"יציאה דרך שרתי {Name(context.Detection)} בלבד."
            };
        }

        // ---- 5. סינון ברמת הספק ----
        //
        // היעד הוא כל האינטרנט, ולכן מה שנאכף הוא הדרך: פורטים
        // שדפדוף צריך, שרתי DNS מאושרים, וחסימה של כל מנהרה.
        return new EnforcementPlan
        {
            BlockAllOutbound = true,
            Posture = EgressPosture.Filtered,
            AllowedPortRules = [.. WebRules(rule, [])],
            AllowedResolvers = [.. rule.Resolvers],
            ServerIps = [.. context.ServerIps],
            AllowedAppPaths = [.. context.AgentPaths],
            BlockedPorts = blockedPorts,
            BlockedRemoteCidrs = [.. rule.BlockedCidrs],
            BlockedProcessNames = blockedProcesses,
            BlockAllInbound = rule.BlockInbound,
            AllowDns = true,
            AllowDhcp = true,
            AllowLoopback = true,
            Reason = $"יציאה מסוננת דרך {Name(context.Detection)}. מנהרות חסומות."
        };
    }

    /// <summary>
    /// נעילה מלאה: רק שרת הניהול והלולאה המקומית.
    ///
    /// DHCP נשאר פתוח בכוונה. בלעדיו המכשיר לא יקבל כתובת כשהוא
    /// עובר רשת, ולא יוכל להגיע לשרת גם כשההורה כבר אישר — נעילה
    /// שאי אפשר לצאת ממנה אינה הגנה אלא תקלה.
    /// </summary>
    private static EnforcementPlan LockedDown(
        EgressRule rule, Context context,
        List<string> blockedProcesses, List<PortBlock> blockedPorts, string why)
        => new()
        {
            BlockAllOutbound = true,
            Posture = EgressPosture.LockedDown,
            AllowedPortRules = [],
            AllowedResolvers = [.. rule.Resolvers],
            ServerIps = [.. context.ServerIps],
            AllowedAppPaths = [.. context.AgentPaths],
            BlockedPorts = blockedPorts,
            BlockedRemoteCidrs = [.. rule.BlockedCidrs],
            BlockedProcessNames = blockedProcesses,
            BlockAllInbound = rule.BlockInbound,

            // DNS נסגר בנעילה אלא אם יש שרתים מאושרים לכוון אליהם
            AllowDns = false,
            AllowDhcp = true,
            AllowLoopback = true,
            Reason = why
        };

    /// <summary>
    /// היתרי הפורטים לדפדוף.
    ///
    /// QUIC מקבל טיפול נפרד ולא נכלל ב-WebPorts: הוא UDP על אותו
    /// מספר פורט, וערבוב שני הפרוטוקולים תחת ערך אחד היה מתיר
    /// אותו בלי שאיש ביקש.
    /// </summary>
    private static List<PortPermit> WebRules(EgressRule rule, IReadOnlyList<string> scope)
    {
        var rules = new List<PortPermit>();

        foreach (var port in rule.WebPorts.Distinct())
            rules.Add(new PortPermit { Port = port, Protocol = "tcp", ToCidrs = [.. scope] });

        if (rule.AllowQuic)
            rules.Add(new PortPermit { Port = 443, Protocol = "udp", ToCidrs = [.. scope] });

        return rules;
    }

    /// <summary>
    /// האם הזיהוי מספיק כדי לפתוח היתרים.
    ///
    /// Low אינו מספיק. וקטור אחד חלש הוא בדיוק מה שאפשר לזייף —
    /// להתקין תעודת שורש בשם דומה, למשל — ולכן הוא אינו קונה
    /// גישה לאינטרנט.
    /// </summary>
    private static bool IsTrusted(ProviderDetection? detection)
        => detection is { ProviderId: not null } d
           && d.Trust is TrustLevel.Medium or TrustLevel.High;

    private static string Name(ProviderDetection? detection)
        => detection?.DisplayName is { Length: > 0 } name ? name : "ספק הסינון";

    /// <summary>איחוד רשימות בלי כפילויות, בלי תלות ברישיות.</summary>
    private static List<string> Merge(IEnumerable<string> baseline, IEnumerable<string> extra)
        => baseline.Concat(extra)
            .Select(x => x.Trim())
            .Where(x => x.Length > 0)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .OrderBy(x => x, StringComparer.OrdinalIgnoreCase)
            .ToList();

    /// <summary>
    /// איחוד פורטים. מפתח הייחוד הוא הפורט והפרוטוקול יחד, כי
    /// חסימת TCP/1194 אינה חוסמת את UDP/1194.
    /// </summary>
    private static List<PortBlock> MergePorts(
        IEnumerable<PortBlock> baseline, IEnumerable<PortBlock> extra)
    {
        var seen = new Dictionary<string, PortBlock>(StringComparer.OrdinalIgnoreCase);

        foreach (var block in baseline.Concat(extra))
        {
            if (block.Port is <= 0 or > 65535) continue;

            var protocol = Normalize(block.Protocol);
            var key = $"{block.Port}/{protocol}";

            // "any" בולע את הווריאנטים הצרים: חסימה של שני
            // הפרוטוקולים כוללת כל אחד מהם בנפרד.
            if (protocol == "any")
            {
                seen.Remove($"{block.Port}/tcp");
                seen.Remove($"{block.Port}/udp");
            }
            else if (seen.ContainsKey($"{block.Port}/any"))
            {
                continue;
            }

            seen[key] = new PortBlock
            {
                Port = block.Port,
                Protocol = protocol,
                Label = block.Label
            };
        }

        return seen.Values.OrderBy(x => x.Port).ThenBy(x => x.Protocol).ToList();
    }

    private static string Normalize(string protocol)
    {
        var value = protocol.Trim().ToLowerInvariant();

        return value is "tcp" or "udp" ? value : "any";
    }
}
