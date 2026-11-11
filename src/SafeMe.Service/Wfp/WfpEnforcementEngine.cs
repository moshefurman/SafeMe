using System.Net;
using System.Runtime.Versioning;
using Microsoft.Extensions.Logging;
using SafeMe.Core.Abstractions;
using SafeMe.Core.Policy;

namespace SafeMe.Service.Wfp;

/// <summary>
/// מתרגם תוכנית אכיפה לחוקי WFP בפועל.
///
/// סדר המשקלים קובע את התוצאה: חוק החסימה הכללי מקבל משקל נמוך,
/// וכל ההיתרים מקבלים משקלים גבוהים יותר, כך שהם גוברים עליו.
/// כל יישום מתבצע בטרנזקציה אחת - או שהכול נכנס, או ששום דבר לא משתנה.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class WfpEnforcementEngine : IEnforcementEngine, IDynamicDestinations
{
    /*
     * סולם המשקלים. ראה מסמך הארכיטקטורה, סעיף 6.2
     *
     * ב-WFP, בתוך אותו SubLayer, המשקל הגבוה מכריע. הסולם מסודר
     * בשלוש קומות: חסימת הרצפה, ההיתרים הרגילים מעליה, והחסימות
     * הממוקדות מעליהם — כדי שחסימת מנהרה תגבר על היתר הדפדוף.
     *
     * ומעל הכול, ההיתרים שאסור לשבור: שרת הניהול, הסוכן עצמו,
     * והלולאה המקומית. הם מעל החסימות ולא מתחתן, במכוון. מחשב
     * שאינו יכול לדווח הוא מחשב שאי אפשר לשחרר, ואם כתובת של
     * השרת תיפול יום אחד בתוך טווח חסום — התוצאה תהיה מחשב
     * נעול שאיש אינו יכול להגיע אליו.
     */
    private const ulong WeightBlockAll = 100;
    private const ulong WeightAllowedNetwork = 1000;
    private const ulong WeightWebPort = 1500;
    private const ulong WeightInfrastructure = 1900;   // DNS ו-DHCP

    private const ulong WeightBlockPort = 3000;
    private const ulong WeightBlockCidr = 3500;
    private const ulong WeightBlockApp = 4000;

    private const ulong WeightServer = 5000;
    private const ulong WeightAgentApp = 5500;
    private const ulong WeightLoopback = 6000;

    private readonly ILogger<WfpEnforcementEngine> _log;
    private readonly WfpEngine _engine;
    private readonly object _sync = new();

    private EnforcementPlan _current = EnforcementPlan.Disabled;
    private bool _initialized;

    /*
     * היעדים של הרשימה הלבנה: כתובות ששרת השמות המקומי החזיר לשמות
     * מותרים, עם הרגע האחרון שבו כל אחת נראתה.
     *
     * הם מוחזקים כאן ולא בתוכנית, כי התוכנית נבנית מחדש מאפס בכל
     * הערכה — ותוכנית שנבנתה שנייה לפני שכתובת הצטרפה הייתה מוחקת
     * אותה. המנוע הוא המקום היחיד שרואה גם את הבנייה וגם את ההצטרפות
     * תחת אותו מנעול.
     */
    private readonly Dictionary<IPAddress, DateTime> _dynamic = new();

    /// <summary>
    /// כמה זמן כתובת נשארת פתוחה אחרי הפעם האחרונה שנשאלה.
    ///
    /// ארוך בהרבה מזמן החיים שהלקוח מקבל בתשובה (חמש דקות לכל היותר),
    /// כדי שחיבור פתוח לא ייחתך — וקצר מספיק כדי שכתובת של CDN
    /// שעברה לאתר אחר לא תישאר פתוחה לנצח.
    /// </summary>
    private static readonly TimeSpan DynamicLifetime = TimeSpan.FromHours(2);

    /// <summary>תקרה. מעבר לה הישנות ביותר נסגרות, כדי שלמידה ארוכה לא תנפח את WFP.</summary>
    private const int MaxDynamic = 4000;

    public WfpEnforcementEngine(ILogger<WfpEnforcementEngine> log)
    {
        _log = log;
        _engine = new WfpEngine(log);
    }

    public int ActiveFilterCount => _engine.FilterCount;

    public EnforcementPlan CurrentPlan
    {
        get { lock (_sync) return _current; }
    }

    public bool Initialize()
    {
        lock (_sync)
        {
            if (_initialized) return true;

            if (!_engine.Open(dynamic: true))
            {
                _log.LogError("לא ניתן לפתוח את מנוע WFP. האכיפה לא תפעל עד שהבעיה תיפתר.");
                return false;
            }

            if (!_engine.EnsureInfrastructure())
            {
                _engine.Close();
                return false;
            }

            _initialized = true;
            _log.LogInformation("תשתית האכיפה של SafeMe נרשמה ב-WFP.");

            return true;
        }
    }

    /// <summary>
    /// מיישם תוכנית אכיפה. תמיד בונים מחדש מאפס במקום לתקן הפרשים,
    /// כי זהו המצב היחיד שאפשר להוכיח את נכונותו מול BFE.
    /// </summary>
    public void Apply(EnforcementPlan plan)
    {
        ArgumentNullException.ThrowIfNull(plan);

        lock (_sync)
        {
            if (!_initialized && !Initialize())
            {
                _log.LogError("יישום תוכנית האכיפה בוטל: המנוע אינו זמין.");
                return;
            }

            var ok = _engine.RunInTransaction(() =>
            {
                _engine.DeleteAllFilters();

                if (!plan.BlockAllOutbound)
                    return;

                using var arena = new NativeArena();

                /*
                 * 1. ההיתרים שאסור לשבור, ראשונים ובמשקל הגבוה ביותר.
                 *
                 * שרת הניהול לפני הכול. כל שאר החוקים יכולים להיות
                 * שגויים ועדיין תהיה דרך לתקן; בלי הערוץ הזה אין.
                 */
                if (plan.AllowLoopback)
                    _engine.AddPermitLoopback(WeightLoopback);

                foreach (var path in plan.AllowedAppPaths)
                    _engine.AddPermitApplication(path, WeightAgentApp, arena);

                foreach (var ip in plan.ServerIps)
                    _engine.AddPermitRemoteCidr(ip, WeightServer, arena);

                // 2. חסימות ממוקדות, מעל ההיתרים הרגילים
                foreach (var path in plan.BlockedProcessNames)
                    _engine.AddBlockApplication(path, WeightBlockApp, arena);

                foreach (var cidr in plan.BlockedRemoteCidrs)
                    _engine.AddBlockRemoteCidr(cidr, WeightBlockCidr, arena);

                foreach (var block in plan.BlockedPorts)
                    AddPortBlock(block);

                if (plan.BlockAllInbound)
                    _engine.AddBlockAllInbound(WeightBlockPort);

                // 3. ההיתרים הרגילים

                /*
                 * DNS. כשיש שרתים מאושרים, הפורט נפתח אליהם בלבד —
                 * שני התנאים באותו חוק. היתר גורף לפורט 53 מאפשר
                 * להצביע על שרת שמות שאינו מסנן, וזו עקיפה שלמה
                 * בשינוי הגדרה אחת.
                 */
                if (plan.AllowDns)
                {
                    if (plan.AllowedResolvers.Count > 0)
                    {
                        foreach (var resolver in plan.AllowedResolvers)
                        {
                            _engine.AddPermitPortToCidr(
                                53, WfpConstants.IPPROTO_UDP, resolver, WeightInfrastructure, arena);

                            _engine.AddPermitPortToCidr(
                                53, WfpConstants.IPPROTO_TCP, resolver, WeightInfrastructure, arena);
                        }
                    }
                    else
                    {
                        _engine.AddPermitRemotePort(53, WfpConstants.IPPROTO_UDP, WeightInfrastructure);
                        _engine.AddPermitRemotePort(53, WfpConstants.IPPROTO_TCP, WeightInfrastructure);
                    }
                }

                if (plan.AllowDhcp)
                {
                    _engine.AddPermitRemotePort(67, WfpConstants.IPPROTO_UDP, WeightInfrastructure);
                    _engine.AddPermitRemotePort(68, WfpConstants.IPPROTO_UDP, WeightInfrastructure);
                }

                // פורטי הדפדוף. בלעדיהם אין אינטרנט בכלל.
                foreach (var permit in plan.AllowedPortRules)
                    AddPortPermit(permit, arena);

                foreach (var cidr in plan.AllowedRemoteCidrs)
                    _engine.AddPermitRemoteCidr(cidr, WeightAllowedNetwork, arena);

                /*
                 * יעדי הרשימה הלבנה, באותו משקל של פורטי הדפדוף —
                 * כלומר מתחת לכל החסימות הממוקדות. כתובת מותרת אינה
                 * פותחת כלי מנהור שרץ אליה.
                 *
                 * בתוכנית שאינה רשימה לבנה הם נשכחים: היתר שנפתח
                 * בשביל רשימה אינו עובר בירושה למצב אחר.
                 */
                if (plan.DynamicPortRules.Count > 0)
                {
                    PruneDynamic();

                    foreach (var address in _dynamic.Keys)
                        AddDynamicPermit(address, plan.DynamicPortRules, arena);
                }
                else
                {
                    _dynamic.Clear();
                }

                // 4. ולבסוף החסימה הרחבה, במשקל הנמוך ביותר
                _engine.AddBlockAllOutbound(WeightBlockAll);
            });

            if (!ok)
            {
                _log.LogError("יישום תוכנית האכיפה נכשל. המצב הקודם נשמר.");
                return;
            }

            _current = plan;

            _log.LogInformation(
                "תוכנית אכיפה הוחלה: חסימה={Block}, חוקים={Count}, סיבה={Reason}",
                plan.BlockAllOutbound, _engine.FilterCount, plan.Reason);
        }
    }

    /// <summary>
    /// מתרגם "any" לשני חוקים נפרדים.
    ///
    /// ל-WFP אין תנאי "כל פרוטוקול" — היעדר התנאי פירושו כל
    /// פרוטוקול, כולל ICMP, ולכן חסימה כזו הייתה רחבה מהכוונה.
    /// שני חוקים מפורשים אומרים בדיוק מה שהתכוונו.
    /// </summary>
    private void AddPortBlock(PortBlock block)
    {
        if (block.Port is <= 0 or > 65535) return;

        var port = (ushort)block.Port;

        switch (block.Protocol)
        {
            case "tcp":
                _engine.AddBlockRemotePort(port, WfpConstants.IPPROTO_TCP, WeightBlockPort);
                break;

            case "udp":
                _engine.AddBlockRemotePort(port, WfpConstants.IPPROTO_UDP, WeightBlockPort);
                break;

            default:
                _engine.AddBlockRemotePort(port, WfpConstants.IPPROTO_TCP, WeightBlockPort);
                _engine.AddBlockRemotePort(port, WfpConstants.IPPROTO_UDP, WeightBlockPort);
                break;
        }
    }

    private void AddPortPermit(PortPermit permit, NativeArena arena)
    {
        if (permit.Port is <= 0 or > 65535) return;

        var port = (ushort)permit.Port;

        byte[] protocols = permit.Protocol switch
        {
            "tcp" => [WfpConstants.IPPROTO_TCP],
            "udp" => [WfpConstants.IPPROTO_UDP],
            _ => [WfpConstants.IPPROTO_TCP, WfpConstants.IPPROTO_UDP]
        };

        foreach (var protocol in protocols)
        {
            if (permit.ToCidrs.Count == 0)
            {
                _engine.AddPermitRemotePort(port, protocol, WeightWebPort);
                continue;
            }

            foreach (var cidr in permit.ToCidrs)
                _engine.AddPermitPortToCidr(port, protocol, cidr, WeightWebPort, arena);
        }
    }

    /// <summary>
    /// פותח כתובות שהתגלו עכשיו, בלי לבנות את התוכנית מחדש.
    ///
    /// רק כשהתוכנית הנוכחית היא רשימה לבנה. בכל מצב אחר — נעילה,
    /// חלון זמן — הקריאה אינה עושה דבר ואינה זוכרת דבר: תשובת DNS
    /// אינה סיבה לפתוח חור בנעילה.
    /// </summary>
    public void Permit(IReadOnlyCollection<IPAddress> addresses)
    {
        lock (_sync)
        {
            var rules = _current.DynamicPortRules;

            if (!_initialized || rules.Count == 0) return;

            var now = DateTime.UtcNow;
            var fresh = new List<IPAddress>();

            foreach (var address in addresses)
            {
                if (!_dynamic.ContainsKey(address)) fresh.Add(address);

                _dynamic[address] = now;
            }

            if (fresh.Count == 0) return;

            var ok = _engine.RunInTransaction(() =>
            {
                using var arena = new NativeArena();

                foreach (var address in fresh)
                    AddDynamicPermit(address, rules, arena);
            });

            if (!ok)
            {
                // נשארות ברשימה: הבנייה הבאה תפתח אותן.
                _log.LogWarning("פתיחת {Count} כתובות לרשימה הלבנה נכשלה.", fresh.Count);
            }
        }
    }

    public void ForgetAll()
    {
        lock (_sync)
        {
            if (_dynamic.Count == 0) return;

            _dynamic.Clear();

            // בנייה מחדש היא הדרך היחידה למחוק חוקים, וזו גם הדרך
            // היחידה שנכונותה מוכחת מול BFE.
            if (_current.DynamicPortRules.Count > 0)
                Apply(_current);
        }
    }

    private void AddDynamicPermit(IPAddress address, List<PortPermit> rules, NativeArena arena)
    {
        var cidr = address.ToString();

        foreach (var rule in rules)
        {
            if (rule.Port is <= 0 or > 65535) continue;

            byte[] protocols = rule.Protocol switch
            {
                "tcp" => [WfpConstants.IPPROTO_TCP],
                "udp" => [WfpConstants.IPPROTO_UDP],
                _ => [WfpConstants.IPPROTO_TCP, WfpConstants.IPPROTO_UDP]
            };

            foreach (var protocol in protocols)
                _engine.AddPermitPortToCidr((ushort)rule.Port, protocol, cidr, WeightWebPort, arena);
        }
    }

    private void PruneDynamic()
    {
        var cutoff = DateTime.UtcNow - DynamicLifetime;

        foreach (var stale in _dynamic.Where(x => x.Value < cutoff).Select(x => x.Key).ToList())
            _dynamic.Remove(stale);

        if (_dynamic.Count <= MaxDynamic) return;

        foreach (var oldest in _dynamic.OrderBy(x => x.Value).Take(_dynamic.Count - MaxDynamic).ToList())
            _dynamic.Remove(oldest.Key);
    }

    public void RemoveAll()
    {
        lock (_sync)
        {
            _engine.RunInTransaction(() => _engine.DeleteAllFilters());
            _current = EnforcementPlan.Disabled;

            _log.LogInformation("כל חוקי האכיפה של SafeMe הוסרו.");
        }
    }

    /// <summary>מסיר גם את ה-Provider וה-SubLayer. משמש רק בהסרה מאושרת.</summary>
    public void Uninstall()
    {
        lock (_sync)
        {
            RemoveAll();
            _engine.RemoveInfrastructure();
            _engine.Close();
            _initialized = false;

            _log.LogInformation("תשתית WFP של SafeMe הוסרה במלואה.");
        }
    }

    public bool VerifyIntegrity()
    {
        lock (_sync)
        {
            if (!_initialized) return true;

            var intact = _engine.VerifyIntegrity(out var missing);

            if (!intact)
                _log.LogWarning("זוהו {Missing} חוקי WFP חסרים. תתבצע בנייה מחדש.", missing);

            return intact;
        }
    }

    /// <summary>
    /// יישוב שמות שרת הניהול לכתובות IP. מבוצע לפני נעילה, כדי שהמחשב
    /// לא יינתק מהשרת רק משום שה-DNS נחסם באותו רגע.
    /// </summary>
    public static async Task<List<string>> ResolveServerIpsAsync(
        IEnumerable<string> hosts, ILogger log, CancellationToken ct)
    {
        var results = new List<string>();

        foreach (var host in hosts)
        {
            if (IPAddress.TryParse(host.Split('/')[0], out _))
            {
                results.Add(host);
                continue;
            }

            try
            {
                var addresses = await Dns.GetHostAddressesAsync(host, ct);

                foreach (var address in addresses)
                {
                    var prefix = address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork ? 32 : 128;
                    results.Add($"{address}/{prefix}");
                }
            }
            catch (Exception ex)
            {
                log.LogWarning(ex, "יישוב כתובת עבור {Host} נכשל.", host);
            }
        }

        return results.Distinct().ToList();
    }

    public void Dispose() => _engine.Dispose();
}
