using FilterPlus.Core.Abstractions;
using FilterPlus.Core.Models;
using FilterPlus.Core.Policy;
using Xunit;

namespace FilterPlus.Tests;

/// <summary>
/// תוכנית היציאה: מה מותר, ומה נחסם.
///
/// הבדיקות כאן שומרות על שלושה דברים שקל לשבור בלי לשים לב: שכל
/// מסלול שאינו ודאי נגמר בנעילה ולא בהיתר, ששרת הניהול פתוח בכל
/// מסלול בלי יוצא מן הכלל, ושזיהוי חלש אינו קונה גישה.
/// </summary>
public class EgressPlannerTests
{
    private static readonly string[] ServerIps = ["203.0.113.10/32"];
    private static readonly string[] AgentPaths = [@"C:\Program Files\FilterPlus\FilterPlus.Service.exe"];

    private static EgressRule Rule(Action<EgressRule>? tweak = null)
    {
        var rule = new EgressRule
        {
            Enabled = true,
            Mode = ProviderEgressMode.IspLevel,
            Resolvers = ["198.51.100.5/32"]
        };

        tweak?.Invoke(rule);

        return rule;
    }

    private static EgressPlanner.Context Context(
        TrustLevel trust = TrustLevel.High, bool networkBlocked = false)
        => new()
        {
            ServerIps = ServerIps,
            AgentPaths = AgentPaths,
            NetworkBlocked = networkBlocked,
            Detection = trust == TrustLevel.None
                ? null
                : new ProviderDetection
                {
                    ProviderId = "netfree",
                    DisplayName = "נטפרי",
                    Trust = trust
                }
        };

    // ─────────────────────────────────────────────── כבוי

    [Fact]
    public void Disabled_rule_produces_no_enforcement()
    {
        var plan = EgressPlanner.Build(Rule(r => r.Enabled = false), Context());

        Assert.False(plan.BlockAllOutbound);
        Assert.Equal(EgressPosture.Off, plan.Posture);
    }

    // ─────────────────────────────────────────────── סינון ברמת הספק

    [Fact]
    public void Isp_level_permits_web_ports_without_destination_limit()
    {
        var plan = EgressPlanner.Build(Rule(), Context());

        Assert.Equal(EgressPosture.Filtered, plan.Posture);
        Assert.True(plan.BlockAllOutbound);

        var web = plan.AllowedPortRules.Single(p => p.Port == 443);

        Assert.Equal("tcp", web.Protocol);

        // בסינון ברמת הספק היעד הוא כל האינטרנט. הגבלת יעד כאן
        // הייתה מנתקת את המחשב לגמרי.
        Assert.Empty(web.ToCidrs);
    }

    [Fact]
    public void Quic_is_closed_unless_asked_for()
    {
        var closed = EgressPlanner.Build(Rule(), Context());

        Assert.DoesNotContain(closed.AllowedPortRules, p => p.Protocol == "udp");

        var open = EgressPlanner.Build(Rule(r => r.AllowQuic = true), Context());

        Assert.Contains(open.AllowedPortRules, p => p.Port == 443 && p.Protocol == "udp");
    }

    [Fact]
    public void Dns_is_limited_to_the_approved_resolvers()
    {
        var plan = EgressPlanner.Build(Rule(), Context());

        Assert.True(plan.AllowDns);
        Assert.Equal(["198.51.100.5/32"], plan.AllowedResolvers);
    }

    // ─────────────────────────────────────────────── סינון דרך שרתי הספק

    [Fact]
    public void Proxy_mode_limits_every_web_rule_to_the_provider()
    {
        var plan = EgressPlanner.Build(
            Rule(r =>
            {
                r.Mode = ProviderEgressMode.ProxyEndpoint;
                r.ProviderCidrs = ["192.0.2.0/24"];
            }),
            Context());

        Assert.Equal(EgressPosture.ProviderOnly, plan.Posture);
        Assert.All(plan.AllowedPortRules, p => Assert.Equal(["192.0.2.0/24"], p.ToCidrs));
    }

    [Fact]
    public void Proxy_mode_without_addresses_locks_down_rather_than_opening_up()
    {
        var plan = EgressPlanner.Build(
            Rule(r => r.Mode = ProviderEgressMode.ProxyEndpoint),
            Context());

        // הרפיה שקטה כאן הייתה הופכת שגיאת הגדרה לאינטרנט פתוח
        Assert.Equal(EgressPosture.LockedDown, plan.Posture);
        Assert.Empty(plan.AllowedPortRules);
    }

    // ─────────────────────────────────────────────── ברירת המחדל היא סגור

    [Fact]
    public void No_provider_means_locked_down()
    {
        var plan = EgressPlanner.Build(Rule(), Context(TrustLevel.None));

        Assert.Equal(EgressPosture.LockedDown, plan.Posture);
        Assert.Empty(plan.AllowedPortRules);
        Assert.False(plan.AllowDns);
    }

    [Fact]
    public void Weak_detection_does_not_buy_access()
    {
        var plan = EgressPlanner.Build(Rule(), Context(TrustLevel.Low));

        // וקטור חלש יחיד הוא בדיוק מה שאפשר לזייף
        Assert.Equal(EgressPosture.LockedDown, plan.Posture);
    }

    [Fact]
    public void Blocked_network_overrides_a_recognised_provider()
    {
        var plan = EgressPlanner.Build(Rule(), Context(networkBlocked: true));

        Assert.Equal(EgressPosture.LockedDown, plan.Posture);
        Assert.Contains("אינה מאושרת", plan.Reason);
    }

    // ─────────────────────────────────────────────── מה שאסור להישבר

    [Theory]
    [InlineData(TrustLevel.High, false)]
    [InlineData(TrustLevel.None, false)]
    [InlineData(TrustLevel.Low, false)]
    [InlineData(TrustLevel.High, true)]
    public void Management_channel_survives_every_posture(TrustLevel trust, bool networkBlocked)
    {
        var plan = EgressPlanner.Build(Rule(), Context(trust, networkBlocked));

        // מחשב שאינו יכול לדווח הוא מחשב שאי אפשר לשחרר
        Assert.Equal(ServerIps, plan.ServerIps);
        Assert.Equal(AgentPaths, plan.AllowedAppPaths);
        Assert.True(plan.AllowLoopback);

        // ובלי DHCP הוא לא יקבל כתובת כשיעבור רשת, וגם אישור של
        // ההורה לא יגיע אליו לעולם
        Assert.True(plan.AllowDhcp);
    }

    [Theory]
    [InlineData(TrustLevel.High)]
    [InlineData(TrustLevel.None)]
    public void Tunnel_blocks_apply_in_every_posture(TrustLevel trust)
    {
        var plan = EgressPlanner.Build(Rule(), Context(trust));

        Assert.Contains(plan.BlockedProcessNames, n => n.Equals("wireguard.exe", StringComparison.OrdinalIgnoreCase));
        Assert.Contains(plan.BlockedPorts, p => p.Port == 1194);
        Assert.Contains(plan.BlockedPorts, p => p.Port == 3389);
        Assert.True(plan.BlockAllInbound);
    }

    // ─────────────────────────────────────────────── מיזוג הרשימות

    [Fact]
    public void Server_list_extends_the_baseline_and_does_not_replace_it()
    {
        var plan = EgressPlanner.Build(
            Rule(r => r.BlockedProcessNames = ["newvpn.exe"]),
            Context());

        Assert.Contains(plan.BlockedProcessNames, n => n == "newvpn.exe");
        Assert.Contains(plan.BlockedProcessNames, n => n == "openvpn.exe");
    }

    [Fact]
    public void Duplicate_names_collapse_regardless_of_case()
    {
        var plan = EgressPlanner.Build(
            Rule(r => r.BlockedProcessNames = ["OpenVPN.exe", "openvpn.exe", "  "]),
            Context());

        Assert.Single(plan.BlockedProcessNames, n => n.Equals("openvpn.exe", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void Any_protocol_absorbs_the_narrower_variants()
    {
        var plan = EgressPlanner.Build(
            Rule(r => r.BlockedPorts =
            [
                new() { Port = 9999, Protocol = "tcp" },
                new() { Port = 9999, Protocol = "any", Label = "הכול" }
            ]),
            Context());

        var nine = plan.BlockedPorts.Where(p => p.Port == 9999).ToList();

        Assert.Single(nine);
        Assert.Equal("any", nine[0].Protocol);
    }

    [Fact]
    public void A_narrower_variant_does_not_weaken_an_existing_any()
    {
        var plan = EgressPlanner.Build(
            Rule(r => r.BlockedPorts =
            [
                new() { Port = 9999, Protocol = "any" },
                new() { Port = 9999, Protocol = "tcp" }
            ]),
            Context());

        // הסדר ההפוך מהבדיקה הקודמת. חסימה רחבה שנכנסה ראשונה
        // אינה מצטמצמת בגלל רשומה צרה שהגיעה אחריה.
        var nine = plan.BlockedPorts.Where(p => p.Port == 9999).ToList();

        Assert.Single(nine);
        Assert.Equal("any", nine[0].Protocol);
    }

    [Fact]
    public void Impossible_port_numbers_are_dropped()
    {
        var plan = EgressPlanner.Build(
            Rule(r => r.BlockedPorts =
            [
                new() { Port = 0 },
                new() { Port = 70000 },
                new() { Port = 65535, Protocol = "tcp" }
            ]),
            Context());

        Assert.DoesNotContain(plan.BlockedPorts, p => p.Port is 0 or 70000);
        Assert.Contains(plan.BlockedPorts, p => p.Port == 65535);
    }

    [Fact]
    public void Unknown_protocol_names_degrade_to_any_rather_than_being_ignored()
    {
        var plan = EgressPlanner.Build(
            Rule(r => r.BlockedPorts = [new() { Port = 8888, Protocol = "sctp" }]),
            Context());

        // שם פרוטוקול שלא הובן הופך לחסימה רחבה. הכיוון השני —
        // התעלמות — היה הופך שגיאת הקלדה בשרת לפורט פתוח.
        Assert.Equal("any", plan.BlockedPorts.Single(p => p.Port == 8888).Protocol);
    }

    // ─────────────────────────────────────────────── חסימה מוחלטת

    /*
     * ההתקנה ללא חשבון היא הפעולה היחידה במוצר שאין ממנה חזרה
     * מהמחשב עצמו. הבדיקות כאן מוודאות שהיא עושה בדיוק את מה
     * שהובטח, ובעיקר שהיא לא נפתחת בטעות.
     */

    private static EgressPlanner.Context Unmanaged(TrustLevel trust = TrustLevel.High)
        => new()
        {
            ServerIps = ServerIps,
            AgentPaths = AgentPaths,
            Unmanaged = true,
            Detection = new ProviderDetection
            {
                ProviderId = "netfree",
                DisplayName = "נטפרי",
                Trust = trust
            }
        };

    [Fact]
    public void Unmanaged_seals_the_machine_even_without_a_policy()
    {
        // הכלל מגיע מהשרת, ובהתקנה ללא חשבון אין שרת. אם הבדיקה
        // הזו נופלת, המשמעות היא שמחשב שנועד להיחסם לחלוטין נשאר
        // פתוח לגמרי — ההפך הגמור מהכוונה.
        var plan = EgressPlanner.Build(Rule(r => r.Enabled = false), Unmanaged());

        Assert.Equal(EgressPosture.Sealed, plan.Posture);
        Assert.True(plan.BlockAllOutbound);
    }

    [Fact]
    public void Sealed_overrides_a_recognised_provider()
    {
        // ספק מזוהה אינו פותח כלום כאן. מי שבחר בהתקנה הזו ביקש
        // מחשב בלי אינטרנט, לא מחשב עם אינטרנט מסונן.
        var plan = EgressPlanner.Build(Rule(), Unmanaged());

        Assert.Equal(EgressPosture.Sealed, plan.Posture);
        Assert.Empty(plan.AllowedPortRules);
    }

    [Fact]
    public void Sealed_closes_the_management_channel_too()
    {
        var plan = EgressPlanner.Build(Rule(), Unmanaged());

        // זה ההבדל מ-LockedDown: אין חשבון, אין למי לדווח, ולכן
        // היתר יוצא הוא פתח בלי שימוש.
        Assert.Empty(plan.ServerIps);
        Assert.Empty(plan.AllowedAppPaths);
        Assert.Empty(plan.AllowedResolvers);
        Assert.False(plan.AllowDns);
        Assert.True(plan.BlockAllInbound);
    }

    [Fact]
    public void Sealed_still_leaves_dhcp_and_loopback()
    {
        var plan = EgressPlanner.Build(Rule(), Unmanaged());

        // הלולאה המקומית — אחרת נשברת תקשורת פנימית של Windows.
        // DHCP — אחרת המחשב נראה תקול ולא חסום, וזה הבדל שמישהו
        // יצטרך להסביר בטלפון.
        Assert.True(plan.AllowLoopback);
        Assert.True(plan.AllowDhcp);
    }

    [Fact]
    public void Sealed_keeps_the_tunnel_blocks()
    {
        var plan = EgressPlanner.Build(Rule(), Unmanaged());

        // החסימה הכללית מכסה אותם ממילא, אבל הן שכבה שנייה מול
        // היתר שנוסף בטעות — וכאן אין שרת שיתקן טעות כזו.
        Assert.Contains(plan.BlockedProcessNames, n => n == "wireguard.exe");
        Assert.Contains(plan.BlockedPorts, p => p.Port == 1194);
    }

    [Fact]
    public void Not_unmanaged_with_a_disabled_rule_stays_disabled()
    {
        // הצד השני של אותו מטבע: הדגל הוא שקובע, לא היעדר מדיניות.
        var plan = EgressPlanner.Build(Rule(r => r.Enabled = false), Context());

        Assert.Equal(EgressPosture.Off, plan.Posture);
        Assert.False(plan.BlockAllOutbound);
    }
}
