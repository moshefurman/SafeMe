using System.Net;
using SafeMe.Core;
using SafeMe.Core.Abstractions;
using SafeMe.Core.DnsFilter;
using SafeMe.Core.Models;
using SafeMe.Core.Policy;
using Xunit;

namespace SafeMe.Tests;

/// <summary>
/// רשימה לבנה: התאמת שמות, פענוח DNS, והתוכנית.
///
/// שלושת החלקים כאן הם אלה שטעות בהם אינה נראית: שם שמתאים בטעות
/// פותח אתר שאיש לא אישר, הודעת DNS פגומה מגיעה מהרשת ואסור שתפיל
/// או תפתח דבר, ותוכנית שנבנתה לא נכון היא אינטרנט פתוח על קו שאינו
/// מסונן.
/// </summary>
public class WhitelistTests
{
    // ─────────────────────────────────────────────── התאמת שמות

    [Theory]
    [InlineData("example.com", true)]
    [InlineData("www.example.com", true)]
    [InlineData("a.b.c.example.com", true)]
    [InlineData("EXAMPLE.COM.", true)]
    [InlineData("notexample.com", false)]
    [InlineData("example.com.evil.net", false)]
    [InlineData("example.co", false)]
    [InlineData("com", false)]
    [InlineData("", false)]
    public void Domain_matches_whole_labels_only(string name, bool expected)
    {
        var matcher = new DomainMatcher(["example.com"]);

        Assert.Equal(expected, matcher.Matches(name));
    }

    [Fact]
    public void Subdomain_entry_does_not_open_its_parent()
    {
        var matcher = new DomainMatcher(["static.example.com"]);

        Assert.True(matcher.Matches("img.static.example.com"));
        Assert.False(matcher.Matches("example.com"));
        Assert.False(matcher.Matches("www.example.com"));
    }

    [Theory]
    [InlineData("com")]
    [InlineData("il")]
    [InlineData("exa mple.com")]
    [InlineData("example..com")]
    [InlineData("http://example.com")]
    [InlineData("example.com/path")]
    public void Entries_that_are_not_domains_are_dropped(string entry)
    {
        // "com" ברשימה היה פותח חצי מהאינטרנט. ערך כזה אינו נכנס.
        Assert.Null(DomainMatcher.Normalize(entry));
        Assert.Equal(0, new DomainMatcher([entry]).Count);
    }

    [Fact]
    public void Wildcard_prefix_and_case_are_normalized()
    {
        Assert.Equal("example.com", DomainMatcher.Normalize("*.Example.COM."));
    }

    [Fact]
    public void Empty_list_matches_nothing()
    {
        Assert.False(DomainMatcher.Empty.Matches("example.com"));
    }

    // ─────────────────────────────────────────────── DNS

    /// <summary>שאילתה כפי שלקוח שולח אותה.</summary>
    private static byte[] Query(string name, ushort type = DnsWire.TypeA)
    {
        var bytes = new List<byte> { 0xAB, 0xCD, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0 };

        foreach (var label in name.Split('.'))
        {
            bytes.Add((byte)label.Length);
            bytes.AddRange(System.Text.Encoding.ASCII.GetBytes(label));
        }

        bytes.Add(0);
        bytes.AddRange([(byte)(type >> 8), (byte)type, 0, 1]);

        return [.. bytes];
    }

    /// <summary>תשובה עם שרשרת CNAME ושתי כתובות, עם דחיסת שמות.</summary>
    private static byte[] Answer(byte[] query, uint ttl, params IPAddress[] addresses)
    {
        var bytes = new List<byte>(query);

        bytes[2] = 0x81;
        bytes[3] = 0x80;
        bytes[7] = (byte)(addresses.Length + 1);

        // CNAME: השם מהשאלה ← cdn.net
        bytes.AddRange([0xC0, 12, 0, 5, 0, 1, 0, 0, 0, 60, 0, 9]);
        bytes.AddRange([3, (byte)'c', (byte)'d', (byte)'n', 3, (byte)'n', (byte)'e', (byte)'t', 0]);

        foreach (var address in addresses)
        {
            var raw = address.GetAddressBytes();

            bytes.AddRange([0xC0, 12, 0, (byte)(raw.Length == 4 ? 1 : 28), 0, 1]);
            bytes.AddRange([(byte)(ttl >> 24), (byte)(ttl >> 16), (byte)(ttl >> 8), (byte)ttl]);
            bytes.AddRange([0, (byte)raw.Length]);
            bytes.AddRange(raw);
        }

        return [.. bytes];
    }

    [Fact]
    public void Question_is_read_and_lowercased()
    {
        var query = Query("WWW.Example.com", DnsWire.TypeAaaa);

        Assert.True(DnsWire.TryReadQuestion(query, out var name, out var type, out var end));
        Assert.Equal("www.example.com", name);
        Assert.Equal(DnsWire.TypeAaaa, type);
        Assert.Equal(query.Length, end);
    }

    [Fact]
    public void Responses_are_not_treated_as_questions()
    {
        var query = Query("example.com");
        query[2] |= 0x80;

        Assert.False(DnsWire.TryReadQuestion(query, out _, out _, out _));
    }

    [Fact]
    public void Truncated_and_garbage_input_is_rejected_without_throwing()
    {
        var query = Query("example.com");

        for (var length = 0; length < query.Length; length++)
            Assert.False(DnsWire.TryReadQuestion(query.AsSpan(0, length), out _, out _, out _));

        var random = new Random(7);

        for (var i = 0; i < 2000; i++)
        {
            var junk = new byte[random.Next(0, 80)];
            random.NextBytes(junk);

            // כל תוצאה מתקבלת, ובלבד שלא נזרקה חריגה
            DnsWire.TryReadQuestion(junk, out _, out _, out _);
            DnsWire.TryReadAddresses(junk, 300, []);
        }
    }

    [Fact]
    public void Name_error_response_echoes_the_question()
    {
        var query = Query("blocked.example");

        Assert.True(DnsWire.TryReadQuestion(query, out _, out _, out var end));

        var response = DnsWire.BuildEmpty(query, end, DnsWire.RcodeNameError);

        Assert.Equal(query[0], response[0]);
        Assert.Equal(query[1], response[1]);
        Assert.Equal(0x81, response[2]);
        Assert.Equal(0x83, response[3]);
        Assert.Equal(query.AsSpan(12).ToArray(), response.AsSpan(12).ToArray());
    }

    [Fact]
    public void Built_address_response_reads_back()
    {
        var query = Query("gate-check.safeme.invalid");

        Assert.True(DnsWire.TryReadQuestion(query, out _, out _, out var end));

        var response = DnsWire.BuildAddress(query, end, IPAddress.Parse("127.0.0.53"), ttl: 1);
        var addresses = new List<IPAddress>();

        Assert.True(DnsWire.TryReadAddresses(response, 300, addresses));
        Assert.Equal([IPAddress.Parse("127.0.0.53")], addresses);
    }

    [Fact]
    public void All_addresses_are_extracted_through_a_cname_chain()
    {
        var v4 = IPAddress.Parse("93.184.216.34");
        var v6 = IPAddress.Parse("2606:2800:220:1:248:1893:25c8:1946");
        var response = Answer(Query("www.example.com"), 60, v4, v6);
        var addresses = new List<IPAddress>();

        Assert.True(DnsWire.TryReadAddresses(response, 300, addresses));
        Assert.Equal([v4, v6], addresses);
    }

    [Fact]
    public void Long_ttl_is_clamped_in_place()
    {
        var response = Answer(Query("www.example.com"), 86400, IPAddress.Parse("93.184.216.34"));

        Assert.True(DnsWire.TryReadAddresses(response, 300, []));

        // קריאה שנייה, עם תקרה גבוהה, רואה את מה שנכתב בראשונה
        var copy = (byte[])response.Clone();
        var ttlOffset = response.Length - 4 - 2 - 4;

        Assert.Equal(300u, System.Buffers.Binary.BinaryPrimitives.ReadUInt32BigEndian(copy.AsSpan(ttlOffset)));
    }

    [Fact]
    public void Record_that_runs_past_the_end_fails_the_whole_message()
    {
        var response = Answer(Query("www.example.com"), 60, IPAddress.Parse("93.184.216.34"));
        var cut = response.AsSpan(0, response.Length - 2).ToArray();

        // הודעה פגומה אינה פותחת אף כתובת, גם לא את אלה שנקראו לפני הפגם
        Assert.False(DnsWire.TryReadAddresses(cut, 300, []));
    }

    [Theory]
    [InlineData("0.0.0.0", false)]
    [InlineData("::", false)]
    [InlineData("127.0.0.1", false)]
    [InlineData("::1", false)]
    [InlineData("255.255.255.255", false)]
    [InlineData("224.0.0.251", false)]
    [InlineData("0.1.2.3", false)]
    [InlineData("93.184.216.34", true)]
    [InlineData("192.168.1.10", true)]
    [InlineData("2606:4700::1111", true)]
    public void Sinkhole_and_local_answers_are_never_opened(string address, bool routable)
    {
        // 0.0.0.0 היא הדרך שבה שרת שמות מסווג אומר "חסום"
        Assert.Equal(routable, DnsWire.IsRoutable(IPAddress.Parse(address)));
    }

    // ─────────────────────────────────────────────── התוכנית

    private static EgressPlanner.Context Context(
        bool whitelist = true, string? forced = null, bool networkBlocked = false,
        bool unmanaged = false)
        => new()
        {
            ServerIps = ["203.0.113.10/32"],
            AgentPaths = [@"C:\Program Files\SafeMe\SafeMe.Service.exe"],
            WhitelistActive = whitelist,
            ForcedLockdownReason = forced,
            NetworkBlocked = networkBlocked,
            Unmanaged = unmanaged,

            // בלי ספק בכלל: קו לא מסונן
            Detection = null
        };

    [Fact]
    public void Whitelist_applies_without_any_provider_and_with_egress_disabled()
    {
        var plan = EgressPlanner.Build(new EgressRule { Enabled = false }, Context());

        Assert.True(plan.BlockAllOutbound);
        Assert.Equal(EgressPosture.Whitelist, plan.Posture);
    }

    [Fact]
    public void Whitelist_plan_opens_no_destination_by_itself()
    {
        var plan = EgressPlanner.Build(new EgressRule { Enabled = true }, Context());

        /*
         * זו הבדיקה החשובה כאן. ב-AllowedPortRules, רשימת יעדים ריקה
         * פירושה "לכל יעד" — ולכן פורט דפדוף שהיה נכנס לשם היה פותח
         * את כל האינטרנט על קו לא מסונן.
         */
        Assert.Empty(plan.AllowedPortRules);
        Assert.Empty(plan.AllowedRemoteCidrs);
        Assert.Empty(plan.AllowedPorts);

        Assert.Contains(plan.DynamicPortRules, p => p is { Port: 443, Protocol: "tcp" });
        Assert.Contains(plan.DynamicPortRules, p => p is { Port: 80, Protocol: "tcp" });
        Assert.DoesNotContain(plan.DynamicPortRules, p => p.Protocol == "udp");
    }

    [Fact]
    public void Whitelist_plan_closes_outbound_dns_and_keeps_the_server_reachable()
    {
        var plan = EgressPlanner.Build(
            new EgressRule { Enabled = true, Resolvers = ["198.51.100.5/32"] }, Context());

        // השאלות עוברות דרך הלולאה המקומית אל הסוכן, ורק הוא יוצא איתן
        Assert.False(plan.AllowDns);
        Assert.Empty(plan.AllowedResolvers);
        Assert.True(plan.AllowLoopback);

        Assert.Equal(["203.0.113.10/32"], plan.ServerIps);
        Assert.NotEmpty(plan.AllowedAppPaths);
    }

    [Fact]
    public void Whitelist_plan_still_blocks_tunnels()
    {
        var plan = EgressPlanner.Build(new EgressRule { Enabled = false }, Context());

        Assert.Contains("openvpn.exe", plan.BlockedProcessNames);
        Assert.Contains(plan.BlockedPorts, p => p.Port == 1194);
        Assert.True(plan.BlockAllInbound);
    }

    [Fact]
    public void Lockdown_reasons_override_whitelist()
    {
        var rule = new EgressRule { Enabled = false };

        var scheduled = EgressPlanner.Build(rule, Context(forced: "חסימה מתוזמנת"));
        var network = EgressPlanner.Build(rule, Context(networkBlocked: true));

        Assert.Equal(EgressPosture.LockedDown, scheduled.Posture);
        Assert.Empty(scheduled.DynamicPortRules);
        Assert.Equal(EgressPosture.LockedDown, network.Posture);
        Assert.Empty(network.DynamicPortRules);
    }

    [Fact]
    public void Unmanaged_install_stays_sealed()
    {
        var plan = EgressPlanner.Build(new EgressRule(), Context(unmanaged: true));

        Assert.Equal(EgressPosture.Sealed, plan.Posture);
        Assert.Empty(plan.DynamicPortRules);
    }

    [Fact]
    public void Without_whitelist_nothing_changes()
    {
        var off = EgressPlanner.Build(new EgressRule { Enabled = false }, Context(whitelist: false));
        var locked = EgressPlanner.Build(new EgressRule { Enabled = true }, Context(whitelist: false));

        Assert.False(off.BlockAllOutbound);
        Assert.Equal(EgressPosture.LockedDown, locked.Posture);
        Assert.Empty(locked.DynamicPortRules);
    }

    // ─────────────────────────────────────────────── הכלל עצמו

    [Fact]
    public void Learning_window_activates_the_rule_even_when_disabled()
    {
        var now = DateTimeOffset.UtcNow;
        var rule = new WhitelistRule { Enabled = false, LearnUntilUtc = now.AddMinutes(10) };

        Assert.True(rule.IsLearning(now));
        Assert.True(rule.IsActive(now));

        Assert.False(rule.IsLearning(now.AddMinutes(11)));
        Assert.False(rule.IsActive(now.AddMinutes(11)));
    }

    [Fact]
    public void Default_policy_has_whitelist_off()
    {
        var policy = PolicyBundle.CreateDefault();

        Assert.False(policy.Enforcement.Whitelist.IsActive(DateTimeOffset.UtcNow));
    }

    [Fact]
    public void Rule_reads_the_shape_the_server_sends()
    {
        const string json = """
            { "enforcement": { "whitelist": {
                "enabled": true,
                "domains": ["example.com", "cdn.example.net"],
                "systemDomains": ["msftconnecttest.com"],
                "upstreamResolvers": ["1.1.1.3", "1.0.0.3"],
                "learnUntilUtc": "2026-11-11T12:30:00.000Z"
            } } }
            """;

        var policy = SafeMeJson.Deserialize<PolicyBundle>(json)!;
        var rule = policy.Enforcement.Whitelist;

        Assert.True(rule.Enabled);
        Assert.Equal(["example.com", "cdn.example.net"], rule.Domains);
        Assert.Equal(["msftconnecttest.com"], rule.SystemDomains);
        Assert.Equal(new DateTimeOffset(2026, 11, 11, 12, 30, 0, TimeSpan.Zero), rule.LearnUntilUtc);
    }

    [Fact]
    public void Status_serializes_as_the_server_expects()
    {
        Assert.Equal("\"whitelist\"", SafeMeJson.Serialize(SecurityStatus.Whitelist));
        Assert.Equal("רשימה לבנה", TrayText.Status(SecurityStatus.Whitelist));
    }
}
