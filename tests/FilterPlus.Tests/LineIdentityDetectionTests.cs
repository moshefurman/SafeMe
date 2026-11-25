using FilterPlus.Core.Audit;
using FilterPlus.Core.Models;
using FilterPlus.Core.Policy;
using FilterPlus.Service.Audit;
using Xunit;

namespace FilterPlus.Tests;

/// <summary>
/// זיהוי לפי הקו: ASN וטווח כתובות.
///
/// נמדד ב-3.9.2026 על קו של רימון: התעודה נעלמה (רימון עברה
/// לנתק במקום להגיש), הכתובת 213.151.47.152 ישבה מחוץ לטווח
/// היחיד שהיה רשום, וה-ASN — שנקרא בכל פעימה — לא נספר כלל.
/// המחשב דווח כלא מסונן על קו מסונן.
/// </summary>
public sealed class LineIdentityDetectionTests
{
    private static ProviderRule Rimon() =>
        PolicyBundle.BuiltInProviders().Single(p => p.Id == "rimon");

    [Fact]
    public void Asn_counts_as_a_live_vector()
    {
        var detection = new ProviderDetection { ProviderId = "rimon", AsnMatch = true };

        Assert.Equal(1, detection.MatchCount);
        Assert.Contains("ספק הקו", detection.MatchedVectors);
        Assert.True(detection.HasAnySignal);
    }

    [Fact]
    public void Asn_and_ip_range_together_reach_high_trust()
    {
        var detection = new ProviderDetection
        {
            ProviderId = "rimon", AsnMatch = true, IpRangeMatch = true
        };

        Assert.Equal(TrustLevel.High, ScoreCalculator.ResolveTrust(detection, Rimon()));
    }

    [Fact]
    public void Built_in_rimon_knows_its_asn()
    {
        Assert.Contains(42925, Rimon().Network!.Asns);
    }

    [Theory]
    [InlineData("213.151.47.152")] // הכתובת שנמדדה — מחוץ ל-213.151.48.0/20 הישן
    [InlineData("213.151.50.7")]   // בתוך הטווח הישן, וגם בחדש
    [InlineData("95.86.100.1")]
    [InlineData("31.44.130.9")]
    public void Built_in_rimon_covers_its_announced_prefixes(string ip)
    {
        Assert.True(NetworkIdentityAuditor.IsInAnyCidr(ip, Rimon().Network!.Cidrs));
    }

    [Fact]
    public void The_old_single_range_missed_the_measured_address()
    {
        // מתעד את הכשל: הטווח היחיד שהיה רשום לא כיסה את הקו האמיתי.
        Assert.False(NetworkIdentityAuditor.IsInAnyCidr("213.151.47.152", ["213.151.48.0/20"]));
    }

    [Theory]
    [InlineData("8.8.8.8")]
    [InlineData("192.168.11.5")]
    public void Strangers_are_outside_rimon(string ip)
    {
        Assert.False(NetworkIdentityAuditor.IsInAnyCidr(ip, Rimon().Network!.Cidrs));
    }
}
