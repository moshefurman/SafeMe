using SafeMe.Core.Audit;
using SafeMe.Core.Models;
using SafeMe.Core.Policy;

namespace SafeMe.Tests;

/// <summary>
/// הציון כשהראיה היחידה היא זהות הספק.
///
/// זה המצב בשטח, ולא מקרה קצה: מדיניות הבסיס אינה מגדירה גששי תוכן,
/// ולכן גשש הזהות הוא הגשש היחיד שנספר. כל התנהגות שלו היא הציון
/// כולו, וכל אפס שלו הוא "אינו מסונן" בפורטל.
/// </summary>
public sealed class ProviderOnlyScoreTests
{
    private static readonly EnforcementPolicy Thresholds = new()
    {
        MinScoreForGreen = 85,
        MinScoreForYellow = 60
    };

    private static ProviderDetection Detected(TrustLevel trust, int matches) => new()
    {
        ProviderId = "rimon",
        DisplayName = "רימון",
        Trust = trust,
        DetectionRan = true,
        TlsIssuerMatch = matches >= 1,
        HttpMarkerMatch = matches >= 2,
        IpRangeMatch = matches >= 3
    };

    private static SecurityStatus StatusOf(ProbeResult identity, ProviderDetection detection) =>
        ScoreCalculator.ResolveStatus(
            ScoreCalculator.ComputeScore([identity]), detection, Thresholds, lockoutActive: false);

    /// <summary>
    /// התקלה עצמה: ספק שזוהה בווקטור אחד דיווח "אינו מסונן".
    ///
    /// הגשש נספר ככישלון מלא, הוא היה הגשש היחיד, והציון יצא 0 —
    /// כלומר בדיוק אותה תוצאה כמו מחשב שאין בו סינון כלל.
    /// </summary>
    [Fact]
    public void OneVectorIsPartialFilteringAndNotNone()
    {
        var identity = ProbeResult.Partial(
            "provider-identity", "ProviderIdentity", 25, 15, ProbeSeverity.Warning);

        Assert.Equal(60, ScoreCalculator.ComputeScore([identity]));
        Assert.Equal(SecurityStatus.LowFilter, StatusOf(identity, Detected(TrustLevel.Medium, 1)));
    }

    [Fact]
    public void TwoVectorsAreFullyFiltered()
    {
        var identity = ProbeResult.Pass("provider-identity", "ProviderIdentity", 25);

        Assert.Equal(100, ScoreCalculator.ComputeScore([identity]));
        Assert.Equal(SecurityStatus.Safe, StatusOf(identity, Detected(TrustLevel.High, 2)));
    }

    /// <summary>ספק שלא זוהה כלל נשאר "אינו מסונן". הראיה החיובית היא שעברה.</summary>
    [Fact]
    public void NoProviderStaysUnfiltered()
    {
        var identity = ProbeResult.Fail(
            "provider-identity", "ProviderIdentity", 25, ProbeSeverity.Critical);

        Assert.Equal(0, ScoreCalculator.ComputeScore([identity]));

        Assert.Equal(
            SecurityStatus.Unfiltered,
            StatusOf(identity, new ProviderDetection { DetectionRan = true }));
    }

    /// <summary>ראיה חלקית אינה כישלון, ואינה אמורה להופיע ברשימת הכשלים.</summary>
    [Fact]
    public void PartialIsNotCountedAsAFailure()
    {
        var report = new AuditReport();

        report.Results.Add(ProbeResult.Partial("a", "K", 25, 15, ProbeSeverity.Warning));
        report.Results.Add(ProbeResult.Fail("b", "K", 10, ProbeSeverity.Warning));

        Assert.Equal("b", Assert.Single(report.Failures).ProbeId);
    }

    [Fact]
    public void CreditNeverExceedsWeight()
    {
        Assert.Equal(25, ProbeResult.Partial("a", "K", 25, 900, ProbeSeverity.Warning).Credit);
        Assert.Equal(0, ProbeResult.Partial("a", "K", 25, -900, ProbeSeverity.Warning).Credit);
    }

    /// <summary>
    /// ראיה חלקית מצטרפת לגששים אחרים במקום להתאפס מולם.
    /// </summary>
    [Fact]
    public void PartialCreditMixesWithOtherProbes()
    {
        var score = ScoreCalculator.ComputeScore(
        [
            ProbeResult.Partial("provider-identity", "ProviderIdentity", 25, 15, ProbeSeverity.Warning),
            ProbeResult.Pass("content", "Content", 25)
        ]);

        Assert.Equal(80, score);
    }
}
