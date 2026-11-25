using System.Security.Cryptography;
using FilterPlus.Core;
using FilterPlus.Core.Audit;
using FilterPlus.Core.Models;
using FilterPlus.Core.Policy;
using FilterPlus.Core.Security;
using Xunit;

namespace FilterPlus.Tests;

/// <summary>מאגר מצב בזיכרון, לבדיקת הגבלת הקצב ללא תלות בדיסק.</summary>
internal sealed class InMemoryStateStore : IUninstallStateStore
{
    public UninstallAttemptState State { get; private set; } = new();

    public List<(TamperKind Kind, string Detail)> Tampers { get; } = new();

    public UninstallAttemptState Load() => State;

    public void Save(UninstallAttemptState state) => State = state;

    public void ReportTamper(TamperKind kind, string detail) => Tampers.Add((kind, detail));
}

public class UninstallAttemptGuardTests
{
    private const string Hwid = "TESTHWID0123456789ABCDEF";

    private static readonly byte[] Secret = RandomNumberGenerator.GetBytes(32);

    private static (UninstallAttemptGuard Guard, InMemoryStateStore Store) Create()
    {
        var store = new InMemoryStateStore();
        return (new UninstallAttemptGuard(store), store);
    }

    [Fact]
    public void ValidCode_IsAcceptedAndIssuesToken()
    {
        var (guard, store) = Create();

        var (challenge, rejection) = guard.IssueChallenge(Hwid, UninstallKeyMode.Hmac);

        Assert.Null(rejection);
        Assert.NotNull(challenge);

        var response = ChallengeResponseService.GenerateHmacResponse(challenge!, Secret);

        var result = guard.Verify(
            challenge!.ToDisplayString(), response, Hwid, UninstallKeyMode.Hmac, null, null, Secret);

        Assert.True(result.Granted);
        Assert.NotNull(guard.GetGrantedToken());
        Assert.Single(store.State.UsedNonces);
    }

    [Fact]
    public void ThreeWrongCodes_TriggerLockout()
    {
        var (guard, store) = Create();

        var (challenge, _) = guard.IssueChallenge(Hwid, UninstallKeyMode.Hmac);
        var wrong = ChallengeResponseService.GenerateHmacResponse(
            challenge!, RandomNumberGenerator.GetBytes(32));

        var text = challenge!.ToDisplayString();

        var first = guard.Verify(text, wrong, Hwid, UninstallKeyMode.Hmac, null, null, Secret);
        var second = guard.Verify(text, wrong, Hwid, UninstallKeyMode.Hmac, null, null, Secret);
        var third = guard.Verify(text, wrong, Hwid, UninstallKeyMode.Hmac, null, null, Secret);

        Assert.Equal(2, first.AttemptsLeft);
        Assert.Equal(1, second.AttemptsLeft);
        Assert.Equal(ChallengeValidation.RateLimited, third.Status);
        Assert.NotNull(third.LockoutUntil);
        Assert.Contains(store.Tampers, t => t.Kind == TamperKind.UninstallBruteForce);
    }

    [Fact]
    public void Lockout_BlocksNewChallenges()
    {
        var (guard, _) = Create();

        LockOut(guard);

        var (challenge, rejection) = guard.IssueChallenge(Hwid, UninstallKeyMode.Hmac);

        Assert.Null(challenge);
        Assert.Equal(ChallengeValidation.RateLimited, rejection!.Status);
    }

    [Fact]
    public void ClockRollback_DoesNotShortenLockout()
    {
        var (guard, store) = Create();

        LockOut(guard);

        var lockoutUntil = store.State.LockoutUntilUtc;
        Assert.NotNull(lockoutUntil);

        // המשתמש מזיז את שעון המערכת שעה אחורה כדי לעקוף את הנעילה
        var rolledBack = DateTimeOffset.UtcNow.AddHours(-1);
        var (active, until) = guard.GetLockoutState(rolledBack);

        Assert.True(active);
        Assert.Equal(lockoutUntil, until);
    }

    [Fact]
    public void RepeatedLockouts_EscalateDuration()
    {
        var (guard, store) = Create();

        LockOut(guard);
        var firstDuration = store.State.LockoutUntilUtc!.Value - DateTimeOffset.UtcNow;

        // מדלגים אל מעבר לנעילה הראשונה ונכשלים שוב
        var later = store.State.LockoutUntilUtc!.Value.AddMinutes(1);
        LockOut(guard, later);

        var secondDuration = store.State.LockoutUntilUtc!.Value - later;

        Assert.True(secondDuration > firstDuration,
            $"נעילה שנייה ({secondDuration}) אמורה להיות ארוכה מהראשונה ({firstDuration}).");
    }

    [Fact]
    public void TypoInChallenge_DoesNotConsumeAttempt()
    {
        var (guard, store) = Create();

        guard.IssueChallenge(Hwid, UninstallKeyMode.Hmac);

        // אתגר פגום נובע מטעות הקלדה ואינו ניסיון תקיפה
        var result = guard.Verify(
            "AAAAAA-BBBBBB-CCCCCC", "SOMECODE", Hwid, UninstallKeyMode.Hmac, null, null, Secret);

        Assert.Equal(ChallengeValidation.MalformedChallenge, result.Status);
        Assert.Equal(0, store.State.FailedAttempts);
    }

    private static void LockOut(UninstallAttemptGuard guard, DateTimeOffset? now = null)
    {
        var (challenge, _) = guard.IssueChallenge(Hwid, UninstallKeyMode.Hmac, now);

        Assert.NotNull(challenge);

        var wrong = ChallengeResponseService.GenerateHmacResponse(
            challenge!, RandomNumberGenerator.GetBytes(32));

        for (var i = 0; i < 3; i++)
            guard.Verify(challenge!.ToDisplayString(), wrong, Hwid,
                UninstallKeyMode.Hmac, null, null, Secret, now);
    }
}

public class ScoreCalculatorTests
{
    [Fact]
    public void Score_IsWeightedAverage()
    {
        List<ProbeResult> results =
        [
            ProbeResult.Pass("a", "T", 30),
            ProbeResult.Pass("b", "T", 20),
            ProbeResult.Fail("c", "T", 50, ProbeSeverity.Warning)
        ];

        Assert.Equal(50, ScoreCalculator.ComputeScore(results));
    }

    [Fact]
    public void InconclusiveProbes_AreExcluded()
    {
        List<ProbeResult> results =
        [
            ProbeResult.Pass("a", "T", 50),
            ProbeResult.Inconclusive("b", "T")
        ];

        // גשש שלא הסתיים לא אמור להעניש ולא לזכות
        Assert.Equal(100, ScoreCalculator.ComputeScore(results));
    }

    [Fact]
    public void CriticalFailure_CapsScore()
    {
        List<ProbeResult> results =
        [
            ProbeResult.Pass("a", "T", 90),
            ProbeResult.Fail("critical", "T", 10, ProbeSeverity.Critical)
        ];

        Assert.Equal(ScoreCalculator.CriticalFailureCeiling, ScoreCalculator.ComputeScore(results));
    }

    [Fact]
    public void Status_RequiresHighTrustForGreen()
    {
        var policy = new EnforcementPolicy { MinScoreForGreen = 85, MinScoreForYellow = 60 };

        var highTrust = new ProviderDetection
        {
            ProviderId = "netfree", Trust = TrustLevel.High, RootCaMatch = true, IpRangeMatch = true
        };

        var mediumTrust = new ProviderDetection
        {
            ProviderId = "netfree", Trust = TrustLevel.Medium, RootCaMatch = true
        };

        Assert.Equal(SecurityStatus.Safe, ScoreCalculator.ResolveStatus(95, highTrust, policy, false));
        Assert.Equal(SecurityStatus.LowFilter, ScoreCalculator.ResolveStatus(95, mediumTrust, policy, false));
        Assert.Equal(SecurityStatus.Blocked, ScoreCalculator.ResolveStatus(95, highTrust, policy, true));
    }

    [Fact]
    public void Trust_RequiresTwoVectorsForHigh()
    {
        var rule = new ProviderRule { Id = "netfree", TrustLevel = TrustLevel.High };

        var single = new ProviderDetection { ProviderId = "netfree", IpRangeMatch = true };
        var dual = new ProviderDetection { ProviderId = "netfree", IpRangeMatch = true, TlsIssuerMatch = true };
        var none = new ProviderDetection { ProviderId = "netfree" };

        Assert.Equal(TrustLevel.Medium, ScoreCalculator.ResolveTrust(single, rule));
        Assert.Equal(TrustLevel.High, ScoreCalculator.ResolveTrust(dual, rule));
        Assert.Equal(TrustLevel.None, ScoreCalculator.ResolveTrust(none, rule));
    }

    /// <summary>
    /// המקרה שנצפה בשטח: המחשב עבר לרשת סלולרית בלי שום סינון,
    /// והסוכן המשיך להציג את רימון כספק שלו.
    ///
    /// הסיבה הייתה שתעודת השורש נספרה כווקטור. היא נשארת מותקנת
    /// לנצח, ולכן "התאימה" גם ברשת שאין לספק שום נגיעה אליה.
    ///
    /// הבדיקה הקודמת דווקא עברה — היא קבעה שתעודת שורש לבדה נותנת
    /// ביטחון בינוני, כלומר קידדה את הבאג כדרישה. זו הפעם הרביעית
    /// בפרויקט הזה שבדיקה שמרה על התנהגות שגויה, ולכן היא נכתבת
    /// כאן במפורש בשם התופעה ולא בשם המנגנון.
    /// </summary>
    [Fact]
    public void RootCertificateAloneIsNotDetection()
    {
        var rule = new ProviderRule { Id = "rimon", TrustLevel = TrustLevel.High };

        var leftoverCertificate = new ProviderDetection { ProviderId = "rimon", RootCaMatch = true };

        Assert.Equal(0, leftoverCertificate.MatchCount);
        Assert.Empty(leftoverCertificate.MatchedVectors);
        Assert.Equal(TrustLevel.None, ScoreCalculator.ResolveTrust(leftoverCertificate, rule));
    }

    [Fact]
    public void RootCertificateAddsNothingToALiveMatch()
    {
        var rule = new ProviderRule { Id = "rimon", TrustLevel = TrustLevel.High };

        var withoutCertificate = new ProviderDetection { ProviderId = "rimon", TlsIssuerMatch = true };
        var withCertificate = new ProviderDetection
        {
            ProviderId = "rimon", TlsIssuerMatch = true, RootCaMatch = true
        };

        // משקל אפס: נוכחות התעודה אינה משנה דבר לכאן או לכאן
        Assert.Equal(withoutCertificate.MatchCount, withCertificate.MatchCount);
        Assert.Equal(
            ScoreCalculator.ResolveTrust(withoutCertificate, rule),
            ScoreCalculator.ResolveTrust(withCertificate, rule));
    }

    [Fact]
    public void MissingRequiredCertificateStillVetoes()
    {
        var rule = new ProviderRule
        {
            Id = "rimon",
            TrustLevel = TrustLevel.High,
            RootCa = new RootCaRule { Required = true }
        };

        var twoLiveVectors = new ProviderDetection
        {
            ProviderId = "rimon", TlsIssuerMatch = true, IpRangeMatch = true
        };

        // וטו, לא ראיה. הוא יכול רק להוריד את הטענה להגנה.
        Assert.Equal(TrustLevel.Low, ScoreCalculator.ResolveTrust(twoLiveVectors, rule));
    }

    [Fact]
    public void CertificateStillWorthProbingFor()
    {
        var leftoverCertificate = new ProviderDetection { ProviderId = "rimon", RootCaMatch = true };
        var nothingAtAll = new ProviderDetection { ProviderId = "rimon" };

        // ניקוד אפס, אבל עדיין סיבה לשלוח בדיקה חיה לספק הזה
        // ולא לכל השאר. זה כל מה שנשאר לה.
        Assert.True(leftoverCertificate.HasAnySignal);
        Assert.False(nothingAtAll.HasAnySignal);
    }

    [Fact]
    public void Trust_IsCappedByPolicy()
    {
        var rule = new ProviderRule { Id = "weak", TrustLevel = TrustLevel.Medium };

        var detection = new ProviderDetection
        {
            ProviderId = "weak", RootCaMatch = true, IpRangeMatch = true, HttpMarkerMatch = true
        };

        // גם עם שלושה וקטורים, המדיניות מגבילה את רמת האמון בספק הזה
        Assert.Equal(TrustLevel.Medium, ScoreCalculator.ResolveTrust(detection, rule));
    }

    [Fact]
    public void RequiredRootCaMissing_LimitsTrust()
    {
        var rule = new ProviderRule
        {
            Id = "netfree",
            TrustLevel = TrustLevel.High,
            RootCa = new RootCaRule { Required = true, Thumbprints = ["ABC"] }
        };

        var detection = new ProviderDetection
        {
            ProviderId = "netfree", IpRangeMatch = true, ReverseDnsMatch = true, RootCaMatch = false
        };

        Assert.Equal(TrustLevel.Low, ScoreCalculator.ResolveTrust(detection, rule));
    }
}

public class ScheduleRuleTests
{
    /// <summary>
    /// השרת שולח ימים כמספרים, והסוכן מפרש DayOfWeek.
    ///
    /// זו נקודת הכשל הקלאסית בין שתי השפות: FilterPlusJson מגדיר
    /// JsonStringEnumConverter, שכותב מחרוזות — ואם הוא גם *קורא*
    /// מחרוזות בלבד, כל חלון זמן שהשרת ישלח יידחה בשקט והמחשב לא
    /// ייחסם אף פעם.
    ///
    /// הכשל היה בלתי נראה לגמרי: המדיניות נכנסת, החלון קיים במסך
    /// ההורה, והאכיפה פשוט לא קורית.
    /// </summary>
    [Fact]
    public void Days_arrive_as_numbers_from_the_server()
    {
        const string json = """
            {"id":"night","days":[0,5],"from":"22:00","to":"07:00","action":"BlockAll"}
            """;

        var rule = FilterPlusJson.Deserialize<ScheduleRule>(json);

        Assert.NotNull(rule);
        Assert.Equal([DayOfWeek.Sunday, DayOfWeek.Friday], rule!.Days);
    }

    /// <summary>
    /// והמספור עצמו: 0 הוא ראשון, 6 הוא שבת.
    ///
    /// זה מה שהשרת מניח כשהוא שומר את בחירת ההורה. מספור שונה בשני
    /// הצדדים היה חוסם ביום הלא נכון — וההורה היה מגלה זאת רק
    /// כשהילד גולש בשבת בלילה.
    /// </summary>
    [Theory]
    [InlineData(0, DayOfWeek.Sunday)]
    [InlineData(5, DayOfWeek.Friday)]
    [InlineData(6, DayOfWeek.Saturday)]
    public void The_day_numbering_matches_the_portal(int sent, DayOfWeek expected)
    {
        var rule = FilterPlusJson.Deserialize<ScheduleRule>(
            $$"""{"id":"x","days":[{{sent}}],"from":"01:00","to":"02:00"}""");

        Assert.Equal(expected, Assert.Single(rule!.Days));
    }

    /// <summary>רשימת ימים ריקה חלה על כל ימות השבוע.</summary>
    [Fact]
    public void No_days_means_every_day()
    {
        var rule = new ScheduleRule { Id = "x", From = "22:00", To = "23:00" };

        foreach (var day in Enum.GetValues<DayOfWeek>())
        {
            var at = new DateTime(2026, 8, 23, 22, 30, 0)
                .AddDays((int)day - (int)DayOfWeek.Sunday);

            Assert.True(rule.IsActiveAt(at), $"{day}");
        }
    }

    [Fact]
    public void Window_CrossingMidnight_IsHandled()
    {
        var rule = new ScheduleRule { Id = "night", From = "23:30", To = "05:30" };

        Assert.True(rule.IsActiveAt(new DateTime(2026, 8, 25, 23, 45, 0)));
        Assert.True(rule.IsActiveAt(new DateTime(2026, 8, 26, 2, 0, 0)));
        Assert.False(rule.IsActiveAt(new DateTime(2026, 8, 26, 6, 0, 0)));
    }

    [Fact]
    public void DayFilter_IsRespected()
    {
        var rule = new ScheduleRule
        {
            Id = "weekdays",
            Days = [DayOfWeek.Monday],
            From = "08:00",
            To = "17:00"
        };

        // 2026-08-24 הוא יום שני, 2026-08-25 הוא יום שלישי
        Assert.True(rule.IsActiveAt(new DateTime(2026, 8, 24, 9, 0, 0)));
        Assert.False(rule.IsActiveAt(new DateTime(2026, 8, 25, 9, 0, 0)));
    }
}

public class HardwareIdTests
{
    [Fact]
    public void Build_IsStableForSameComponents()
    {
        List<string?> components = ["GUID-1234-5678", "BASEBOARD-9999", "CPU-ABCDEF"];

        Assert.Equal(HardwareIdBuilder.Build(components), HardwareIdBuilder.Build(components));
    }

    [Fact]
    public void Build_IgnoresManufacturerPlaceholders()
    {
        List<string?> withPlaceholders =
            ["GUID-1234-5678", "To be filled by O.E.M.", null, "  ", "BASEBOARD-9999"];

        List<string?> clean = ["GUID-1234-5678", "BASEBOARD-9999"];

        Assert.Equal(HardwareIdBuilder.Build(clean), HardwareIdBuilder.Build(withPlaceholders));
    }

    [Fact]
    public void Build_DiffersBetweenMachines()
    {
        Assert.NotEqual(
            HardwareIdBuilder.Build(["GUID-1111", "BOARD-1111"]),
            HardwareIdBuilder.Build(["GUID-2222", "BOARD-2222"]));
    }

    [Fact]
    public void Build_ThrowsWhenNoStableComponent()
    {
        Assert.Throws<InvalidOperationException>(() =>
            HardwareIdBuilder.Build([null, "", "none", "0000-0000"]));
    }
}
