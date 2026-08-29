using SafeMe.Core.Models;
using SafeMe.Core.Policy;

namespace SafeMe.Tests;

/// <summary>
/// ההצמדה לרצפה.
///
/// הבדיקות כאן נכתבו אחרי תקלה שעלתה ימים: מחשב דחה כל חבילת מדיניות
/// בגלל שדה אכיפה אחד, ולכן לא קיבל מעולם את כללי זיהוי הספקים — ודיווח
/// "לא מסונן" על מחשב שהיה מסונן לחלוטין. הבדיקה המרכזית כאן היא זו
/// שמוודאת שהכללים עוברים דווקא כשהאכיפה מוצמדת.
/// </summary>
public sealed class PolicyFloorClampTests
{
    private static PolicyFloorSpec StrictFloor() => new()
    {
        Mode = EnforcementMode.Enforce,
        OnRedAction = RedAction.Lockout,
        MinScoreForGreen = 85,
        MinScoreForYellow = 60
    };

    private static PolicyBundle LooseWithRules() => new()
    {
        Version = 7,
        IssuedUtc = DateTimeOffset.UtcNow,
        Providers =
        [
            new ProviderRule
            {
                Id = "rimon",
                DisplayName = "רימון",
                TlsIssuer = new TlsIssuerRule
                {
                    Patterns = ["*netspark*"],
                    Probes = ["www.bet365.com"]
                }
            }
        ],
        Enforcement = new EnforcementPolicy
        {
            Mode = EnforcementMode.Monitor,
            OnRedAction = RedAction.Warn,
            MinScoreForGreen = 70,
            MinScoreForYellow = 40
        }
    };

    [Fact]
    public void RaisesEveryAxisBackToTheFloor()
    {
        var result = PolicyFloorClamp.Apply(LooseWithRules(), StrictFloor());

        Assert.True(result.WasClamped);

        var e = result.Policy.Enforcement;

        Assert.Equal(EnforcementMode.Enforce, e.Mode);
        Assert.Equal(RedAction.Lockout, e.OnRedAction);
        Assert.Equal(85, e.MinScoreForGreen);
        Assert.Equal(60, e.MinScoreForYellow);
    }

    /// <summary>
    /// זו התקלה עצמה. כללי הזיהוי אינם נוגעים לרצפה, ואין שום סיבה
    /// שאכיפה מקלה תמנע מהם להגיע — אבל בדיוק זה מה שקרה.
    /// </summary>
    [Fact]
    public void DetectionRulesSurviveTheClamp()
    {
        var result = PolicyFloorClamp.Apply(LooseWithRules(), StrictFloor());

        var provider = Assert.Single(result.Policy.Providers);

        Assert.Equal("rimon", provider.Id);
        Assert.Equal("www.bet365.com", Assert.Single(provider.TlsIssuer!.Probes));
    }

    /// <summary>מדיניות שמוצמדת חייבת לעבור את בדיקת הרצפה עצמה.</summary>
    [Fact]
    public void ClampedPolicyPassesTheFloorCheck()
    {
        var floor = StrictFloor();
        var result = PolicyFloorClamp.Apply(LooseWithRules(), floor);

        var delta = StrictnessComparer.CheckAgainstFloor(
            floor.ToStrictness(), PolicyStrictness.FromPolicy(result.Policy));

        Assert.False(delta.IsLoosening, string.Join(" · ", delta.Reasons));
    }

    [Fact]
    public void PolicyAboveTheFloorIsReturnedUntouched()
    {
        var policy = LooseWithRules();

        policy.Enforcement.Mode = EnforcementMode.Enforce;
        policy.Enforcement.OnRedAction = RedAction.Lockout;
        policy.Enforcement.MinScoreForGreen = 90;
        policy.Enforcement.MinScoreForYellow = 70;

        var result = PolicyFloorClamp.Apply(policy, StrictFloor());

        Assert.False(result.WasClamped);
        Assert.Same(policy, result.Policy);
    }

    /// <summary>
    /// ההצמדה מייצרת עותק. שינוי המקור בידי הקורא לא היה נראה, וגרוע
    /// מכך — היה משנה חבילה שהחתימה עליה כבר אומתה.
    /// </summary>
    [Fact]
    public void DoesNotMutateTheOriginal()
    {
        var policy = LooseWithRules();

        PolicyFloorClamp.Apply(policy, StrictFloor());

        Assert.Equal(EnforcementMode.Monitor, policy.Enforcement.Mode);
        Assert.Equal(RedAction.Warn, policy.Enforcement.OnRedAction);
    }

    /// <summary>
    /// החתימה נחתמה על גוף אחר מזה שיצא מההצמדה, ולכן אינה מועברת.
    /// שדה חתימה שאינו מאמת את מה שהוא יושב עליו הוא מלכודת.
    /// </summary>
    [Fact]
    public void DropsTheSignatureWhenTheBodyChanges()
    {
        var policy = LooseWithRules();

        policy.Signature = "AAAA";

        Assert.Null(PolicyFloorClamp.Apply(policy, StrictFloor()).Policy.Signature);
    }

    // ---------------------------------------------------------------- ספקים

    [Fact]
    public void EmptyRequirementIsRestoredFromTheFloor()
    {
        var floor = StrictFloor();

        floor.RequireProvider = ["rimon"];

        var result = PolicyFloorClamp.Apply(LooseWithRules(), floor);

        Assert.Equal(["rimon"], result.Policy.Enforcement.AllowedNetworks.RequireProvider);
    }

    [Fact]
    public void ProvidersOutsideTheFloorAreDropped()
    {
        var floor = StrictFloor();

        floor.RequireProvider = ["rimon"];

        var policy = LooseWithRules();

        policy.Enforcement.AllowedNetworks.RequireProvider = ["rimon", "anything"];

        var result = PolicyFloorClamp.Apply(policy, floor);

        Assert.Equal(["rimon"], result.Policy.Enforcement.AllowedNetworks.RequireProvider);
    }

    /// <summary>
    /// רצפה ללא דרישת ספק אינה מגבילה דבר, ומדיניות שמגדירה דרישה
    /// מהדקת מעליה. קודם זה סווג כהקלה, והמדיניות נדחתה.
    /// </summary>
    [Fact]
    public void AddingARequirementAboveAnUnrestrictedFloorIsTightening()
    {
        var policy = LooseWithRules();

        policy.Enforcement.AllowedNetworks.RequireProvider = ["rimon"];

        var delta = StrictnessComparer.CheckAgainstFloor(
            new PolicyFloorSpec
            {
                Mode = EnforcementMode.Monitor,
                OnRedAction = RedAction.Warn,
                MinScoreForGreen = 70,
                MinScoreForYellow = 40
            }.ToStrictness(),
            PolicyStrictness.FromPolicy(policy));

        Assert.False(delta.IsLoosening, string.Join(" · ", delta.Reasons));
    }
}
