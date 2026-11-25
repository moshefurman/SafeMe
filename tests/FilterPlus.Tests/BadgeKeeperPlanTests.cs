using FilterPlus.Core.Models;
using Xunit;

namespace FilterPlus.Tests;

/// <summary>
/// ההכרעה מה לתקן בתג שנעלם. "נעלם" חוזר בשטח בעוד התהליך חי.
/// </summary>
public sealed class BadgeKeeperPlanTests
{
    private static BadgeObservation Fine() => new(
        IsVisible: true, OnCurrentDesktop: true, InsideWorkArea: true, CoveredBy: null);

    [Fact]
    public void Nothing_to_repair_when_everything_is_in_place()
    {
        Assert.Equal(BadgeRepair.None, BadgeKeeperPlan.Decide(Fine()));
        Assert.Equal("התג במקומו", BadgeKeeperPlan.Describe(BadgeRepair.None, Fine()));
    }

    [Fact]
    public void Hidden_window_is_shown()
    {
        var o = Fine() with { IsVisible = false };

        Assert.Equal(BadgeRepair.Show, BadgeKeeperPlan.Decide(o));
    }

    [Fact]
    public void Other_virtual_desktop_moves_it_here()
    {
        var o = Fine() with { OnCurrentDesktop = false };

        Assert.Equal(BadgeRepair.MoveToCurrentDesktop, BadgeKeeperPlan.Decide(o));
    }

    [Fact]
    public void Outside_work_area_repositions()
    {
        var o = Fine() with { InsideWorkArea = false };

        Assert.Equal(BadgeRepair.Reposition, BadgeKeeperPlan.Decide(o));
    }

    [Fact]
    public void A_covering_application_window_is_climbed_over()
    {
        var o = Fine() with { CoveredBy = "zoom.exe: Zoom Meeting" };

        Assert.Equal(BadgeRepair.RaiseAboveCover, BadgeKeeperPlan.Decide(o));
        Assert.Contains("zoom.exe", BadgeKeeperPlan.Describe(BadgeRepair.RaiseAboveCover, o));
    }

    [Fact]
    public void The_shell_itself_is_not_climbed_over()
    {
        // תפריט התחלה, חיפוש, מסך נעילה: מכסים לרגע ובכוונת המשתמש.
        var o = Fine() with { CoveredBy = "StartMenuExperienceHost.exe", CoverIsShell = true };

        Assert.Equal(BadgeRepair.None, BadgeKeeperPlan.Decide(o));
    }

    [Fact]
    public void Several_faults_combine()
    {
        var o = new BadgeObservation(
            IsVisible: false, OnCurrentDesktop: false, InsideWorkArea: false, CoveredBy: "x.exe");

        var repair = BadgeKeeperPlan.Decide(o);

        Assert.True(repair.HasFlag(BadgeRepair.Show));
        Assert.True(repair.HasFlag(BadgeRepair.MoveToCurrentDesktop));
        Assert.True(repair.HasFlag(BadgeRepair.Reposition));
        Assert.True(repair.HasFlag(BadgeRepair.RaiseAboveCover));

        var text = BadgeKeeperPlan.Describe(repair, o);

        Assert.StartsWith("התג שוחזר", text);
        Assert.Contains("מוסתר", text);
        Assert.Contains("וירטואלי", text);
        Assert.Contains("x.exe", text);
    }
}
