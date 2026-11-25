using FilterPlus.Uninstaller;

namespace FilterPlus.Tests;

/// <summary>
/// מתי המסיר פועל בלי חלון.
///
/// המסלול הזה נועד לבדיקות אוטומטיות בלבד, והסיכון שבו אינו
/// שהוא ייכשל — אלא שייתפס בטעות. משתמש שמפעיל את המסיר רגיל
/// ומקבל תהליך שקט שנסגר מיד לא יבין מה קרה, ולא תהיה לו דרך
/// לגלות.
///
/// לכן הבדיקה כאן היא על הכיוון האחר: שהפעלה רגילה, בכל צורה
/// סבירה שהיא מגיעה, פותחת חלון.
/// </summary>
public class HeadlessUninstallTests
{
    [Theory]
    [InlineData()]
    [InlineData("")]
    [InlineData("/silent")]
    [InlineData("--help")]
    [InlineData(@"C:\Program Files\FilterPlus\FilterPlus.Uninstaller.exe")]
    public void Ordinary_launch_opens_a_window(params string[] args)
    {
        Assert.False(Headless.Requested(args));
    }

    [Theory]
    [InlineData("--new-challenge")]
    [InlineData("--code", "W3GMYF-5FM3Z1-EMAZZS-ZSF6D5")]
    [InlineData("--challenge", "040C61-JRP94S", "--code", "ABC")]
    public void Explicit_flags_go_headless(params string[] args)
    {
        Assert.True(Headless.Requested(args));
    }
}
