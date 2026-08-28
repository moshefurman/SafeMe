using System.Net.Security;
using System.Security.Authentication;
using System.Net.Sockets;
using System.Runtime.Versioning;
using System.Security.Cryptography.X509Certificates;

using Microsoft.Extensions.Logging;

using SafeMe.Core.Policy;

namespace SafeMe.Service.Audit;

/// <summary>מה נצפה על החיבור למארח אחד.</summary>
public enum TlsObservation
{
    /// <summary>לא הצלחנו להגיע כלל. אין מזה מה ללמוד.</summary>
    Unreachable,

    /// <summary>לחיצת היד נותקה. סימן לחסימה, אך בלי זהות.</summary>
    Reset,

    /// <summary>התקבלה תעודה.</summary>
    Certificate,
}

public sealed record TlsProbe(string Host, TlsObservation Observation, string? Issuer);

/// <summary>
/// בודק מי הנפיק את התעודה שמוצגת בגלישה בפועל.
///
/// זהו הווקטור החזק ביותר לזיהוי ספק שמסנן דרך פרוקסי, והוא לא היה
/// קיים. שלושת הווקטורים הקודמים בודקים דברים עקיפים: מה מותקן
/// במחשב, מאיזו כתובת הוא יוצא, ומה שרת חיצוני אומר עליו. כאן
/// נמדד החיבור עצמו.
///
/// כשהסינון מגיש דף חסימה הוא **חייב** להציג תעודה משלו, ושם
/// המנפיק הוא חתימה שאי אפשר לזייף בלי המפתח הפרטי שלו. זה מה
/// שמבדיל בין "כנראה מסונן" לבין "מסונן דרך רימון".
///
/// חשוב לא פחות ממה שהוא עושה: **מה שהוא אינו עושה.** אין כאן בקשת
/// HTTP ולא יורד שום תוכן — רק לחיצת יד, שקוראת את התעודה ומנתקת.
/// המארחים הנבדקים נבחרים דווקא בקטגוריות שהסינון חוסם, ולכן חיבור
/// מלא אליהם היה בדיוק מה שאסור.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class TlsIssuerAuditor
{
    /// <summary>
    /// פסק זמן קצר לכל מארח.
    ///
    /// הבדיקה רצה בכל ביקורת, ומארח שאינו מגיב אינו אמור לעכב
    /// אותה. ניתוק מהיר הוא ממילא התוצאה השכיחה.
    /// </summary>
    private static readonly TimeSpan Timeout = TimeSpan.FromSeconds(6);

    private readonly ILogger<TlsIssuerAuditor> _log;

    public TlsIssuerAuditor(ILogger<TlsIssuerAuditor> log) => _log = log;

    /// <summary>
    /// מוצא ספק שמנפיק התעודה שלו תואם.
    ///
    /// עוצר במארח הראשון שנתן זהות: אין טעם להמשיך לדפוק בדלתות
    /// אחרי שהתשובה ידועה, וכל בדיקה נוספת היא עוד חיבור לאתר
    /// בקטגוריה חסומה.
    /// </summary>
    public async Task<(bool Matched, string? Issuer)> MatchesAsync(
        ProviderRule provider, CancellationToken ct)
    {
        var rule = provider.TlsIssuer;

        if (rule is null || rule.Patterns.Count == 0 || rule.Probes.Count == 0)
            return (false, null);

        foreach (var host in rule.Probes)
        {
            var probe = await ObserveAsync(host, ct);

            if (probe.Observation != TlsObservation.Certificate || probe.Issuer is null)
                continue;

            foreach (var pattern in rule.Patterns)
            {
                if (!Wildcard.IsMatch(probe.Issuer, pattern)) continue;

                _log.LogInformation(
                    "מנפיק התעודה על {Host} תואם ל-{Provider}: {Issuer}",
                    host, provider.Id, probe.Issuer);

                return (true, probe.Issuer);
            }

            // תעודה שהתקבלה ואינה תואמת היא מידע בפני עצמו: המארח
            // נגיש ואינו מסונן על ידי הספק הזה.
            return (false, probe.Issuer);
        }

        return (false, null);
    }

    /// <summary>
    /// לחיצת יד אחת. אין בקשה ואין קריאת תוכן.
    /// </summary>
    public async Task<TlsProbe> ObserveAsync(string host, CancellationToken ct)
    {
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);

        cts.CancelAfter(Timeout);

        try
        {
            using var tcp = new TcpClient();

            await tcp.ConnectAsync(host, 443, cts.Token);

            /*
             * אימות התעודה מבוטל במכוון.
             *
             * המטרה היא לקרוא מי הנפיק אותה, ולא לסמוך עליה. תעודת
             * סינון היא בהגדרה תעודה שהדפדפן סומך עליה רק בגלל
             * שורש שהותקן — ואימות רגיל היה מפיל את הבדיקה בדיוק
             * במקרה שאותו אנחנו מחפשים.
             *
             * שום נתון אינו נשלח על החיבור הזה, ולכן אין מה להגן
             * עליו.
             */
            using var ssl = new SslStream(tcp.GetStream(), leaveInnerStreamOpen: false,
                (_, _, _, _) => true);

            await ssl.AuthenticateAsClientAsync(host, null, checkCertificateRevocation: false);

            var remote = ssl.RemoteCertificate;

            if (remote is null) return new TlsProbe(host, TlsObservation.Reset, null);

            using var cert = new X509Certificate2(remote);

            return new TlsProbe(host, TlsObservation.Certificate, cert.Issuer);
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested)
        {
            // פסק זמן שלנו, לא כיבוי. נספר כניתוק.
            return new TlsProbe(host, TlsObservation.Reset, null);
        }
        catch (SocketException)
        {
            /*
             * לא הצלחנו להתחבר בכלל.
             *
             * שונה מניתוק לחיצת יד: שם החיבור נוצר ואז נקטע, וזה
             * סימן לסינון פעיל. כאן ייתכן שפשוט אין רשת, ואסור
             * להסיק מזה דבר.
             */
            return new TlsProbe(host, TlsObservation.Unreachable, null);
        }
        catch (Exception ex) when (ex is AuthenticationException or IOException)
        {
            // לחיצת היד נקטעה. הצורה השכיחה של חסימה לפי SNI.
            return new TlsProbe(host, TlsObservation.Reset, null);
        }
    }
}
