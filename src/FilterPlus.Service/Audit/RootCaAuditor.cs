using System.Runtime.Versioning;
using System.Security.Cryptography.X509Certificates;
using System.Text.RegularExpressions;
using Microsoft.Extensions.Logging;
using FilterPlus.Core.Models;
using FilterPlus.Core.Policy;

namespace FilterPlus.Service.Audit;

/// <summary>
/// סורק את מאגר תעודות השורש של המכונה ומחפש תעודות של ספקי סינון ידועים.
///
/// זהו וקטור הזיהוי הראשון מתוך ארבעה. הוא חזק יחסית משום שספק סינון
/// שמבצע בדיקת TLS חייב שתעודת השורש שלו תותקן, אחרת כל גלישה מאובטחת תישבר.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class RootCaAuditor
{
    private readonly ILogger<RootCaAuditor> _log;

    public RootCaAuditor(ILogger<RootCaAuditor> log) => _log = log;

    /// <summary>מחזיר את מזהי הספקים שתעודת השורש שלהם מותקנת.</summary>
    public IReadOnlyDictionary<string, List<string>> DetectProviders(PolicyBundle policy)
    {
        var matches = new Dictionary<string, List<string>>(StringComparer.OrdinalIgnoreCase);
        var certificates = EnumerateRootCertificates();

        foreach (var provider in policy.Providers)
        {
            if (provider.RootCa is null) continue;

            var found = new List<string>();

            foreach (var cert in certificates)
            {
                if (MatchesThumbprint(cert, provider.RootCa) || MatchesSubject(cert, provider.RootCa))
                    found.Add(cert.Thumbprint);
            }

            if (found.Count > 0)
            {
                matches[provider.Id] = found;

                _log.LogInformation(
                    "זוהתה תעודת שורש של {Provider} ({Count} תעודות).", provider.Id, found.Count);
            }
        }

        foreach (var cert in certificates) cert.Dispose();

        return matches;
    }

    /// <summary>מייצר תוצאת גשש עבור נוכחות או היעדר תעודת השורש הנדרשת.</summary>
    public ProbeResult BuildProbeResult(ProviderRule? expected, IReadOnlyDictionary<string, List<string>> matches)
    {
        const string kind = "RootCa";

        if (expected?.RootCa is null || expected.RootCa.Thumbprints.Count + expected.RootCa.SubjectPatterns.Count == 0)
            return ProbeResult.Inconclusive("rootca", kind, "לא הוגדרה תעודת שורש לבדיקה.");

        if (matches.ContainsKey(expected.Id))
        {
            var result = ProbeResult.Pass("rootca", kind, 20,
                $"תעודת השורש של {expected.DisplayName} מותקנת.");

            result.Title = "תעודת סינון";
            result.Evidence["thumbprints"] = string.Join(",", matches[expected.Id]);

            return result;
        }

        var severity = expected.RootCa.Required ? ProbeSeverity.Critical : ProbeSeverity.Warning;

        var fail = ProbeResult.Fail("rootca", kind, 20, severity,
            $"תעודת השורש של {expected.DisplayName} אינה מותקנת.");

        fail.Title = "תעודת סינון";

        return fail;
    }

    /// <summary>
    /// מחזיר את כל תעודות השורש של המכונה. חשוב לקרוא את מאגר המכונה
    /// ולא את זה של המשתמש, כי הסינון מותקן ברמת המכונה.
    /// </summary>
    private List<X509Certificate2> EnumerateRootCertificates()
    {
        var results = new List<X509Certificate2>();

        foreach (var storeName in new[] { StoreName.Root, StoreName.CertificateAuthority })
        {
            try
            {
                using var store = new X509Store(storeName, StoreLocation.LocalMachine);
                store.Open(OpenFlags.ReadOnly | OpenFlags.OpenExistingOnly);

                foreach (var cert in store.Certificates)
                    results.Add(cert);
            }
            catch (Exception ex)
            {
                _log.LogWarning(ex, "קריאת מאגר התעודות {Store} נכשלה.", storeName);
            }
        }

        return results;
    }

    private static bool MatchesThumbprint(X509Certificate2 cert, RootCaRule rule)
    {
        if (rule.Thumbprints.Count == 0) return false;

        var sha1 = cert.Thumbprint?.Replace(" ", "").ToUpperInvariant() ?? "";
        var sha256 = Convert.ToHexString(cert.GetCertHash(System.Security.Cryptography.HashAlgorithmName.SHA256));

        return rule.Thumbprints.Any(t =>
        {
            var normalized = t.Replace(" ", "").Replace(":", "").ToUpperInvariant();
            return normalized == sha1 || normalized == sha256;
        });
    }

    private static bool MatchesSubject(X509Certificate2 cert, RootCaRule rule) =>
        rule.SubjectPatterns.Any(pattern =>
            Wildcard.IsMatch(cert.Subject, pattern) || Wildcard.IsMatch(cert.Issuer, pattern));
}

/// <summary>התאמת תבניות עם כוכבית, כפי שמוגדרות במדיניות מהשרת.</summary>
public static partial class Wildcard
{
    public static bool IsMatch(string? input, string pattern)
    {
        if (string.IsNullOrEmpty(input) || string.IsNullOrEmpty(pattern)) return false;
        if (pattern == "*") return true;

        var regex = "^" + Regex.Escape(pattern).Replace("\\*", ".*").Replace("\\?", ".") + "$";

        return Regex.IsMatch(input, regex, RegexOptions.IgnoreCase | RegexOptions.CultureInvariant,
            TimeSpan.FromMilliseconds(250));
    }
}
