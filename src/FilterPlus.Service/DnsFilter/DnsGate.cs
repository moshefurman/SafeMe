using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Runtime.Versioning;
using Microsoft.Extensions.Logging;
using FilterPlus.Core.Abstractions;
using FilterPlus.Core.DnsFilter;
using FilterPlus.Core.Policy;

namespace FilterPlus.Service.DnsFilter;

/// <summary>
/// שרת השמות המקומי של הרשימה הלבנה.
///
/// כל שאלת DNS במחשב מגיעה לכאן (ראה DnsRedirect), וכאן מוכרע מה
/// נפתר. שם מותר מועבר לשרת שמות אמיתי, והכתובות שחזרו נפתחות
/// ב-WFP **לפני** שהתשובה נשלחת ללקוח. שם שאינו מותר נענה "אין שם
/// כזה", ושום דבר לא נפתח.
///
/// הסדר הזה הוא כל המנגנון: הדפדפן אינו יכול להתחבר לכתובת שלא
/// קיבל, ואינו יכול לקבל כתובת שלא נפתחה.
///
/// שלושה סוגי שמות:
///   מותר       — ברשימה, או שחלון הלמידה פתוח. נפתר ונפתח.
///   של הסוכן   — מארחים שהסוכן עצמו צריך לבדיקות שלו. נפתר, ולא
///                נפתח: לסוכן יש היתר משלו, ולאף אחד אחר אין סיבה
///                להגיע לשם.
///   כל השאר    — "אין שם כזה".
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class DnsGate : IDisposable
{
    /// <summary>
    /// כתובת לולאה ייעודית, ולא 127.0.0.1.
    ///
    /// על 127.0.0.1:53 כבר יושבות תוכנות אחרות במחשבים אמיתיים. כתובת
    /// משלנו אינה מתנגשת עם אף אחת מהן — נמדד על מחשב שבו שיתוף
    /// האינטרנט של Windows מחזיק את 0.0.0.0:53, והכתובת הזו נקשרה
    /// וקיבלה חבילות בלי הפרעה.
    /// </summary>
    public static readonly IPAddress ListenAddress = IPAddress.Parse("127.0.0.53");

    /// <summary>שם שרק השרת הזה עונה עליו. משמש לבדוק שההפניה באמת עובדת.</summary>
    public const string CanaryName = "gate-check.filterplus.invalid";

    /// <summary>זמן החיים המרבי שלקוח מקבל. ראה DnsWire.TryReadAddresses.</summary>
    private const uint MaxTtlSeconds = 300;

    private const int MaxObserved = 3000;

    private readonly ILogger<DnsGate> _log;
    private readonly IDynamicDestinations _destinations;
    private readonly DnsRedirect _redirect;
    private readonly object _sync = new();

    private sealed record Config(
        WhitelistRule Rule,
        DomainMatcher Allowed,
        DomainMatcher Quiet,
        DomainMatcher AgentOnly,
        IReadOnlyList<IPAddress> Upstreams,
        bool SystemFallback,
        string Fingerprint);

    private volatile Config? _config;
    private CancellationTokenSource? _cts;
    private Socket? _udp;
    private TcpListener? _tcp;
    private Timer? _timer;
    private bool _wasLearning;
    private bool _redirectVerified;
    private bool _verifying;
    private DateTime _verifyFailedAt = DateTime.MinValue;

    private readonly ConcurrentDictionary<string, int> _observed = new(StringComparer.Ordinal);

    private (DateTime At, List<IPAddress> Servers) _systemResolvers = (DateTime.MinValue, []);

    /// <summary>חלון הלמידה נגמר. מי שמחזיק את תוכנית האכיפה צריך לבנות אותה מחדש.</summary>
    public event Action? LearningEnded;

    public DnsGate(ILogger<DnsGate> log, IDynamicDestinations destinations, DnsRedirect redirect)
    {
        _log = log;
        _destinations = destinations;
        _redirect = redirect;
    }

    public bool Running => _config is not null;

    public bool Learning => _config?.Rule.IsLearning(DateTimeOffset.UtcNow) == true;

    public int AllowedCount => _config?.Rule.Domains.Count ?? 0;

    /// <summary>
    /// מביא את השרת למצב שהמדיניות דורשת: רץ עם הרשימה הנוכחית, או כבוי.
    ///
    /// נקרא בכל הערכה מחדש של האכיפה, ולכן רוב הקריאות אינן משנות דבר.
    /// </summary>
    public void Configure(
        WhitelistRule? rule, IEnumerable<string> agentHosts, bool providerTrusted)
    {
        lock (_sync)
        {
            var now = DateTimeOffset.UtcNow;

            if (rule is null || !rule.IsActive(now))
            {
                StopLocked();
                return;
            }

            var learning = rule.IsLearning(now);

            var fingerprint = string.Join(',',
                rule.Domains.Concat(rule.SystemDomains).Order(StringComparer.Ordinal))
                + (learning ? "|learning" : "");

            var upstreams = rule.UpstreamResolvers
                .Select(x => IPAddress.TryParse(x, out var ip) ? ip : null)
                .Where(x => x is not null)
                .Cast<IPAddress>()
                .ToList();

            var previous = _config;

            _config = new Config(
                rule,
                new DomainMatcher(rule.Domains.Concat(rule.SystemDomains)),
                new DomainMatcher(rule.SystemDomains),
                new DomainMatcher(agentHosts),
                upstreams,
                providerTrusted,
                fingerprint);

            /*
             * רשימה שהשתנתה סוגרת את כל מה שנפתח.
             *
             * דומיין שהוסר צריך להיסגר עכשיו ולא בעוד שעתיים, ואין
             * דרך לדעת אילו כתובות היו שלו — כתובת אחת משרתת כמה
             * שמות. סגירת הכול וריקון המטמון מאלצים כל שם להישאל
             * מחדש, ורק מה שעדיין מותר נפתח שוב.
             */
            if (previous is not null && previous.Fingerprint != fingerprint)
            {
                _destinations.ForgetAll();
                _redirect.FlushCache();
            }

            _wasLearning = learning;

            if (_cts is null && !StartLocked()) return;

            EnsureRedirectLocked();
        }
    }

    /// <summary>
    /// בודק שההפניה עדיין במקומה, ומחזיר אותה אם לא. true פירושו שתוקן.
    /// </summary>
    public bool VerifyAndRestore()
    {
        lock (_sync)
        {
            if (_config is null || _cts is null) return false;
            if (_redirect.IsInstalled(ListenAddress.ToString())) return false;

            _log.LogWarning("הפניית ה-DNS אל FilterPlus נמחקה מחוץ לסוכן. מוחזרת.");
            _redirect.Install(ListenAddress.ToString());

            return true;
        }
    }

    public void Stop()
    {
        lock (_sync) StopLocked();
    }

    /// <summary>מה שנצפה בלמידה מאז הפעם הקודמת.</summary>
    public List<KeyValuePair<string, int>> DrainObserved()
    {
        var drained = new List<KeyValuePair<string, int>>();

        foreach (var name in _observed.Keys.ToList())
        {
            if (_observed.TryRemove(name, out var count))
                drained.Add(new(name, count));
        }

        return drained;
    }

    /// <summary>מחזיר מה שלא הצליח להישלח, כדי שלא ילך לאיבוד בניתוק.</summary>
    public void RestoreObserved(IEnumerable<KeyValuePair<string, int>> items)
    {
        foreach (var (name, count) in items)
            _observed.AddOrUpdate(name, count, (_, existing) => existing + count);
    }

    // ------------------------------------------------------------ מחזור חיים

    private bool StartLocked()
    {
        try
        {
            var udp = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);

            /*
             * בלי זה, שגיאת ICMP על שליחה אחת מפילה את הקבלה הבאה.
             *
             * ב-Windows, לקוח שסגר את השקע לפני שהתשובה הגיעה גורם
             * ל-ReceiveFrom הבא לזרוק "החיבור אופס". בשרת זה אומר
             * שלקוח אחד קצר רוח עוצר את כולם.
             */
            const int SioUdpConnReset = -1744830452;
            udp.IOControl(SioUdpConnReset, [0], null);
            udp.Bind(new IPEndPoint(ListenAddress, 53));

            var tcp = new TcpListener(ListenAddress, 53);
            tcp.Start();

            _udp = udp;
            _tcp = tcp;
            _cts = new CancellationTokenSource();

            var token = _cts.Token;

            _ = Task.Run(() => UdpLoopAsync(udp, token));
            _ = Task.Run(() => TcpLoopAsync(tcp, token));

            _timer = new Timer(_ => Tick(), null, TimeSpan.FromSeconds(15), TimeSpan.FromSeconds(15));

            _log.LogWarning("שרת השמות של הרשימה הלבנה עלה על {Address}:53.", ListenAddress);

            return true;
        }
        catch (Exception ex)
        {
            /*
             * בלי שרת אין הפניה.
             *
             * הפניה אל כתובת שאיש אינו מאזין עליה היא מחשב בלי DNS
             * ובלי הסבר. בלי ההפניה, השאלות יוצאות החוצה ונחסמות
             * ב-WFP — אותה תוצאה למשתמש, אבל הסיבה כתובה כאן ביומן.
             */
            _log.LogError(ex, "שרת השמות של הרשימה הלבנה לא עלה. שום אתר לא ייפתח.");

            _udp?.Dispose();
            _udp = null;
            _tcp = null;
            _cts = null;

            return false;
        }
    }

    private void StopLocked()
    {
        var wasRunning = _config is not null || _cts is not null;

        _config = null;

        // ההפניה יורדת ראשונה: מרגע שהשרת נסגר, כל שאלה שעוד מופנית
        // אליו נופלת.
        _redirect.Remove();
        _redirectVerified = false;

        _timer?.Dispose();
        _timer = null;

        _cts?.Cancel();
        _cts?.Dispose();
        _cts = null;

        try { _udp?.Dispose(); } catch { /* כבר סגור */ }
        try { _tcp?.Stop(); } catch { /* כבר סגור */ }

        _udp = null;
        _tcp = null;
        _wasLearning = false;

        if (!wasRunning) return;

        _destinations.ForgetAll();
        _redirect.FlushCache();
        _log.LogWarning("שרת השמות של הרשימה הלבנה נעצר.");
    }

    private void EnsureRedirectLocked()
    {
        var server = ListenAddress.ToString();

        if (!_redirect.IsInstalled(server))
        {
            try
            {
                _redirect.Install(server);
            }
            catch (Exception ex)
            {
                _log.LogError(ex, "הגדרת הפניית ה-DNS נכשלה.");
                return;
            }
        }

        /*
         * בדיקה אחת בכל פעם, ואחרי כישלון — הפסקה.
         *
         * הפונקציה הזו נקראת בכל הערכה מחדש של האכיפה. בלי הבלם,
         * מחשב שההפניה אינה עובדת בו היה מריץ PowerShell כל כמה
         * דקות לנצח, וממלא את היומן באותה שורה.
         */
        if (_redirectVerified || _verifying) return;
        if (DateTime.UtcNow - _verifyFailedAt < TimeSpan.FromMinutes(10)) return;

        _verifying = true;

        // מחוץ למנעול: הבדיקה שואלת את המערכת, והשאלה חוזרת לכאן.
        _ = Task.Run(async () =>
        {
            try
            {
                await VerifyRedirectAsync();
            }
            catch (Exception ex)
            {
                _log.LogDebug(ex, "בדיקת הפניית ה-DNS נכשלה.");
            }
            finally
            {
                if (!_redirectVerified) _verifyFailedAt = DateTime.UtcNow;

                _verifying = false;
            }
        });
    }

    /// <summary>
    /// מרוקן את מטמון ה-DNS של המערכת.
    ///
    /// נדרש כשהתוכנית עוברת לרשימה לבנה: שם שנפתר לפני כן יושב במטמון
    /// עם כתובת שמעולם לא נפתחה ב-WFP, והאתר נראה שבור עד שהרשומה
    /// פגה. ריקון מאלץ אותו להישאל מחדש — ואז הכתובת נפתחת.
    /// </summary>
    public void FlushClientCache() => _redirect.FlushCache();

    /// <summary>
    /// בודק שההפניה באמת עובדת, ולא רק שהיא כתובה.
    ///
    /// שואלים את המערכת על שם שרק השרת הזה מכיר. אם התשובה שלנו חזרה,
    /// כל המסלול עובד: הכלל נקרא, השאלה הגיעה, והתשובה התקבלה. זה
    /// נמדד בכל מחשב ובכל הפעלה, ונכתב ליומן — כדי שהשאלה "האם זה
    /// בכלל פועל" תיענה ממדידה ולא מהשערה.
    /// </summary>
    private async Task VerifyRedirectAsync()
    {
        if (await CanaryAnswersAsync(attempts: 6))
        {
            _redirectVerified = true;
            _log.LogWarning("הפניית ה-DNS אל FilterPlus נבדקה ועובדת.");
            return;
        }

        _log.LogWarning("הפניית ה-DNS נכתבה אך אינה נענית. מנסה דרך PowerShell.");

        if (_redirect.InstallViaCmdlet(ListenAddress.ToString()) && await CanaryAnswersAsync(attempts: 6))
        {
            _redirectVerified = true;
            _log.LogWarning("הפניית ה-DNS אל FilterPlus עובדת, דרך PowerShell.");
            return;
        }

        _log.LogError(
            "הפניית ה-DNS אל FilterPlus אינה עובדת. במצב רשימה לבנה שום אתר לא ייפתח עד שתתוקן.");
    }

    private async Task<bool> CanaryAnswersAsync(int attempts)
    {
        for (var i = 0; i < attempts; i++)
        {
            try
            {
                var addresses = await System.Net.Dns.GetHostAddressesAsync(CanaryName);

                if (addresses.Any(a => a.Equals(ListenAddress))) return true;
            }
            catch (SocketException)
            {
                // עוד לא. תשובה שלילית נשמרת במטמון, ולכן מרוקנים לפני הניסיון הבא.
            }

            _redirect.FlushCache();
            await Task.Delay(700);
        }

        return false;
    }

    private void Tick()
    {
        try
        {
            bool ended;

            lock (_sync)
            {
                var config = _config;

                if (config is null) return;

                var learning = config.Rule.IsLearning(DateTimeOffset.UtcNow);

                ended = _wasLearning && !learning;
                _wasLearning = learning;
            }

            if (!ended) return;

            _log.LogWarning("חלון הלמידה של הרשימה הלבנה נגמר.");

            // מה שנפתח בלמידה נסגר עכשיו, לא כשיפוג מעצמו.
            _destinations.ForgetAll();
            _redirect.FlushCache();

            LearningEnded?.Invoke();
        }
        catch (Exception ex)
        {
            _log.LogDebug(ex, "בדיקת סוף הלמידה נכשלה.");
        }
    }

    // ------------------------------------------------------------ קבלה

    private async Task UdpLoopAsync(Socket socket, CancellationToken ct)
    {
        var buffer = new byte[4096];

        while (!ct.IsCancellationRequested)
        {
            try
            {
                var received = await socket.ReceiveFromAsync(
                    buffer, SocketFlags.None, new IPEndPoint(IPAddress.Any, 0), ct);

                var query = buffer.AsSpan(0, received.ReceivedBytes).ToArray();
                var client = received.RemoteEndPoint;

                _ = Task.Run(async () =>
                {
                    try
                    {
                        var response = await HandleAsync(query, viaTcp: false, ct);

                        if (response is not null)
                            await socket.SendToAsync(response, SocketFlags.None, client, ct);
                    }
                    catch (Exception ex) when (ex is not OperationCanceledException)
                    {
                        _log.LogDebug(ex, "טיפול בשאלת DNS נכשל.");
                    }
                }, ct);
            }
            catch (OperationCanceledException)
            {
                return;
            }
            catch (ObjectDisposedException)
            {
                return;
            }
            catch (SocketException ex)
            {
                _log.LogDebug(ex, "שגיאת קבלה בשרת השמות.");
            }
        }
    }

    private async Task TcpLoopAsync(TcpListener listener, CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            try
            {
                var client = await listener.AcceptTcpClientAsync(ct);

                _ = Task.Run(async () =>
                {
                    using (client)
                    {
                        try
                        {
                            client.ReceiveTimeout = 5000;

                            var stream = client.GetStream();
                            var query = await ReadFramedAsync(stream, ct);

                            if (query is null) return;

                            var response = await HandleAsync(query, viaTcp: true, ct);

                            if (response is not null)
                                await WriteFramedAsync(stream, response, ct);
                        }
                        catch (Exception ex) when (ex is not OperationCanceledException)
                        {
                            _log.LogDebug(ex, "טיפול בשאלת DNS ב-TCP נכשל.");
                        }
                    }
                }, ct);
            }
            catch (OperationCanceledException)
            {
                return;
            }
            catch (ObjectDisposedException)
            {
                return;
            }
            catch (SocketException ex)
            {
                _log.LogDebug(ex, "שגיאת קבלה בשרת השמות (TCP).");
            }
        }
    }

    // ------------------------------------------------------------ הכרעה

    private async Task<byte[]?> HandleAsync(byte[] query, bool viaTcp, CancellationToken ct)
    {
        if (!DnsWire.TryReadQuestion(query, out var name, out var type, out var questionEnd))
            return null;

        var config = _config;

        if (config is null)
            return DnsWire.BuildEmpty(query, questionEnd, DnsWire.RcodeServerFailure);

        if (name == CanaryName)
        {
            return type == DnsWire.TypeA
                ? DnsWire.BuildAddress(query, questionEnd, ListenAddress, ttl: 1)
                : DnsWire.BuildEmpty(query, questionEnd, DnsWire.RcodeOk);
        }

        var listed = config.Allowed.Matches(name);
        var learning = config.Rule.IsLearning(DateTimeOffset.UtcNow);

        if (listed || learning)
        {
            /*
             * רשומות HTTPS ו-SVCB נענות ריק.
             *
             * הן נושאות רמזי כתובת משלהן, והדפדפן רשאי להתחבר לפיהם
             * בלי לשאול על A. כתובת שהגיעה כך לא עברה דרך הפתיחה
             * ב-WFP, והחיבור היה נכשל. תשובה ריקה מחזירה את הדפדפן
             * לשאלה הרגילה.
             */
            if (type is DnsWire.TypeHttps or DnsWire.TypeSvcb)
                return DnsWire.BuildEmpty(query, questionEnd, DnsWire.RcodeOk);

            var servers = config.SystemFallback
                ? config.Upstreams.Concat(SystemResolvers()).ToList()
                : config.Upstreams;

            var response = await ForwardAsync(query, servers, viaTcp, ct);

            if (response is null)
                return DnsWire.BuildEmpty(query, questionEnd, DnsWire.RcodeServerFailure);

            var addresses = new List<IPAddress>();

            if (!DnsWire.TryReadAddresses(response, MaxTtlSeconds, addresses))
                return DnsWire.BuildEmpty(query, questionEnd, DnsWire.RcodeServerFailure);

            var routable = addresses.Where(DnsWire.IsRoutable).ToList();

            if (routable.Count > 0)
            {
                // קודם פותחים, ורק אז עונים.
                _destinations.Permit(routable);

                if (learning && !config.Quiet.Matches(name) && !config.AgentOnly.Matches(name))
                    Observe(name);
            }

            return response;
        }

        if (config.AgentOnly.Matches(name))
        {
            // לבדיקות של הסוכן עצמו. נפתר דרך שרתי הרשת, כי זה מה
            // שהבדיקות באות למדוד — ושום כתובת אינה נפתחת.
            var servers = SystemResolvers().Concat(config.Upstreams).ToList();
            var response = await ForwardAsync(query, servers, viaTcp, ct);

            return response ?? DnsWire.BuildEmpty(query, questionEnd, DnsWire.RcodeServerFailure);
        }

        return DnsWire.BuildEmpty(query, questionEnd, DnsWire.RcodeNameError);
    }

    private void Observe(string name)
    {
        if (_observed.Count >= MaxObserved && !_observed.ContainsKey(name)) return;

        _observed.AddOrUpdate(name, 1, (_, count) => count + 1);
    }

    // ------------------------------------------------------------ העברה

    private async Task<byte[]?> ForwardAsync(
        byte[] query, IReadOnlyList<IPAddress> servers, bool viaTcp, CancellationToken ct)
    {
        foreach (var server in servers)
        {
            try
            {
                if (!viaTcp)
                {
                    var response = await ForwardUdpAsync(query, server, ct);

                    if (response is null) continue;

                    // תשובה קטועה ב-UDP: הלקוח יחזור ב-TCP ויקבל את המלאה.
                    return response;
                }

                var full = await ForwardTcpAsync(query, server, ct);

                if (full is not null) return full;
            }
            catch (Exception ex) when (ex is SocketException or IOException or OperationCanceledException)
            {
                if (ct.IsCancellationRequested) throw;

                _log.LogDebug(ex, "שרת השמות {Server} לא ענה.", server);
            }
        }

        return null;
    }

    private static async Task<byte[]?> ForwardUdpAsync(byte[] query, IPAddress server, CancellationToken ct)
    {
        using var socket = new Socket(server.AddressFamily, SocketType.Dgram, ProtocolType.Udp);
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);

        timeout.CancelAfter(TimeSpan.FromSeconds(2));

        // שקע מחובר מקבל רק מהשרת שנשאל. תשובה מכתובת אחרת אינה תשובה.
        await socket.ConnectAsync(new IPEndPoint(server, 53), timeout.Token);
        await socket.SendAsync(query, SocketFlags.None, timeout.Token);

        var buffer = new byte[4096];
        var length = await socket.ReceiveAsync(buffer, SocketFlags.None, timeout.Token);

        if (length < 12) return null;

        // מזהה השאלה חייב לחזור כפי שנשלח
        if (buffer[0] != query[0] || buffer[1] != query[1]) return null;

        return buffer.AsSpan(0, length).ToArray();
    }

    private static async Task<byte[]?> ForwardTcpAsync(byte[] query, IPAddress server, CancellationToken ct)
    {
        using var client = new TcpClient(server.AddressFamily);
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);

        timeout.CancelAfter(TimeSpan.FromSeconds(4));

        await client.ConnectAsync(new IPEndPoint(server, 53), timeout.Token);

        var stream = client.GetStream();

        await WriteFramedAsync(stream, query, timeout.Token);

        return await ReadFramedAsync(stream, timeout.Token);
    }

    private static async Task<byte[]?> ReadFramedAsync(NetworkStream stream, CancellationToken ct)
    {
        var prefix = new byte[2];

        await stream.ReadExactlyAsync(prefix, ct);

        var length = BinaryPrimitives.ReadUInt16BigEndian(prefix);

        if (length < 12) return null;

        var message = new byte[length];

        await stream.ReadExactlyAsync(message, ct);

        return message;
    }

    private static async Task WriteFramedAsync(NetworkStream stream, byte[] message, CancellationToken ct)
    {
        var framed = new byte[message.Length + 2];

        BinaryPrimitives.WriteUInt16BigEndian(framed, (ushort)message.Length);
        message.CopyTo(framed, 2);

        await stream.WriteAsync(framed, ct);
    }

    /// <summary>
    /// שרתי השמות שהרשת עצמה נתנה למחשב.
    ///
    /// נקראים מהמתאמים ולא מהמערכת: ההפניה אינה משנה אותם, ולכן הם
    /// עדיין מה שה-DHCP חילק. נשמרים לחצי דקה, כי קריאת המתאמים אינה
    /// זולה והיא קורית בכל שאלה.
    /// </summary>
    private List<IPAddress> SystemResolvers()
    {
        var cached = _systemResolvers;

        if (DateTime.UtcNow - cached.At < TimeSpan.FromSeconds(30)) return cached.Servers;

        var servers = new List<IPAddress>();

        try
        {
            foreach (var nic in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (nic.OperationalStatus != OperationalStatus.Up) continue;
                if (nic.NetworkInterfaceType == NetworkInterfaceType.Loopback) continue;

                foreach (var address in nic.GetIPProperties().DnsAddresses)
                {
                    if (IPAddress.IsLoopback(address)) continue;
                    if (address.IsIPv6SiteLocal) continue;
                    if (!servers.Contains(address)) servers.Add(address);
                }
            }
        }
        catch (NetworkInformationException ex)
        {
            _log.LogDebug(ex, "קריאת שרתי השמות של המתאמים נכשלה.");
        }

        _systemResolvers = (DateTime.UtcNow, servers);

        return servers;
    }

    public void Dispose()
    {
        /*
         * עצירת השירות אינה מסירה את ההפניה, ובכוונה.
         *
         * שירות שנעצר אינו שירות שהוסר. אם ההפניה הייתה יורדת כאן,
         * עצירת השירות הייתה מחזירה את ה-DNS הרגיל — ובלי ה-WFP
         * הדינמי שנמחק יחד עם התהליך, זה אינטרנט פתוח. כשהיא נשארת,
         * מחשב שהסוכן שלו נעצר הוא מחשב בלי DNS עד שהסוכן חוזר.
         *
         * ההסרה נעשית רק במסלולים שמכבים את המצב במפורש: מדיניות
         * שכיבתה אותו, או הסרה מאושרת.
         */
        lock (_sync)
        {
            _timer?.Dispose();
            _cts?.Cancel();

            try { _udp?.Dispose(); } catch { /* כבר סגור */ }
            try { _tcp?.Stop(); } catch { /* כבר סגור */ }
        }
    }
}

/// <summary>
/// המארחים שהסוכן עצמו פונה אליהם.
///
/// במצב רשימה לבנה גם השאלות של הסוכן עוברות דרך שרת השמות שלו, כי
/// ההפניה חלה על כל המחשב. בלי הרשימה הזו הסוכן היה חוסם את עצמו:
/// לא מגיע לשרת, ולא מצליח לבדוק דרך איזה ספק המחשב יוצא.
/// </summary>
public static class AgentHosts
{
    /// <summary>שירותי הכתובת הציבורית, ומקורות העדכון.</summary>
    private static readonly string[] BuiltIn =
    [
        "api.ipify.org", "checkip.amazonaws.com", "ifconfig.me", "ipinfo.io",
        "github.com", "objects.githubusercontent.com", "release-assets.githubusercontent.com"
    ];

    public static List<string> Collect(PolicyBundle policy, IEnumerable<string> serverHosts)
    {
        var hosts = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var host in BuiltIn) hosts.Add(host);
        foreach (var host in serverHosts) Add(hosts, host);
        foreach (var host in policy.Enforcement.AlwaysAllow.Hosts) Add(hosts, host);

        foreach (var provider in policy.Providers)
        {
            foreach (var probe in provider.TlsIssuer?.Probes ?? []) Add(hosts, probe);

            if (provider.HttpMarkers is not { } markers) continue;

            Add(hosts, markers.Url);

            foreach (var host in markers.LevelHosts) Add(hosts, host);
            foreach (var probe in markers.Probes) Add(hosts, probe.Url);
        }

        foreach (var probe in policy.ContentProbes) Add(hosts, probe.Url);
        foreach (var probe in policy.AiProbes) Add(hosts, probe.Host);
        foreach (var probe in policy.ImageProbes) Add(hosts, probe.Url);

        return hosts.ToList();
    }

    /// <summary>מקבל מארח או כתובת מלאה, ושומר את המארח בלבד.</summary>
    private static void Add(HashSet<string> hosts, string? value)
    {
        if (string.IsNullOrWhiteSpace(value)) return;

        var host = Uri.TryCreate(value, UriKind.Absolute, out var uri) && uri.Host.Length > 0
            ? uri.Host
            : value.Split('/')[0].Split(':')[0];

        if (DomainMatcher.Normalize(host) is { } normalized)
            hosts.Add(normalized);
    }
}
