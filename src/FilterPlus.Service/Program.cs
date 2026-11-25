using System.Runtime.Versioning;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Hosting.WindowsServices;
using Microsoft.Extensions.Logging;
using FilterPlus.Core.Abstractions;
using FilterPlus.Core.Models;
using FilterPlus.Core.Security;
using FilterPlus.Service.Audit;
using FilterPlus.Service.Browser;
using FilterPlus.Service.DnsFilter;
using FilterPlus.Service.Ipc;
using FilterPlus.Service.Net;
using FilterPlus.Service.State;
using FilterPlus.Service.Watchdog;
using FilterPlus.Service.Wfp;
using FilterPlus.Service.Workers;
using FilterPlus.Service.Integrity;

namespace FilterPlus.Service;

[SupportedOSPlatform("windows")]
public static class Program
{
    /// <summary>שם השירות כפי שהוא נרשם ב-SCM. חייב להתאים לסקריפטי ההתקנה.</summary>
    public const string ServiceName = "FilterPlusAgent";

    public static async Task Main(string[] args)
    {
        // הכנת תיקיות והרשאות לפני כל דבר אחר, כי כל שאר הרכיבים תלויים בהן.
        // התיקיות מוגבלות ל-SYSTEM ולמנהלים, ולכן כישלון כאן משמעו שהתהליך
        // אינו רץ בהקשר הנכון. עדיף לצאת עם הודעה ברורה מאשר לרוץ חלקית.
        try
        {
            FilterPlusPaths.EnsureCreated();
        }
        catch (UnauthorizedAccessException ex)
        {
            await Console.Error.WriteLineAsync(
                $"אין הרשאה לתיקיית העבודה של FilterPlus: {ex.Message}\n" +
                "יש להריץ את השירות כ-SYSTEM, או להפעיל מחלון מורם לצורכי פיתוח.");

            Environment.ExitCode = 5;
            return;
        }

        var builder = Host.CreateApplicationBuilder(args);

        builder.Services.AddWindowsService(options => options.ServiceName = ServiceName);

        builder.Logging.AddEventLog(settings =>
        {
            settings.SourceName = "FilterPlus";
            settings.LogName = "Application";
        });

        builder.Services.Configure<ServerOptions>(builder.Configuration.GetSection("Server"));

        RegisterHttpClients(builder.Services);
        RegisterCoreServices(builder.Services);
        RegisterWorkers(builder.Services);

        var host = builder.Build();

        var log = host.Services.GetRequiredService<ILogger<IHost>>();
        log.LogInformation("סוכן FilterPlus עולה. גרסה {Version}.",
            typeof(Program).Assembly.GetName().Version?.ToString(3));

        // אתחול מנוע האכיפה מוקדם, כדי שכשל בו יתגלה מיד ולא בזמן נעילה
        var engine = host.Services.GetRequiredService<IEnforcementEngine>();

        if (!engine.Initialize())
        {
            var events = host.Services.GetRequiredService<EventQueue>();

            events.Enqueue(new TamperEvent
            {
                Kind = TamperKind.BfeUnavailable,
                Detail = "לא ניתן לאתחל את מנוע WFP. ייתכן ששירות BFE מושבת."
            });
        }

        /*
         * שרת השמות של הרשימה הלבנה עולה לפני העובדים.
         *
         * ההפניה שורדת אתחול. מחשב שעולה במצב רשימה לבנה מפנה כל
         * שאלת DNS אל הסוכן מהרגע הראשון, ועד שהשרת מאזין — שום שם
         * אינו נפתר, גם לא של שרת הניהול.
         */
        try
        {
            host.Services.GetRequiredService<EnforcementCoordinator>().SyncDnsGate();
        }
        catch (Exception ex)
        {
            log.LogError(ex, "הכנת שרת השמות של הרשימה הלבנה נכשלה.");
        }

        await host.RunAsync();
    }

    private static void RegisterHttpClients(IServiceCollection services)
    {
        // לקוח בדיקות: עוקב אחרי הפניות, לזיהוי דפי חסימה
        services.AddHttpClient("probe", client =>
        {
            client.Timeout = TimeSpan.FromSeconds(15);
            client.DefaultRequestHeaders.UserAgent.ParseAdd("FilterPlus-Agent/1.0");
        });

        // לקוח בדיקות ללא מעקב הפניות: ההפניה עצמה היא הראיה לחסימה
        services.AddHttpClient("probe-noredirect", client =>
            {
                client.Timeout = TimeSpan.FromSeconds(15);
                client.DefaultRequestHeaders.UserAgent.ParseAdd("FilterPlus-Agent/1.0");
            })
            .ConfigurePrimaryHttpMessageHandler(() => new HttpClientHandler
            {
                AllowAutoRedirect = false,
                // אימות התעודה מושבת בגששים בכוונה: החלפת תעודה על ידי הסינון
                // היא בדיוק מה שרוצים לזהות, ולא סיבה להיכשל.
                ServerCertificateCustomValidationCallback = (_, _, _, _) => true
            });

        // לקוח שרת הניהול: אימות תעודה מלא, ללא ויתורים
        services.AddHttpClient("server", client =>
        {
            client.Timeout = TimeSpan.FromSeconds(30);
            client.DefaultRequestHeaders.UserAgent.ParseAdd("FilterPlus-Agent/1.0");
        });
    }

    private static void RegisterCoreServices(IServiceCollection services)
    {
        services.AddSingleton<IAgentStateProvider, AgentState>();
        services.AddSingleton<IHardwareIdProvider, WindowsHardwareIdProvider>();
        services.AddSingleton<DeviceStateStore>();
        services.AddSingleton<PolicyStore>();
        services.AddSingleton<EventQueue>();
        services.AddSingleton<EventLogPowerReader>();
        services.AddSingleton<CoverageReconciler>();

        // מופע אחד, שני תפקידים: מי שמחיל תוכנית, ומי שפותח יעדים
        // תוך כדי ריצה. שני מופעים היו שני מנועי WFP שמוחקים זה לזה.
        services.AddSingleton<WfpEnforcementEngine>();
        services.AddSingleton<IEnforcementEngine>(sp => sp.GetRequiredService<WfpEnforcementEngine>());
        services.AddSingleton<IDynamicDestinations>(sp => sp.GetRequiredService<WfpEnforcementEngine>());

        services.AddSingleton<DnsRedirect>();
        services.AddSingleton<DnsGate>();
        services.AddSingleton<IManagementServerClient, ManagementServerClient>();

        services.AddSingleton<RootCaAuditor>();
        services.AddSingleton<NetworkIdentityAuditor>();
        services.AddSingleton<TlsIssuerAuditor>();
        services.AddSingleton<FilterLevelReader>();
        services.AddSingleton<TunnelLocator>();
        services.AddSingleton<HttpFilterAuditor>();
        services.AddSingleton<AuditEngine>();

        services.AddSingleton<EnforcementCoordinator>();

        /*
         * לקוח HTTP נפרד לעדכונים.
         *
         * ההורדה היא כ-60 מגה ממאגר ציבורי, ולא בקשת API קצרה לשרת
         * שלנו. שיתוף הלקוח היה גורם לפסק הזמן של הפעימות לחתוך
         * הורדה באמצע.
         */
        services.AddSingleton<UpdateWorker>(sp => new UpdateWorker(
            sp.GetRequiredService<ILogger<UpdateWorker>>(),
            sp.GetRequiredService<DeviceStateStore>(),
            sp.GetRequiredService<IHardwareIdProvider>(),
            new HttpClient { Timeout = TimeSpan.FromMinutes(20) }));
        services.AddSingleton<UninstallCoordinator>();

        // מאגר מצב ההסרה מדווח אירועי חבלה דרך התור המרכזי
        services.AddSingleton<IUninstallStateStore>(sp => new UninstallStateStore(
            sp.GetRequiredService<ILogger<UninstallStateStore>>(),
            sp.GetRequiredService<DeviceStateStore>(),
            tamperEvent => sp.GetRequiredService<EventQueue>().Enqueue(tamperEvent)));

        services.AddSingleton(sp => new UninstallAttemptGuard(sp.GetRequiredService<IUninstallStateStore>()));

        services.AddSingleton<BrowserPolicyEnforcer>();
        services.AddSingleton<HeartbeatSignal>();
        services.AddSingleton<IpcRequestHandler>();
    }

    private static void RegisterWorkers(IServiceCollection services)
    {
        // AuditWorker נרשם גם כ-singleton כדי שפקודת RunAudit מהשרת תוכל להפעילו ישירות
        services.AddSingleton<AuditWorker>();
        services.AddHostedService(sp => sp.GetRequiredService<AuditWorker>());

        services.AddHostedService<HeartbeatWorker>();
        services.AddHostedService<IntegrityWorker>();
        services.AddHostedService<TrayWatchdogWorker>();

        /*
         * שמירה הדדית: הסוכן מחזיר את השומר, והשומר מחזיר את הסוכן.
         *
         * שירות אינו יכול לשמור על עצמו — ברגע שנעצר, כל קוד שבתוכו
         * נעצר איתו. שני שירותים שכל אחד מחזיר את האחר הופכים את
         * ההשבתה למשימה עם חלון של פחות משתי שניות.
         */
        services.AddHostedService<GuardianWatchdogWorker>();
        services.AddHostedService<IpcServer>();
    }
}
