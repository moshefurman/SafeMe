using System.Runtime.Versioning;

using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

using SafeMe.Guardian;

/*
 * שירות השמירה של SafeMe.
 *
 * קטן במכוון. כל מה שהוא עושה הוא להשגיח על שירות אחד ולהחזיר אותו,
 * ולכן אין לו רשת, אין לו מסד, ואין לו מדיניות. משטח תקיפה קטן הוא
 * חלק מהתפקיד: שומר שמתרסק בעצמו אינו שומר.
 */

[SupportedOSPlatform("windows")]
internal static class Program
{
    private static async Task Main(string[] args)
    {
        var builder = Host.CreateApplicationBuilder(args);

        builder.Services.AddWindowsService(options =>
        {
            options.ServiceName = "SafeMeGuardian";
        });

        /*
         * יומן האירועים של Windows, באותו מקור כמו הסוכן.
         *
         * כך החייאה מופיעה באותה שורת זמן עם כל השאר, ומי שמאבחן
         * רואה סיפור אחד ולא שניים.
         */
        builder.Logging.AddEventLog(settings =>
        {
            settings.SourceName = "SafeMe";
            settings.LogName = "Application";
        });

        builder.Services.AddHostedService<GuardianWorker>();

        await builder.Build().RunAsync();
    }
}
