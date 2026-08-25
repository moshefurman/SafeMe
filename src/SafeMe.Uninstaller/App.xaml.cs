using System.Windows;
using System.Windows.Markup;

namespace SafeMe.Uninstaller;

public partial class App : Application
{
    protected override void OnStartup(StartupEventArgs e)
    {
        FrameworkElement.LanguageProperty.OverrideMetadata(
            typeof(FrameworkElement),
            new FrameworkPropertyMetadata(XmlLanguage.GetLanguage("he-IL")));

        base.OnStartup(e);
    }
}
