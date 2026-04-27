using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using RhinoSniff.Windows;

namespace RhinoSniff.Views
{
    /// <summary>
    /// Phase 6 — content-area Settings shell with sub-sidebar
    /// (Network / General / Hotkeys / Appearance / Performance).
    /// Replaces the legacy <c>Views/Settings.xaml</c> side-panel Page.
    /// </summary>
    public partial class SettingsHost : UserControl
    {
        private readonly MainWindow _host;

        // Lazy-init child sub-pages
        private SettingsNetwork _net;
        private SettingsGeneral _gen;
        private HotkeysSettings _keys;
        private SettingsAppearance _appear;
        private SettingsPerformance _perf;

        private enum SubPage { Network, General, Hotkeys, Appearance, Performance }

        public SettingsHost(MainWindow host)
        {
            InitializeComponent();
            _host = host;
            ShowSubPage(SubPage.Network);
        }

        private void ShowSubPage(SubPage target)
        {
            switch (target)
            {
                case SubPage.Network:
                    _net ??= new SettingsNetwork(_host);
                    SubContent.Content = _net;
                    break;
                case SubPage.General:
                    _gen ??= new SettingsGeneral(_host);
                    SubContent.Content = _gen;
                    break;
                case SubPage.Hotkeys:
                    _keys ??= new HotkeysSettings(_host);
                    SubContent.Content = _keys;
                    break;
                case SubPage.Appearance:
                    _appear ??= new SettingsAppearance(_host);
                    SubContent.Content = _appear;
                    break;
                case SubPage.Performance:
                    _perf ??= new SettingsPerformance(_host);
                    SubContent.Content = _perf;
                    break;
            }
            UpdateActive(target);
        }

        private void UpdateActive(SubPage target)
        {
            // Use SetResourceReference so theme swaps re-resolve Foreground.
            // Direct assignment of a resolved Brush kills the DynamicResource
            // binding and freezes the button at whatever color was resolved first.
            void SetFg(System.Windows.Controls.Control c, bool isActive) =>
                c?.SetResourceReference(System.Windows.Controls.Control.ForegroundProperty,
                    isActive ? "SidebarItemActive" : "SidebarItemInactive");

            SetFg(SubNavNetwork,     target == SubPage.Network);
            SetFg(SubNavGeneral,     target == SubPage.General);
            SetFg(SubNavHotkeys,     target == SubPage.Hotkeys);
            SetFg(SubNavAppearance,  target == SubPage.Appearance);
            SetFg(SubNavPerformance, target == SubPage.Performance);
        }

        private void SubNavNetwork_Click(object sender, RoutedEventArgs e)     => ShowSubPage(SubPage.Network);
        private void SubNavGeneral_Click(object sender, RoutedEventArgs e)     => ShowSubPage(SubPage.General);
        private void SubNavHotkeys_Click(object sender, RoutedEventArgs e)     => ShowSubPage(SubPage.Hotkeys);
        private void SubNavAppearance_Click(object sender, RoutedEventArgs e)  => ShowSubPage(SubPage.Appearance);
        private void SubNavPerformance_Click(object sender, RoutedEventArgs e) => ShowSubPage(SubPage.Performance);

        /// <summary>
        /// Called by MainWindow when a hotkey action maps to a specific sub-page
        /// (future extension; currently no-op).
        /// </summary>
        public void OpenHotkeys() => ShowSubPage(SubPage.Hotkeys);
    }
}
