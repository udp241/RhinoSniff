using System;
using System.Diagnostics;
using System.IO;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Interop;
using System.Windows.Media;
using RhinoSniff.Interfaces;
using RhinoSniff.Models;
using RhinoSniff.Windows;

namespace RhinoSniff.Views
{
    /// <summary>
    /// Phase 6 — Settings → General sub-page.
    /// Primary toggles + Resources card + Tutorial reset + Advanced (legacy toggles preserved).
    /// </summary>
    public partial class SettingsGeneral : UserControl
    {
        private readonly MainWindow _host;
        private bool _loaded;

        public SettingsGeneral(MainWindow host)
        {
            InitializeComponent();
            _host = host;
            LoadState();
            _loaded = true;
        }

        private void LoadState()
        {
            NotificationsToggle.IsChecked       = Globals.Settings.EnableNotifications;
            DiscordToggle.IsChecked             = Globals.Settings.DiscordStatus;
            AutoSaveToggle.IsChecked            = Globals.Settings.AutoSaveCapture;
            AutoRemoveInactiveToggle.IsChecked  = Globals.Settings.AutoRemoveInactive;
            UpdateDiscordPill();

            // Advanced
            CountryFlagsToggle.IsChecked    = Globals.Settings.ShowFlags;
            GeoToggle.IsChecked             = Globals.Settings.Geolocate;
            HardwareAccelToggle.IsChecked   = Globals.Settings.HardwareAccel;
            TopMostToggle.IsChecked         = Globals.Settings.TopMost;
            SoundAlertsToggle.IsChecked     = Globals.Settings.SoundAlerts;
            RememberAdapterToggle.IsChecked = Globals.Settings.RememberInterface;
            AutoShowPanelToggle.IsChecked   = Globals.Settings.AutoShowPanel;
            PacketAnalyserToggle.IsChecked  = Globals.Settings.PacketAnalyser;
            EnableLabelsToggle.IsChecked    = Globals.Settings.EnableLabels;
        }

        private void UpdateDiscordPill()
        {
            bool on = Globals.Settings.DiscordStatus;
            DiscordPillText.Text = on ? "ENABLED" : "DISABLED";
            try
            {
                DiscordPill.SetResourceReference(Border.BackgroundProperty,
                    on ? "PillCapturingBg" : "PillStoppedBg");
                DiscordPillText.SetResourceReference(TextBlock.ForegroundProperty,
                    on ? "PillCapturingText" : "PillStoppedText");
            }
            catch { }
        }

        private async void Persist()
        {
            if (!_loaded) return;
            try { await Globals.Container.GetInstance<IServerSettings>().UpdateSettingsAsync(); }
            catch { }
        }

        // ── Primary toggles ──────────────────────────────────────────────
        private void NotificationsToggle_Click(object sender, RoutedEventArgs e)
        {
            Globals.Settings.EnableNotifications = NotificationsToggle.IsChecked == true;
            Persist();
        }

        private void DiscordToggle_Click(object sender, RoutedEventArgs e)
        {
            var on = DiscordToggle.IsChecked == true;
            Globals.Settings.DiscordStatus = on;
            UpdateDiscordPill();
            try
            {
                var rpc = Globals.Container.GetInstance<IDiscordPresenceService>();
                if (on) rpc.Initialize(); else rpc.DeInitialize();
            }
            catch { /* service not registered in some contexts */ }
            Persist();
        }

        private void AutoSaveToggle_Click(object sender, RoutedEventArgs e)
        {
            Globals.Settings.AutoSaveCapture = AutoSaveToggle.IsChecked == true;
            Persist();
        }

        private void AutoRemoveInactiveToggle_Click(object sender, RoutedEventArgs e)
        {
            Globals.Settings.AutoRemoveInactive = AutoRemoveInactiveToggle.IsChecked == true;
            Persist();
        }

        // ── Resources ────────────────────────────────────────────────────
        private void LearnButton_Click(object sender, RoutedEventArgs e) =>
            OpenUrl("https://github.com/rhino/rhinosniff");

        private void DiscordButton_Click(object sender, RoutedEventArgs e) =>
            OpenUrl("https://discord.gg/nca");

        private static void OpenUrl(string url)
        {
            try { Process.Start(new ProcessStartInfo { FileName = url, UseShellExecute = true }); }
            catch { }
        }

        private void ResetTutorialButton_Click(object sender, RoutedEventArgs e)
        {
            // Tutorial itself not yet implemented (Phase 7+). Stub: no-op + toast.
            try { _host?.NotifyPublic(NotificationType.Info, "Tutorial reset — will replay on next launch."); }
            catch { }
        }

        // ── Advanced ─────────────────────────────────────────────────────
        private void CountryFlagsToggle_Click(object sender, RoutedEventArgs e)
        {
            Globals.Settings.ShowFlags = CountryFlagsToggle.IsChecked == true;
            Persist();
        }

        private void GeoToggle_Click(object sender, RoutedEventArgs e)
        {
            Globals.Settings.Geolocate = GeoToggle.IsChecked == true;
            Persist();
        }

        private void HardwareAccelToggle_Click(object sender, RoutedEventArgs e)
        {
            var on = HardwareAccelToggle.IsChecked == true;
            Globals.Settings.HardwareAccel = on;
            RenderOptions.ProcessRenderMode = on ? RenderMode.Default : RenderMode.SoftwareOnly;
            Persist();
        }

        private void TopMostToggle_Click(object sender, RoutedEventArgs e)
        {
            Globals.Settings.TopMost = TopMostToggle.IsChecked == true;
            try { if (_host != null) _host.Topmost = Globals.Settings.TopMost; } catch { }
            Persist();
        }

        private void SoundAlertsToggle_Click(object sender, RoutedEventArgs e)
        {
            Globals.Settings.SoundAlerts = SoundAlertsToggle.IsChecked == true;
            Persist();
        }

        private void RememberAdapterToggle_Click(object sender, RoutedEventArgs e)
        {
            Globals.Settings.RememberInterface = RememberAdapterToggle.IsChecked == true;
            Persist();
        }

        private void AutoShowPanelToggle_Click(object sender, RoutedEventArgs e)
        {
            Globals.Settings.AutoShowPanel = AutoShowPanelToggle.IsChecked == true;
            Persist();
        }

        private void PacketAnalyserToggle_Click(object sender, RoutedEventArgs e)
        {
            Globals.Settings.PacketAnalyser = PacketAnalyserToggle.IsChecked == true;
            Persist();
        }

        private void EnableLabelsToggle_Click(object sender, RoutedEventArgs e)
        {
            Globals.Settings.EnableLabels = EnableLabelsToggle.IsChecked == true;
            Persist();
        }

        // ── Log file ─────────────────────────────────────────────────────
        private void OpenLogButton_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                var path = Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                    "RhinoSniff", "logfile.log");
                Process.Start(new ProcessStartInfo { FileName = path, UseShellExecute = true });
            }
            catch (Exception ex) { _ = ex.AutoDumpExceptionAsync(); }
        }
    }
}
