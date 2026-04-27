using System;
using System.Collections.ObjectModel;
using System.Linq;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using MaterialDesignThemes.Wpf;
using RhinoSniff.Classes;
using RhinoSniff.Models;
using RhinoSniff.Windows;

namespace RhinoSniff.Views
{
    public partial class Hotspot : UserControl
    {
        public class AdapterRow
        {
            public string Name { get; set; }
            public string Description { get; set; }
            public string Guid { get; set; }
            public string RoleDisplay { get; set; }
            public string StatusDisplay { get; set; }
        }

        private readonly MainWindow _host;
        private readonly HotspotManager _hotspot = new();
        private readonly ObservableCollection<AdapterRow> _adapters = new();
        private bool _passVisible;

        public Hotspot(MainWindow host)
        {
            _host = host;
            InitializeComponent();
            AdaptersGrid.ItemsSource = _adapters;

            Loaded += async (_, _) =>
            {
                RefreshHotspotStatus();
                await RefreshAdaptersAsync();
            };
        }

        // ── Hotspot (WinRT) ─────────────────────────────────────────────────

        private void RefreshHotspotStatus()
        {
            var status = _hotspot.GetStatus();

            if (!status.Supported)
            {
                UnsupportedBanner.Visibility = Visibility.Visible;
                UnsupportedText.Text = status.Error ?? "Mobile Hotspot is not available on this system.";
            }
            else
            {
                UnsupportedBanner.Visibility = Visibility.Collapsed;
            }

            CurrentSsidText.Text = string.IsNullOrWhiteSpace(status.Ssid) ? "—" : status.Ssid;
            ClientCountText.Text = status.ClientCount.ToString();

            // Only repopulate editor fields if they're empty — don't clobber in-progress edits
            if (string.IsNullOrEmpty(SsidInput.Text)) SsidInput.Text = status.Ssid ?? "";
            if (string.IsNullOrEmpty(PassInput.Password) && string.IsNullOrEmpty(PassInputVisible.Text))
            {
                PassInput.Password = status.Passphrase ?? "";
                PassInputVisible.Text = status.Passphrase ?? "";
            }

            SetStatePill(status.Running);
            HotspotToggleText.Text = status.Running ? "Stop Hotspot" : "Start Hotspot";
            HotspotToggleIcon.Kind = status.Running ? PackIconKind.Stop : PackIconKind.Play;
        }

        private void SetStatePill(bool running)
        {
            if (running)
            {
                StatePill.SetResourceReference(Border.BackgroundProperty, "PillCapturingBg");
                StateDot.SetResourceReference(System.Windows.Shapes.Shape.FillProperty, "StatusSuccess");
                StateText.SetResourceReference(TextBlock.ForegroundProperty, "PillCapturingText");
                StateText.Text = "ON";
            }
            else
            {
                StatePill.SetResourceReference(Border.BackgroundProperty, "PillStoppedBg");
                StateDot.SetResourceReference(System.Windows.Shapes.Shape.FillProperty, "StatusDanger");
                StateText.SetResourceReference(TextBlock.ForegroundProperty, "PillStoppedText");
                StateText.Text = "OFF";
            }
        }

        private void TogglePassVisibility_Click(object sender, RoutedEventArgs e)
        {
            _passVisible = !_passVisible;
            if (_passVisible)
            {
                PassInputVisible.Text = PassInput.Password;
                PassInputVisible.Visibility = Visibility.Visible;
                PassInput.Visibility = Visibility.Collapsed;
                PassEyeIcon.Kind = PackIconKind.EyeOffOutline;
            }
            else
            {
                PassInput.Password = PassInputVisible.Text;
                PassInput.Visibility = Visibility.Visible;
                PassInputVisible.Visibility = Visibility.Collapsed;
                PassEyeIcon.Kind = PackIconKind.EyeOutline;
            }
        }

        private string CurrentPassphrase() => _passVisible ? PassInputVisible.Text : PassInput.Password;

        private async void SaveHotspot_Click(object sender, RoutedEventArgs e)
        {
            var ssid = (SsidInput.Text ?? "").Trim();
            var pass = CurrentPassphrase() ?? "";
            var (ok, err) = await _hotspot.ApplyConfigAsync(ssid, pass);
            if (!ok) _host?.NotifyPublic(NotificationType.Error, "Hotspot config: " + err);
            else _host?.NotifyPublic(NotificationType.Info, "Hotspot config saved.");
            RefreshHotspotStatus();
        }

        private async void ToggleHotspot_Click(object sender, RoutedEventArgs e)
        {
            var status = _hotspot.GetStatus();
            if (!status.Supported)
            {
                _host?.NotifyPublic(NotificationType.Error, status.Error ?? "Mobile Hotspot unavailable.");
                return;
            }

            if (status.Running)
            {
                var (ok, err) = await _hotspot.StopAsync();
                if (!ok) _host?.NotifyPublic(NotificationType.Error, "Stop: " + err);
                else _host?.NotifyPublic(NotificationType.Info, "Hotspot stopped.");
            }
            else
            {
                // Apply pending edits first if the user didn't click Save
                var ssid = (SsidInput.Text ?? "").Trim();
                var pass = CurrentPassphrase() ?? "";
                if (!string.IsNullOrEmpty(ssid) && (ssid != status.Ssid || pass != status.Passphrase))
                {
                    var (cok, cerr) = await _hotspot.ApplyConfigAsync(ssid, pass);
                    if (!cok)
                    {
                        _host?.NotifyPublic(NotificationType.Error, "Config: " + cerr);
                        return;
                    }
                }
                var (ok, err) = await _hotspot.StartAsync();
                if (!ok) _host?.NotifyPublic(NotificationType.Error, "Start: " + err);
                else _host?.NotifyPublic(NotificationType.Info, "Hotspot started.");
            }
            RefreshHotspotStatus();
        }

        // ── ICS (COM) ───────────────────────────────────────────────────────

        private async Task RefreshAdaptersAsync()
        {
            _adapters.Clear();
            var list = await IcsManager.ListAsync();

            // Populate combos with a copy of the same list (DisplayMemberPath=Name)
            var comboItems = list.Select(a => new { a.Name, a.Guid, a.Description, Display = $"{a.Name} — {a.Description}" }).ToList();
            var priorPublicGuid = (PublicAdapterCombo.SelectedItem as dynamic)?.Guid as string;
            var priorPrivateGuid = (PrivateAdapterCombo.SelectedItem as dynamic)?.Guid as string;

            PublicAdapterCombo.ItemsSource = null;
            PrivateAdapterCombo.ItemsSource = null;
            PublicAdapterCombo.DisplayMemberPath = "Display";
            PrivateAdapterCombo.DisplayMemberPath = "Display";
            PublicAdapterCombo.ItemsSource = comboItems;
            PrivateAdapterCombo.ItemsSource = comboItems;

            // Restore selections (or preselect whatever's currently sharing)
            var currentPublic = list.FirstOrDefault(a => a.SharingEnabled && a.SharingRole == 0)?.Guid;
            var currentPrivate = list.FirstOrDefault(a => a.SharingEnabled && a.SharingRole == 1)?.Guid;
            PublicAdapterCombo.SelectedItem = comboItems.FirstOrDefault(x => x.Guid == (priorPublicGuid ?? currentPublic));
            PrivateAdapterCombo.SelectedItem = comboItems.FirstOrDefault(x => x.Guid == (priorPrivateGuid ?? currentPrivate));

            foreach (var a in list)
            {
                _adapters.Add(new AdapterRow
                {
                    Name = a.Name,
                    Description = a.Description,
                    Guid = a.Guid,
                    RoleDisplay = a.SharingEnabled
                        ? (a.SharingRole == 0 ? "Public" : a.SharingRole == 1 ? "Private" : "Shared")
                        : "—",
                    StatusDisplay = a.IsActive ? "Active" : "Idle"
                });
            }
        }

        private async void RefreshIcs_Click(object sender, RoutedEventArgs e)
        {
            await RefreshAdaptersAsync();
        }

        private async void EnableIcs_Click(object sender, RoutedEventArgs e)
        {
            var pub = (PublicAdapterCombo.SelectedItem as dynamic)?.Guid as string;
            var prv = (PrivateAdapterCombo.SelectedItem as dynamic)?.Guid as string;
            if (string.IsNullOrEmpty(pub) || string.IsNullOrEmpty(prv))
            {
                _host?.NotifyPublic(NotificationType.Alert, "Pick both a public and private adapter.");
                return;
            }
            var (ok, err) = await IcsManager.EnableAsync(pub, prv);
            if (!ok) _host?.NotifyPublic(NotificationType.Error, "ICS: " + err);
            else _host?.NotifyPublic(NotificationType.Info, "Internet sharing enabled.");
            await RefreshAdaptersAsync();
        }

        private async void DisableIcs_Click(object sender, RoutedEventArgs e)
        {
            var (ok, err) = await IcsManager.DisableAllAsync();
            if (!ok) _host?.NotifyPublic(NotificationType.Error, "ICS: " + err);
            else _host?.NotifyPublic(NotificationType.Info, "Internet sharing disabled.");
            await RefreshAdaptersAsync();
        }

        // ── Setup guide ─────────────────────────────────────────────────────

        private void SetupGuide_Click(object sender, RoutedEventArgs e)
        {
            var msg =
                "HOTSPOT SETUP\n" +
                "=============\n\n" +
                "Wi-Fi Hotspot (RECOMMENDED for consoles)\n" +
                "  1. Connect this PC to the internet (Ethernet, Wi-Fi, or VPN).\n" +
                "  2. Set an SSID + password (8+ chars) on the left card.\n" +
                "  3. Click Start Hotspot.\n" +
                "  4. Join your console / other device to the new SSID.\n" +
                "  5. Your console's traffic now routes through this PC — capture\n" +
                "     it on your internet-facing adapter in Network Monitor.\n\n" +
                "Ethernet Bridge (ICS)\n" +
                "  1. Plug the client device into a spare NIC on this PC.\n" +
                "  2. On the right card, pick the internet-facing adapter as PUBLIC\n" +
                "     and the spare NIC as PRIVATE.\n" +
                "  3. Click Enable Sharing.\n" +
                "  4. The client gets an IP from 192.168.137.x (ICS default).\n\n" +
                "Notes\n" +
                "  - Both paths require Administrator (already granted).\n" +
                "  - Mobile Hotspot is not available on every Windows SKU.\n" +
                "  - When using Mullvad / WireGuard as the public side, your console\n" +
                "    will also be tunneled.";
            MessageBox.Show(Window.GetWindow(this), msg, "Hotspot Setup Guide",
                MessageBoxButton.OK, MessageBoxImage.Information);
        }
    }
}
