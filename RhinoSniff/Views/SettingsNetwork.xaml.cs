using System;
using System.Linq;
using System.Windows.Controls;
using RhinoSniff.Classes;
using RhinoSniff.Interfaces;
using RhinoSniff.Models;
using RhinoSniff.Windows;

namespace RhinoSniff.Views
{
    /// <summary>
    /// Phase 6 — Settings → Network sub-page.
    /// Adapter preview card + 4 network-scoped toggles.
    /// </summary>
    public partial class SettingsNetwork : UserControl
    {
        private readonly MainWindow _host;
        private bool _loaded;

        public SettingsNetwork(MainWindow host)
        {
            InitializeComponent();
            _host = host;
            LoadState();
            RefreshAdapterCard();
            _loaded = true;
        }

        private void LoadState()
        {
            AutoDetectToggle.IsChecked        = Globals.Settings.AutoDetectInterfaces;
            ShowInactiveToggle.IsChecked      = !Globals.Settings.HideInterfaces; // legacy field uses inverse
            InspectModeToggle.IsChecked       = Globals.Settings.NetworkInspectMode;
            DisableRemoteWarnToggle.IsChecked = Globals.Settings.DisableRemoteNetworkWarning;
        }

        private void RefreshAdapterCard()
        {
            try
            {
                var name = Globals.Settings.InterfaceName;
                var adapter = Adapter.Instance.FirstOrDefault(a => a.Name == name);
                if (string.IsNullOrEmpty(adapter.Name))
                {
                    AdapterNameText.Text = "No adapter selected";
                    AdapterIpText.Text = "—";
                    UpPillText.Text = "OFF";
                    return;
                }
                AdapterNameText.Text = adapter.DisplayName;
                AdapterIpText.Text = string.IsNullOrWhiteSpace(adapter.IpAddress) ? "—" : adapter.IpAddress;
                UpPillText.Text = "UP";
            }
            catch { /* non-fatal */ }
        }

        private async void Persist()
        {
            if (!_loaded) return;
            try { await Globals.Container.GetInstance<IServerSettings>().UpdateSettingsAsync(); }
            catch { /* ignore — not worth interrupting the user */ }
        }

        private void AutoDetectToggle_Click(object sender, System.Windows.RoutedEventArgs e)
        {
            Globals.Settings.AutoDetectInterfaces = AutoDetectToggle.IsChecked == true;
            Persist();
        }

        private void ShowInactiveToggle_Click(object sender, System.Windows.RoutedEventArgs e)
        {
            // Stored as HideInterfaces (inverse) for backward compatibility.
            Globals.Settings.HideInterfaces = !(ShowInactiveToggle.IsChecked == true);
            Persist();
        }

        private void InspectModeToggle_Click(object sender, System.Windows.RoutedEventArgs e)
        {
            Globals.Settings.NetworkInspectMode = InspectModeToggle.IsChecked == true;
            Persist();
        }

        private void DisableRemoteWarnToggle_Click(object sender, System.Windows.RoutedEventArgs e)
        {
            Globals.Settings.DisableRemoteNetworkWarning = DisableRemoteWarnToggle.IsChecked == true;
            Persist();
        }
    }
}
