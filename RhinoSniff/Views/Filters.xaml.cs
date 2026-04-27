using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Linq;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using RhinoSniff.Classes;
using RhinoSniff.Interfaces;
using RhinoSniff.Models;
using RhinoSniff.Windows;
using MaterialDesignThemes.Wpf;

namespace RhinoSniff.Views
{
    public partial class Filters : Page
    {
        private readonly MainWindow _host;
        private readonly BindingList<ushort> portBoxSource = new(Globals.Settings.Ports);
        private readonly BindingList<CustomFilter> customFilterSource = new();
        private readonly List<CheckBox> filterCheckboxes = new();
        private bool _suppressFilterChange;

        public Filters(MainWindow host)
        {
            _host = host;
            InitializeComponent();

            // Port blacklist
            PortListBox.ItemsSource = portBoxSource;
            InvertPortFilterToggle.IsChecked = Globals.Settings.PortsInverse;
            InvertPortFilterToggle.Unchecked += (_, _) => { SaveSettings(); };
            InvertPortFilterToggle.Checked += (_, _) => { SaveSettings(); };

            // ISP filter
            IspFilterBox.Text = Globals.Settings.IspFilter ?? "";

            // Console IP filter
            ConsoleIpFilterBox.Text = Globals.Settings.ConsoleIpFilter ?? "";

            // Other Info (All Traffic) tab toggle
            OtherInfoToggle.IsChecked = Globals.Settings.ShowOtherInfoTab;
            OtherInfoToggle.Checked += OtherInfoToggle_Changed;
            OtherInfoToggle.Unchecked += OtherInfoToggle_Changed;

            // Packet type toggles — set values FIRST, then wire events
            ShowUdpToggle.IsChecked = Globals.Settings.ShowUdpPackets;
            ShowTcpToggle.IsChecked = Globals.Settings.ShowTcpPackets;
            ShowUdpToggle.Checked += PacketTypeToggle_Changed;
            ShowUdpToggle.Unchecked += PacketTypeToggle_Changed;
            ShowTcpToggle.Checked += PacketTypeToggle_Changed;
            ShowTcpToggle.Unchecked += PacketTypeToggle_Changed;

            // Auto remove inactive
            AutoRemoveInactiveToggle.IsChecked = Globals.Settings.AutoRemoveInactive;
            AutoRemoveInactiveToggle.Checked += (_, _) => { Globals.Settings.AutoRemoveInactive = true; SaveSettings(); };
            AutoRemoveInactiveToggle.Unchecked += (_, _) => { Globals.Settings.AutoRemoveInactive = false; SaveSettings(); };

            // Custom filters
            foreach (var cf in Globals.Settings.CustomFilters)
                customFilterSource.Add(cf);
            CustomFilterListBox.ItemsSource = customFilterSource;

            // Build game filter checkboxes
            BuildFilterCheckboxes();
        }

        private void BuildFilterCheckboxes()
        {
            _suppressFilterChange = true;
            // Keep the header row (first child), clear the rest
            while (FilterCheckboxPanel.Children.Count > 1)
                FilterCheckboxPanel.Children.RemoveAt(FilterCheckboxPanel.Children.Count - 1);
            filterCheckboxes.Clear();

            var activeFilters = Globals.Settings.ActiveGameFilters ?? new List<FilterPreset>();

            foreach (FilterPreset val in Enum.GetValues(typeof(FilterPreset)))
            {
                if (val == FilterPreset.None) continue;

                var cb = new CheckBox
                {
                    Tag = val,
                    IsChecked = activeFilters.Contains(val),
                    VerticalAlignment = VerticalAlignment.Center,
                    Margin = new Thickness(4, 0, 0, 0)
                };
                cb.Checked += FilterCheckbox_Changed;
                cb.Unchecked += FilterCheckbox_Changed;
                filterCheckboxes.Add(cb);

                var typeBadge = new Border
                {
                    Background = new System.Windows.Media.SolidColorBrush(
                        System.Windows.Media.Color.FromArgb(0x44, 0x66, 0xBB, 0x6A)),
                    CornerRadius = new CornerRadius(3),
                    Padding = new Thickness(4, 1, 4, 1),
                    HorizontalAlignment = HorizontalAlignment.Center
                };
                typeBadge.Child = new TextBlock
                {
                    Text = "UDP",
                    FontSize = 9,
                    FontWeight = FontWeights.SemiBold,
                    Foreground = new System.Windows.Media.SolidColorBrush(
                        System.Windows.Media.Color.FromRgb(0x66, 0xBB, 0x6A)),
                    HorizontalAlignment = HorizontalAlignment.Center
                };

                var row = new Grid { Margin = new Thickness(0, 2, 0, 2) };
                row.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(28) });
                row.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
                row.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(40) });
                row.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(62) });

                Grid.SetColumn(cb, 0);
                row.Children.Add(cb);

                var nameBlock = new TextBlock
                {
                    Text = FormatFilterName(val),
                    Foreground = System.Windows.Media.Brushes.White,
                    FontSize = 11,
                    VerticalAlignment = VerticalAlignment.Center,
                    Margin = new Thickness(4, 0, 0, 0),
                    TextTrimming = TextTrimming.CharacterEllipsis
                };
                Grid.SetColumn(nameBlock, 1);
                row.Children.Add(nameBlock);

                Grid.SetColumn(typeBadge, 2);
                row.Children.Add(typeBadge);

                var consoleBlock = new TextBlock
                {
                    Text = GetConsoleName(val),
                    Foreground = new System.Windows.Media.SolidColorBrush(
                        System.Windows.Media.Color.FromArgb(0x99, 0xFF, 0xFF, 0xFF)),
                    FontSize = 9,
                    VerticalAlignment = VerticalAlignment.Center,
                    HorizontalAlignment = HorizontalAlignment.Center,
                    TextTrimming = TextTrimming.CharacterEllipsis
                };
                Grid.SetColumn(consoleBlock, 3);
                row.Children.Add(consoleBlock);

                FilterCheckboxPanel.Children.Add(row);
            }

            _suppressFilterChange = false;
        }

        private static string GetConsoleName(FilterPreset preset)
        {
            return preset switch
            {
                FilterPreset.PSNParty => "PS4",
                FilterPreset.GTAVConsole => "PS4",
                FilterPreset.XboxPartyBETA => "Universal",
                FilterPreset.Discord => "PC",
                FilterPreset.Minecraft => "Universal",
                FilterPreset.uTorrent or FilterPreset.GenericTorrentClient => "PC",
                FilterPreset.TCP or FilterPreset.UDP => "Universal",
                FilterPreset.Custom => "Custom",
                _ => "Universal"
            };
        }

        private static string FormatFilterName(FilterPreset preset)
        {
            return preset switch
            {
                FilterPreset.PSNParty => "PSN Party (Client)",
                FilterPreset.XboxPartyBETA => "Xbox Party (Server)",
                FilterPreset.CallOfDuty => "Call of Duty (Client)",
                FilterPreset.CSGO => "CS:GO / CS2 (Server)",
                FilterPreset.GTAOnline => "GTA Online (Server)",
                FilterPreset.RDR2Online => "RDR2 Online (Server)",
                FilterPreset.GTAVConsole => "GTA V (Console)",
                FilterPreset.RainbowSixSiege => "Rainbow 6 Siege (Server)",
                FilterPreset.SeaOfThieves => "Sea of Thieves (Server)",
                FilterPreset.DeadByDaylight => "Dead by Daylight (Server)",
                FilterPreset.NBA2K => "NBA 2K (Server)",
                FilterPreset.FIFA => "FIFA / EA FC (Server)",
                FilterPreset.GenericTorrentClient => "Torrent (Generic)",
                FilterPreset.uTorrent => "uTorrent",
                FilterPreset.RecRoom => "Rec Room (Server)",
                FilterPreset.Fortnite => "Fortnite (Server)",
                FilterPreset.Valorant => "Valorant (Server)",
                FilterPreset.PUBG => "PUBG (Server)",
                FilterPreset.Overwatch => "Overwatch (Server)",
                FilterPreset.Battlefield => "Battlefield (Server)",
                FilterPreset.Halo => "Halo (Server)",
                FilterPreset.Destiny => "Destiny (Server)",
                FilterPreset.Rust => "Rust (Server)",
                FilterPreset.ARK => "ARK (Server)",
                FilterPreset.DayZ => "DayZ (Server)",
                FilterPreset.Minecraft => "Minecraft (Host)",
                FilterPreset.Tekken => "Tekken (Client)",
                FilterPreset.MortalKombat => "Mortal Kombat (Client)",
                FilterPreset.RocketLeague => "Rocket League (Server)",
                FilterPreset.ApexLegends => "Apex Legends (Server)",
                FilterPreset.Discord => "Discord Voice (Server)",
                FilterPreset.TCP => "TCP Only",
                FilterPreset.UDP => "UDP Only",
                FilterPreset.Custom => "Custom Filter",
                _ => preset.ToString()
            };
        }

        private void FilterCheckbox_Changed(object sender, RoutedEventArgs e)
        {
            if (_suppressFilterChange) return;

            var active = new List<FilterPreset>();
            foreach (var cb in filterCheckboxes)
            {
                if (cb.IsChecked == true && cb.Tag is FilterPreset fp)
                    active.Add(fp);
            }

            Globals.Settings.ActiveGameFilters = active;
            // Clear single filter since we're using multi-mode
            Globals.Settings.Filter = FilterPreset.None;
            SaveSettings();
        }

        private void IspFilter_TextChanged(object sender, TextChangedEventArgs e)
        {
            Globals.Settings.IspFilter = IspFilterBox.Text?.Trim() ?? "";
            // Saved when panel closes or another control triggers SaveSettings
        }

        private void ConsoleIpFilter_TextChanged(object sender, TextChangedEventArgs e)
        {
            Globals.Settings.ConsoleIpFilter = ConsoleIpFilterBox.Text?.Trim() ?? "";
            // Saved when panel closes or another control triggers SaveSettings
        }

        private void OtherInfoToggle_Changed(object sender, RoutedEventArgs e)
        {
            var show = OtherInfoToggle.IsChecked == true;
            Globals.Settings.ShowOtherInfoTab = show;
            _host.SetAllTrafficTabVisibility(show);
            SaveSettings();
        }

        private void PacketTypeToggle_Changed(object sender, RoutedEventArgs e)
        {
            if (ShowUdpToggle == null || ShowTcpToggle == null) return;
            Globals.Settings.ShowUdpPackets = ShowUdpToggle.IsChecked == true;
            Globals.Settings.ShowTcpPackets = ShowTcpToggle.IsChecked == true;
            SaveSettings();
        }

        private void AddCustomFilter_Click(object sender, RoutedEventArgs e)
        {
            var name = CustomNameBox.Text?.Trim();
            if (string.IsNullOrEmpty(name)) return;
            if (!ushort.TryParse(CustomMinPortBox.Text, out var min)) return;
            if (!ushort.TryParse(CustomMaxPortBox.Text, out var max)) return;
            if (min > max) return;

            var cf = new CustomFilter { Name = name, MinPort = min, MaxPort = max, UdpOnly = true };
            customFilterSource.Add(cf);
            Globals.Settings.CustomFilters.Add(cf);
            SaveSettings();

            CustomNameBox.Text = "";
            CustomMinPortBox.Text = "";
            CustomMaxPortBox.Text = "";
        }

        private void DeleteCustomFilter_Click(object sender, RoutedEventArgs e)
        {
            if (CustomFilterListBox.SelectedItem is not CustomFilter cf) return;
            customFilterSource.Remove(cf);
            Globals.Settings.CustomFilters.Remove(cf);
            SaveSettings();
        }

        private void CopyPortItem_Click(object sender, RoutedEventArgs e)
        {
            if (PortListBox.SelectedItem != null)
                PortListBox.SelectedItem.ToString().CopyToClipboard();
        }

        private void DeletePortItem_Click(object sender, RoutedEventArgs e)
        {
            if (PortListBox.SelectedItem != null)
            {
                portBoxSource.Remove(Convert.ToUInt16(PortListBox.SelectedItem));
                SaveSettings(); // Persist port blacklist changes
            }
        }

        private void DialogHost_Closed(object sender, DialogClosingEventArgs eventArgs)
        {
            if (!Equals(eventArgs.Parameter, true))
                return;

            if (!ushort.TryParse(PortText.Text, out var port) || portBoxSource.Contains(port)) return;
            
            PortText.Text = string.Empty;
            portBoxSource.Add(port);
            SaveSettings(); // Persist port blacklist changes
        }

        private async void SaveSettings()
        {
            Globals.Settings.PortsInverse = InvertPortFilterToggle.IsChecked == true;
            await Globals.Container.GetInstance<IServerSettings>().UpdateSettingsAsync();
        }
    }
}
