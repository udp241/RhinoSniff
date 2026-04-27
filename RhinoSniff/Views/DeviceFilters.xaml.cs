using System;
using System.Linq;
using System.Net;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;
using MaterialDesignThemes.Wpf;
using RhinoSniff.Classes;
using RhinoSniff.Interfaces;
using RhinoSniff.Models;
using RhinoSniff.Windows;

namespace RhinoSniff.Views
{
    public partial class DeviceFilters : UserControl
    {
        private readonly MainWindow _host;

        public DeviceFilters(MainWindow host)
        {
            _host = host;
            InitializeComponent();
            RenderList();
        }

        private void RenderList()
        {
            var list = Globals.Settings.DeviceFilterIps ??= new System.Collections.Generic.List<string>();
            CountText.Text = $"{list.Count} DEVICE{(list.Count == 1 ? "" : "S")}";
            EmptyBanner.Visibility = list.Count == 0 ? Visibility.Visible : Visibility.Collapsed;

            IpList.Items.Clear();
            foreach (var ip in list) IpList.Items.Add(BuildRow(ip));
        }

        private Border BuildRow(string ip)
        {
            var row = new Border
            {
                Background = (Brush)FindResource("InputBg"),
                BorderBrush = (Brush)FindResource("InputBorder"),
                BorderThickness = new Thickness(1),
                CornerRadius = new CornerRadius(6),
                Padding = new Thickness(12, 8, 8, 8),
                Margin = new Thickness(0, 0, 0, 6)
            };

            var g = new Grid();
            g.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
            g.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
            g.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });

            var icon = new PackIcon
            {
                Kind = PackIconKind.Devices,
                Width = 16, Height = 16,
                Foreground = (Brush)FindResource("TextMuted"),
                VerticalAlignment = VerticalAlignment.Center,
                Margin = new Thickness(0, 0, 10, 0)
            };
            Grid.SetColumn(icon, 0);
            g.Children.Add(icon);

            var text = new TextBlock
            {
                Text = ip,
                FontFamily = new FontFamily("Consolas"),
                FontSize = 12,
                VerticalAlignment = VerticalAlignment.Center,
                Foreground = (Brush)FindResource("TextPrimary"),
                TextTrimming = TextTrimming.CharacterEllipsis
            };
            Grid.SetColumn(text, 1);
            g.Children.Add(text);

            var del = new Button
            {
                Style = (Style)FindResource("MaterialDesignIconButton"),
                Height = 28, Width = 28, Padding = new Thickness(0),
                Cursor = Cursors.Hand,
                Tag = ip,
                ToolTip = "Remove"
            };
            del.Content = new PackIcon
            {
                Kind = PackIconKind.TrashOutline,
                Width = 16, Height = 16,
                Foreground = (Brush)FindResource("StatusDanger")
            };
            del.Click += DeleteIp_Click;
            Grid.SetColumn(del, 2);
            g.Children.Add(del);

            row.Child = g;
            return row;
        }

        private void AddIp_Click(object sender, RoutedEventArgs e) => AddFromInput();
        private void IpInput_KeyDown(object sender, KeyEventArgs e)
        {
            if (e.Key == Key.Enter) AddFromInput();
        }

        private void AddFromInput()
        {
            var value = IpInput.Text?.Trim();
            if (string.IsNullOrEmpty(value)) return;
            if (!IPAddress.TryParse(value, out var parsed) ||
                parsed.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork) return;

            var list = Globals.Settings.DeviceFilterIps ??= new System.Collections.Generic.List<string>();
            if (list.Any(s => string.Equals(s, value, StringComparison.OrdinalIgnoreCase)))
            {
                IpInput.Text = "";
                return;
            }
            list.Add(value);
            IpInput.Text = "";
            SaveSettings();
            RenderList();
        }

        private void DeleteIp_Click(object sender, RoutedEventArgs e)
        {
            if (sender is not Button b || b.Tag is not string ip) return;
            var list = Globals.Settings.DeviceFilterIps ??= new System.Collections.Generic.List<string>();
            list.RemoveAll(s => string.Equals(s, ip, StringComparison.OrdinalIgnoreCase));
            SaveSettings();
            RenderList();
        }

        private async void SaveSettings()
        {
            try { await Globals.Container.GetInstance<IServerSettings>().UpdateSettingsAsync(); }
            catch { }
        }
    }
}
