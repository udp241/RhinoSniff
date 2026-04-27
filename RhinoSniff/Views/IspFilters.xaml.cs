using System;
using System.Linq;
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
    public partial class IspFilters : UserControl
    {
        private readonly MainWindow _host;
        private bool _suppress;

        public IspFilters(MainWindow host)
        {
            _host = host;
            InitializeComponent();

            _suppress = true;
            BehaviorCombo.SelectedIndex =
                Globals.Settings.IspFilterBehavior == IspFilterBehavior.Dim ? 1 : 0;
            _suppress = false;

            RenderList();
        }

        private void RenderList()
        {
            var list = Globals.Settings.IspFilters ??= new System.Collections.Generic.List<string>();
            IspCountText.Text = $"{list.Count} RULE{(list.Count == 1 ? "" : "S")}";
            EmptyBanner.Visibility = list.Count == 0 ? Visibility.Visible : Visibility.Collapsed;

            IspList.Items.Clear();
            foreach (var isp in list) IspList.Items.Add(BuildRow(isp));
        }

        private Border BuildRow(string isp)
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
                Kind = PackIconKind.OfficeBuildingOutline,
                Width = 16, Height = 16,
                Foreground = (Brush)FindResource("TextMuted"),
                VerticalAlignment = VerticalAlignment.Center,
                Margin = new Thickness(0, 0, 10, 0)
            };
            Grid.SetColumn(icon, 0);
            g.Children.Add(icon);

            var text = new TextBlock
            {
                Text = isp,
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
                Tag = isp,
                ToolTip = "Remove"
            };
            del.Content = new PackIcon
            {
                Kind = PackIconKind.TrashOutline,
                Width = 16, Height = 16,
                Foreground = (Brush)FindResource("StatusDanger")
            };
            del.Click += DeleteIsp_Click;
            Grid.SetColumn(del, 2);
            g.Children.Add(del);

            row.Child = g;
            return row;
        }

        private void AddIsp_Click(object sender, RoutedEventArgs e) => AddIspFromInput();
        private void IspInput_KeyDown(object sender, KeyEventArgs e)
        {
            if (e.Key == Key.Enter) AddIspFromInput();
        }

        private void AddIspFromInput()
        {
            var value = IspInput.Text?.Trim();
            if (string.IsNullOrEmpty(value)) return;

            var list = Globals.Settings.IspFilters ??= new System.Collections.Generic.List<string>();
            if (list.Any(s => string.Equals(s, value, StringComparison.OrdinalIgnoreCase)))
            {
                IspInput.Text = "";
                return;
            }
            list.Add(value);
            IspInput.Text = "";
            SaveSettings();
            RenderList();
        }

        private void DeleteIsp_Click(object sender, RoutedEventArgs e)
        {
            if (sender is not Button b || b.Tag is not string isp) return;
            var list = Globals.Settings.IspFilters ??= new System.Collections.Generic.List<string>();
            list.RemoveAll(s => string.Equals(s, isp, StringComparison.OrdinalIgnoreCase));
            SaveSettings();
            RenderList();
        }

        private void Behavior_Changed(object sender, SelectionChangedEventArgs e)
        {
            if (_suppress) return;
            if (BehaviorCombo.SelectedItem is ComboBoxItem item && item.Tag is string tag)
            {
                Globals.Settings.IspFilterBehavior = tag == "Dim" ? IspFilterBehavior.Dim : IspFilterBehavior.Hide;
                SaveSettings();
            }
        }

        private async void SaveSettings()
        {
            try { await Globals.Container.GetInstance<IServerSettings>().UpdateSettingsAsync(); }
            catch { }
        }
    }
}
