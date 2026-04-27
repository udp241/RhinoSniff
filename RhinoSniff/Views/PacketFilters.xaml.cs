using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Linq;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Controls.Primitives;
using System.Windows.Input;
using System.Windows.Media;
using MaterialDesignThemes.Wpf;
using RhinoSniff.Classes;
using RhinoSniff.Interfaces;
using RhinoSniff.Models;
using RhinoSniff.Windows;

namespace RhinoSniff.Views
{
    public partial class PacketFilters : UserControl
    {
        private readonly MainWindow _host;
        private readonly BindingList<ushort> _portBoxSource = new(Globals.Settings.Ports);
        private readonly BindingList<CustomFilter> _customFilterSource = new();

        // ── Three-tab state ───────────────────────────────────────────────
        private enum Tab { Active, MyFilters, Community }
        private Tab _currentTab = Tab.Active;

        private bool _saving;

        public PacketFilters(MainWindow host)
        {
            _host = host;
            InitializeComponent();

            // Port blacklist list
            PortListBox.ItemsSource = _portBoxSource;
            InvertPortFilterToggle.IsChecked = Globals.Settings.PortsInverse;
            InvertPortFilterToggle.Checked += (_, _) => SaveSettings();
            InvertPortFilterToggle.Unchecked += (_, _) => SaveSettings();

            // Packet-type toggles
            ShowUdpToggle.IsChecked = Globals.Settings.ShowUdpPackets;
            ShowTcpToggle.IsChecked = Globals.Settings.ShowTcpPackets;
            ShowUdpToggle.Checked += PacketTypeToggle_Changed;
            ShowUdpToggle.Unchecked += PacketTypeToggle_Changed;
            ShowTcpToggle.Checked += PacketTypeToggle_Changed;
            ShowTcpToggle.Unchecked += PacketTypeToggle_Changed;

            // Other toggles
            OtherInfoToggle.IsChecked = Globals.Settings.ShowOtherInfoTab;
            OtherInfoToggle.Checked += OtherInfoToggle_Changed;
            OtherInfoToggle.Unchecked += OtherInfoToggle_Changed;

            AutoRemoveInactiveToggle.IsChecked = Globals.Settings.AutoRemoveInactive;
            AutoRemoveInactiveToggle.Checked += (_, _) =>
            {
                Globals.Settings.AutoRemoveInactive = true;
                SaveSettings();
            };
            AutoRemoveInactiveToggle.Unchecked += (_, _) =>
            {
                Globals.Settings.AutoRemoveInactive = false;
                SaveSettings();
            };

            // Custom port-range filters (legacy bottom card — kept untouched)
            foreach (var cf in Globals.Settings.CustomFilters) _customFilterSource.Add(cf);
            CustomFilterListBox.ItemsSource = _customFilterSource;

            StyleTab(ActiveTab, true);
            StyleTab(MyFiltersTab, false);
            StyleTab(CommunityTab, false);
            RenderCards();
        }

        // ── Tabs ───────────────────────────────────────────────────────────────
        private void TabClick(object sender, RoutedEventArgs e)
        {
            if (sender == ActiveTab) _currentTab = Tab.Active;
            else if (sender == MyFiltersTab) _currentTab = Tab.MyFilters;
            else if (sender == CommunityTab) _currentTab = Tab.Community;

            StyleTab(ActiveTab, _currentTab == Tab.Active);
            StyleTab(MyFiltersTab, _currentTab == Tab.MyFilters);
            StyleTab(CommunityTab, _currentTab == Tab.Community);
            RenderCards();
        }

        private void StyleTab(ToggleButton t, bool selected)
        {
            t.IsChecked = selected;
            if (selected)
            {
                t.SetResourceReference(Control.BackgroundProperty, "AccentTealDark");
                t.SetResourceReference(Control.ForegroundProperty, "TextOnAccent");
                t.SetResourceReference(Control.BorderBrushProperty, "AccentTealDark");
            }
            else
            {
                t.Background = Brushes.Transparent;
                t.SetResourceReference(Control.ForegroundProperty, "TextSecondary");
                t.SetResourceReference(Control.BorderBrushProperty, "CardBorder");
            }
        }

        // ── Card rendering ─────────────────────────────────────────────────────
        private void RenderCards()
        {
            var activePresets = Globals.Settings.ActiveGameFilters ?? new List<FilterPreset>();
            var userFilters = Globals.Settings.UserFilters ?? new List<UserFilter>();
            var activeUserFilters = userFilters.Where(u => u.IsActive).ToList();

            var communityLibrarySize = FilterRegistry.All()
                .Count(m => m.Preset != FilterPreset.None);
            var customCount = userFilters.Count;
            var activeCount = activePresets.Count + activeUserFilters.Count;

            ActiveCountText.Text = $"{activeCount} active";
            FilterBreakdownText.Text = $"({customCount} custom + {communityLibrarySize} community)";

            ActiveTabText.Text = $"Active ({activeCount})";
            MyFiltersTabText.Text = $"My Filters ({customCount})";
            CommunityTabText.Text = $"Community Filters ({communityLibrarySize})";

            CardsHost.Items.Clear();

            switch (_currentTab)
            {
                case Tab.Active:
                    RenderActiveTab(activePresets, activeUserFilters);
                    break;
                case Tab.MyFilters:
                    RenderMyFiltersTab(userFilters);
                    break;
                case Tab.Community:
                    RenderCommunityTab();
                    break;
            }
        }

        private void RenderActiveTab(List<FilterPreset> activePresets, List<UserFilter> activeUserFilters)
        {
            var empty = activePresets.Count == 0 && activeUserFilters.Count == 0;
            EmptyActiveCard.Visibility = empty ? Visibility.Visible : Visibility.Collapsed;
            if (empty) return;

            foreach (var uf in activeUserFilters)
                CardsHost.Items.Add(BuildUserCard(uf, showActions: false));

            foreach (var preset in activePresets)
            {
                var meta = FilterRegistry.Get(preset);
                if (meta.Preset == FilterPreset.None) continue;
                CardsHost.Items.Add(BuildPresetCard(meta));
            }
        }

        private void RenderMyFiltersTab(List<UserFilter> userFilters)
        {
            EmptyActiveCard.Visibility = Visibility.Collapsed;

            CardsHost.Items.Add(BuildCreateFilterCard());

            foreach (var uf in userFilters)
                CardsHost.Items.Add(BuildUserCard(uf, showActions: true));
        }

        private void RenderCommunityTab()
        {
            EmptyActiveCard.Visibility = Visibility.Collapsed;

            var metas = FilterRegistry.All()
                .Where(m => m.Preset != FilterPreset.None)
                .ToList();

            foreach (var m in metas)
                CardsHost.Items.Add(BuildPresetCard(m));
        }

        // ── Built-in preset card (Community Filters + Active tab) ──
        private Border BuildPresetCard(FilterMeta m)
        {
            var isEnabled = (Globals.Settings.ActiveGameFilters ?? new()).Contains(m.Preset);
            var action = GetAction(m.Preset);

            var card = new Border
            {
                Width = 210,
                Margin = new Thickness(0, 0, 10, 10),
                Background = (Brush)FindResource("CardBg"),
                BorderBrush = isEnabled
                    ? (Brush)FindResource("AccentTeal")
                    : (Brush)FindResource("CardBorder"),
                BorderThickness = new Thickness(isEnabled ? 1.5 : 1),
                CornerRadius = new CornerRadius(8),
                Cursor = Cursors.Hand,
                Tag = m.Preset
            };
            card.MouseLeftButtonUp += PresetCard_Click;

            var outer = new Grid();
            outer.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            outer.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            outer.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            outer.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });

            var header = BuildCardHeader(
                ColorFromHex(m.AccentHexA), ColorFromHex(m.AccentHexB),
                isEnabled, action, isUserFilter: false, userFilter: null);
            Grid.SetRow(header, 0);
            outer.Children.Add(header);

            outer.Children.Add(BuildCardName(m.DisplayName, row: 1));
            outer.Children.Add(BuildCardAuthor(m.Author, CategoryLabel(m.Category), row: 2));

            var platforms = new WrapPanel { Margin = new Thickness(12, 0, 12, 10) };
            foreach (var p in m.Platforms)
                platforms.Children.Add(BuildPlatformPill(p));
            Grid.SetRow(platforms, 3);
            outer.Children.Add(platforms);

            card.Child = outer;
            return card;
        }

        // ── User-created card (My Filters + Active tab) ──
        private Border BuildUserCard(UserFilter uf, bool showActions)
        {
            var card = new Border
            {
                Width = 210,
                Margin = new Thickness(0, 0, 10, 10),
                Background = (Brush)FindResource("CardBg"),
                BorderBrush = uf.IsActive
                    ? (Brush)FindResource("AccentTeal")
                    : (Brush)FindResource("CardBorder"),
                BorderThickness = new Thickness(uf.IsActive ? 1.5 : 1),
                CornerRadius = new CornerRadius(8),
                Cursor = Cursors.Hand,
                Tag = uf.Id
            };
            card.MouseLeftButtonUp += UserCard_Click;

            var outer = new Grid();
            outer.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            outer.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            outer.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            outer.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });

            var header = BuildCardHeader(
                Color.FromRgb(0x1F, 0x29, 0x37), Color.FromRgb(0x11, 0x18, 0x27),
                uf.IsActive, uf.Action, isUserFilter: true, userFilter: uf);

            if (showActions)
                AttachUserCardActionButtons(header, uf);

            Grid.SetRow(header, 0);
            outer.Children.Add(header);

            outer.Children.Add(BuildCardName(
                string.IsNullOrWhiteSpace(uf.Name) ? "(unnamed)" : uf.Name,
                row: 1));
            outer.Children.Add(BuildCardAuthor(uf.Author, "N/A", row: 2));

            var platforms = new WrapPanel { Margin = new Thickness(12, 0, 12, 10) };
            if (uf.Platforms != null)
                foreach (var p in uf.Platforms)
                    platforms.Children.Add(BuildPlatformPill(p));
            Grid.SetRow(platforms, 3);
            outer.Children.Add(platforms);

            card.Child = outer;
            return card;
        }

        // ── Dashed "Create Filter" card ──
        private Border BuildCreateFilterCard()
        {
            var border = new Border
            {
                Width = 210,
                Height = 270,
                Margin = new Thickness(0, 0, 10, 10),
                Background = Brushes.Transparent,
                BorderBrush = Brushes.Transparent,
                CornerRadius = new CornerRadius(8),
                Cursor = Cursors.Hand
            };
            border.MouseLeftButtonUp += CreateFilterCard_Click;

            var grid = new Grid();
            // Dashed outline (Border lacks stroke dash, so Rectangle overlay)
            grid.Children.Add(new System.Windows.Shapes.Rectangle
            {
                Stroke = (Brush)FindResource("CardBorder"),
                StrokeThickness = 1,
                StrokeDashArray = new DoubleCollection { 4, 3 },
                RadiusX = 8, RadiusY = 8
            });

            grid.Children.Add(new PackIcon
            {
                Kind = PackIconKind.Plus,
                Width = 40, Height = 40,
                Foreground = (Brush)FindResource("TextFaint"),
                HorizontalAlignment = HorizontalAlignment.Center,
                VerticalAlignment = VerticalAlignment.Center
            });

            grid.Children.Add(new TextBlock
            {
                Text = "Create Filter",
                FontSize = 12,
                FontWeight = FontWeights.SemiBold,
                Foreground = (Brush)FindResource("TextPrimary"),
                HorizontalAlignment = HorizontalAlignment.Left,
                VerticalAlignment = VerticalAlignment.Bottom,
                Margin = new Thickness(12, 0, 0, 12)
            });

            border.Child = grid;
            return border;
        }

        // ── Shared card-chunk builders ──
        private Border BuildCardHeader(Color a, Color b, bool isActive, FilterAction action,
            bool isUserFilter, UserFilter userFilter)
        {
            var header = new Border
            {
                Height = 112,
                CornerRadius = new CornerRadius(8, 8, 0, 0),
                Background = new LinearGradientBrush(a, b, 45)
            };
            var grid = new Grid();

            // Centered controller placeholder (no cover art — no IGDB integration)
            grid.Children.Add(new PackIcon
            {
                Kind = PackIconKind.ControllerClassicOutline,
                Width = 32, Height = 32,
                Opacity = 0.3,
                Foreground = Brushes.White,
                HorizontalAlignment = HorizontalAlignment.Center,
                VerticalAlignment = VerticalAlignment.Center
            });

            // Active badge (Highlight/Discard)
            if (isActive)
            {
                var badge = new Border
                {
                    Background = action == FilterAction.Discard
                        ? new SolidColorBrush(Color.FromArgb(0xCC, 0xDC, 0x26, 0x26))
                        : new SolidColorBrush(Color.FromArgb(0xCC, 0x16, 0xA3, 0x4A)),
                    CornerRadius = new CornerRadius(3),
                    Padding = new Thickness(6, 2, 6, 2),
                    HorizontalAlignment = HorizontalAlignment.Left,
                    VerticalAlignment = VerticalAlignment.Top,
                    Margin = new Thickness(6, 6, 0, 0),
                    MaxWidth = 180
                };
                var badgeStack = new StackPanel { Orientation = Orientation.Vertical };
                badgeStack.Children.Add(new TextBlock
                {
                    Text = action == FilterAction.Discard ? "DISCARD" : "HIGHLIGHT",
                    FontSize = 8, FontWeight = FontWeights.Bold,
                    Foreground = Brushes.White
                });
                badgeStack.Children.Add(new TextBlock
                {
                    Text = action == FilterAction.Discard
                        ? "Matching packets dropped"
                        : "Matched packets highlighted in Filtered Traffic",
                    FontSize = 8,
                    Foreground = new SolidColorBrush(Color.FromArgb(0xCC, 0xFF, 0xFF, 0xFF)),
                    MaxWidth = 160,
                    TextWrapping = TextWrapping.Wrap,
                    Margin = new Thickness(0, 1, 0, 0)
                });
                badge.Child = badgeStack;
                grid.Children.Add(badge);
            }

            // Thumbs (stub counter)
            var thumbs = new Border
            {
                Background = new SolidColorBrush(Color.FromArgb(0x66, 0x00, 0x00, 0x00)),
                CornerRadius = new CornerRadius(8),
                Padding = new Thickness(6, 2, 6, 2),
                HorizontalAlignment = HorizontalAlignment.Right,
                VerticalAlignment = VerticalAlignment.Top,
                Margin = new Thickness(0, 6, 6, 0)
            };
            var thumbsRow = new StackPanel { Orientation = Orientation.Horizontal };
            thumbsRow.Children.Add(new PackIcon
            {
                Kind = PackIconKind.ThumbUpOutline,
                Width = 10, Height = 10,
                Foreground = Brushes.White,
                VerticalAlignment = VerticalAlignment.Center,
                Margin = new Thickness(0, 0, 3, 0)
            });
            thumbsRow.Children.Add(new TextBlock
            {
                Text = "0",
                FontSize = 9, FontWeight = FontWeights.Bold,
                Foreground = Brushes.White,
                VerticalAlignment = VerticalAlignment.Center
            });
            thumbs.Child = thumbsRow;
            grid.Children.Add(thumbs);

            header.Child = grid;
            return header;
        }

        private void AttachUserCardActionButtons(Border header, UserFilter uf)
        {
            if (header.Child is not Grid grid) return;

            // Remove the active badge (if any) to prevent overlap — for My Filters tab,
            // the edit/delete buttons live where the badge normally goes. Cards here
            // are rendered inactive-styled anyway so there's no badge to worry about.
            var actions = new StackPanel
            {
                Orientation = Orientation.Horizontal,
                HorizontalAlignment = HorizontalAlignment.Left,
                VerticalAlignment = VerticalAlignment.Top,
                Margin = new Thickness(6, 6, 0, 0)
            };

            var editBtn = new Button
            {
                Width = 26, Height = 26, Padding = new Thickness(0),
                Margin = new Thickness(0, 0, 4, 0),
                Background = new SolidColorBrush(Color.FromRgb(0x3B, 0x82, 0xF6)),
                BorderBrush = null,
                Cursor = Cursors.Hand,
                Style = (Style)FindResource("MaterialDesignFlatButton"),
                Tag = uf.Id,
                Content = new PackIcon
                {
                    Kind = PackIconKind.PencilOutline,
                    Width = 14, Height = 14,
                    Foreground = Brushes.White
                }
            };
            ButtonAssist.SetCornerRadius(editBtn, new CornerRadius(4));
            editBtn.Click += EditUserFilter_Click;
            actions.Children.Add(editBtn);

            var delBtn = new Button
            {
                Width = 26, Height = 26, Padding = new Thickness(0),
                Background = new SolidColorBrush(Color.FromRgb(0xDC, 0x26, 0x26)),
                BorderBrush = null,
                Cursor = Cursors.Hand,
                Style = (Style)FindResource("MaterialDesignFlatButton"),
                Tag = uf.Id,
                Content = new PackIcon
                {
                    Kind = PackIconKind.TrashCanOutline,
                    Width = 14, Height = 14,
                    Foreground = Brushes.White
                }
            };
            ButtonAssist.SetCornerRadius(delBtn, new CornerRadius(4));
            delBtn.Click += DeleteUserFilter_Click;
            actions.Children.Add(delBtn);

            grid.Children.Add(actions);
        }

        private TextBlock BuildCardName(string name, int row)
        {
            var tb = new TextBlock
            {
                Text = name,
                FontSize = 13,
                FontWeight = FontWeights.SemiBold,
                Foreground = (Brush)FindResource("TextPrimary"),
                TextTrimming = TextTrimming.CharacterEllipsis,
                Margin = new Thickness(12, 10, 12, 0)
            };
            Grid.SetRow(tb, row);
            return tb;
        }

        private TextBlock BuildCardAuthor(string author, string filterType, int row)
        {
            var tb = new TextBlock
            {
                FontSize = 10,
                Foreground = (Brush)FindResource("TextMuted"),
                Margin = new Thickness(12, 2, 12, 4),
                Text = $"by {author} · Filter Type: {filterType}"
            };
            Grid.SetRow(tb, row);
            return tb;
        }

        private Border BuildPlatformPill(FilterPlatform p)
        {
            var pill = new Border
            {
                Background = PlatformBrush(p),
                CornerRadius = new CornerRadius(10),
                Padding = new Thickness(7, 1, 7, 1),
                Margin = new Thickness(0, 0, 4, 2)
            };
            pill.Child = new TextBlock
            {
                Text = PlatformLabel(p),
                FontSize = 9,
                FontWeight = FontWeights.Bold,
                Foreground = Brushes.White
            };
            return pill;
        }

        // ── Card click handlers ────────────────────────────────────────────
        private void PresetCard_Click(object sender, MouseButtonEventArgs e)
        {
            // Ignore bubbled clicks from buttons inside the card
            if (e.OriginalSource is Button) return;
            if (sender is not Border b || b.Tag is not FilterPreset preset) return;
            var meta = FilterRegistry.Get(preset);
            if (meta.Preset == FilterPreset.None) return;
            if (_host == null) return;

            var active = Globals.Settings.ActiveGameFilters ??= new List<FilterPreset>();
            var actions = Globals.Settings.FilterActions ??= new Dictionary<FilterPreset, FilterAction>();
            bool isActive = active.Contains(preset);
            FilterAction currentAction = actions.TryGetValue(preset, out var a) ? a : FilterAction.Highlight;

            _host.ShowFilterActionDialog(meta.DisplayName, isActive, currentAction, result =>
            {
                switch (result)
                {
                    case string cmd when cmd == "remove":
                        active.RemoveAll(p => p == preset);
                        actions.Remove(preset);
                        break;
                    case FilterAction act:
                        if (!active.Contains(preset)) active.Add(preset);
                        actions[preset] = act;
                        Globals.Settings.Filter = FilterPreset.None;
                        break;
                    default:
                        return; // cancelled
                }
                SaveSettings();
                RenderCards();
            });
        }

        private void UserCard_Click(object sender, MouseButtonEventArgs e)
        {
            if (e.OriginalSource is Button) return;
            if (sender is not Border b || b.Tag is not Guid id) return;
            var uf = (Globals.Settings.UserFilters ?? new List<UserFilter>())
                .FirstOrDefault(x => x.Id == id);
            if (uf == null || _host == null) return;

            _host.ShowFilterActionDialog(uf.Name, uf.IsActive, uf.Action, result =>
            {
                switch (result)
                {
                    case string cmd when cmd == "remove":
                        uf.IsActive = false;
                        break;
                    case FilterAction act:
                        uf.Action = act;
                        uf.IsActive = true;
                        break;
                    default:
                        return;
                }
                SaveSettings();
                RenderCards();
            });
        }

        private void CreateFilterCard_Click(object sender, MouseButtonEventArgs e)
        {
            _host?.ShowCreateFilterWizard(null, result =>
            {
                if (result == null) return;
                var list = Globals.Settings.UserFilters ??= new List<UserFilter>();
                list.Add(result);
                SaveSettings();
                RenderCards();
            });
        }

        private void EditUserFilter_Click(object sender, RoutedEventArgs e)
        {
            if (sender is not Button b || b.Tag is not Guid id) return;
            var list = Globals.Settings.UserFilters ??= new List<UserFilter>();
            var uf = list.FirstOrDefault(x => x.Id == id);
            if (uf == null) return;

            _host?.ShowCreateFilterWizard(uf, result =>
            {
                if (result == null) return;
                result.Id = uf.Id;
                result.IsActive = uf.IsActive;
                result.CreatedAt = uf.CreatedAt;
                var idx = list.IndexOf(uf);
                if (idx >= 0) list[idx] = result;
                SaveSettings();
                RenderCards();
            });
        }

        private void DeleteUserFilter_Click(object sender, RoutedEventArgs e)
        {
            if (sender is not Button b || b.Tag is not Guid id) return;
            var list = Globals.Settings.UserFilters ??= new List<UserFilter>();
            list.RemoveAll(x => x.Id == id);
            SaveSettings();
            RenderCards();
        }

        // Highlight/Discard/Remove dialog is now a dedicated UserControl
        // (Windows/FilterActionDialog.xaml) hosted in MainWindow.FilterModalRoot
        // via MainWindow.ShowFilterActionDialog(). See PresetCard_Click /
        // UserCard_Click above for call sites.


        // ── Packet-type / misc toggles ─────────────────────────────────────────
        private void PacketTypeToggle_Changed(object sender, RoutedEventArgs e)
        {
            if (ShowUdpToggle == null || ShowTcpToggle == null) return;
            Globals.Settings.ShowUdpPackets = ShowUdpToggle.IsChecked == true;
            Globals.Settings.ShowTcpPackets = ShowTcpToggle.IsChecked == true;
            SaveSettings();
        }

        private void OtherInfoToggle_Changed(object sender, RoutedEventArgs e)
        {
            var show = OtherInfoToggle.IsChecked == true;
            Globals.Settings.ShowOtherInfoTab = show;
            _host.SetAllTrafficTabVisibility(show);
            SaveSettings();
        }

        // ── Port blacklist ─────────────────────────────────────────────────────
        private void AddPort_Click(object sender, RoutedEventArgs e) => AddPortFromInput();

        private void PortInput_KeyDown(object sender, KeyEventArgs e)
        {
            if (e.Key == Key.Enter) AddPortFromInput();
        }

        private void AddPortFromInput()
        {
            if (!ushort.TryParse(PortInput.Text?.Trim(), out var port) || port == 0) return;
            if (_portBoxSource.Contains(port)) { PortInput.Text = ""; return; }
            _portBoxSource.Add(port);
            PortInput.Text = "";
            SaveSettings();
        }

        private void DeletePortItem_Click(object sender, RoutedEventArgs e)
        {
            if (PortListBox.SelectedItem == null) return;
            _portBoxSource.Remove(Convert.ToUInt16(PortListBox.SelectedItem));
            SaveSettings();
        }

        private void CopyPortItem_Click(object sender, RoutedEventArgs e)
        {
            if (PortListBox.SelectedItem != null)
                PortListBox.SelectedItem.ToString().CopyToClipboard();
        }

        // ── Custom port-range filters (legacy — unchanged) ─────────────────────
        private void AddCustomFilter_Click(object sender, RoutedEventArgs e)
        {
            var name = CustomNameBox.Text?.Trim();
            if (string.IsNullOrEmpty(name)) return;
            if (!ushort.TryParse(CustomMinPortBox.Text, out var min)) return;
            if (!ushort.TryParse(CustomMaxPortBox.Text, out var max)) return;
            if (min > max) return;

            var cf = new CustomFilter { Name = name, MinPort = min, MaxPort = max, UdpOnly = true };
            _customFilterSource.Add(cf);
            Globals.Settings.CustomFilters.Add(cf);
            SaveSettings();

            CustomNameBox.Text = CustomMinPortBox.Text = CustomMaxPortBox.Text = "";
        }

        private void DeleteCustomFilter_Click(object sender, RoutedEventArgs e)
        {
            if (CustomFilterListBox.SelectedItem is not CustomFilter cf) return;
            _customFilterSource.Remove(cf);
            Globals.Settings.CustomFilters.Remove(cf);
            SaveSettings();
        }

        // ── Helpers ────────────────────────────────────────────────────────────
        private static FilterAction GetAction(FilterPreset preset)
        {
            return Globals.Settings.FilterActions.TryGetValue(preset, out var a) ? a : FilterAction.Highlight;
        }

        private static string CategoryLabel(FilterCategory c) => c switch
        {
            FilterCategory.Server => "Server",
            FilterCategory.P2P => "P2P",
            FilterCategory.Universal => "Universal",
            _ => "N/A"
        };

        private static string PlatformLabel(FilterPlatform p) => p switch
        {
            FilterPlatform.Xbox => "Xbox",
            FilterPlatform.PC => "PC",
            FilterPlatform.PlayStation => "PlayStation",
            FilterPlatform.Android => "Android",
            FilterPlatform.iOS => "iOS",
            FilterPlatform.Mobile => "Mobile",
            FilterPlatform.Server => "Server",
            FilterPlatform.PS3 => "PS3",
            FilterPlatform.PS4 => "PS4",
            FilterPlatform.PS5 => "PS5",
            FilterPlatform.Xbox360 => "Xbox 360",
            FilterPlatform.XboxOne => "Xbox One",
            FilterPlatform.XboxSeriesX => "Xbox Series X",
            _ => "Universal"
        };

        private Brush PlatformBrush(FilterPlatform p) => p switch
        {
            FilterPlatform.Xbox or FilterPlatform.Xbox360 or FilterPlatform.XboxOne or FilterPlatform.XboxSeriesX
                => (Brush)FindResource("PlatformXbox"),
            FilterPlatform.PC => (Brush)FindResource("PlatformPC"),
            FilterPlatform.PlayStation or FilterPlatform.PS3 or FilterPlatform.PS4 or FilterPlatform.PS5
                => (Brush)FindResource("PlatformPSN"),
            FilterPlatform.Android => (Brush)FindResource("PlatformAndroid"),
            FilterPlatform.iOS => (Brush)FindResource("PlatformIOS"),
            FilterPlatform.Mobile => (Brush)FindResource("PlatformMobile"),
            FilterPlatform.Server => (Brush)FindResource("PlatformServer"),
            _ => (Brush)FindResource("PlatformUniversal")
        };

        private static Color ColorFromHex(string hex)
        {
            try { return (Color)ColorConverter.ConvertFromString(hex); }
            catch { return Colors.Black; }
        }

        private async void SaveSettings()
        {
            if (_saving) return;
            _saving = true;
            try
            {
                Globals.Settings.PortsInverse = InvertPortFilterToggle.IsChecked == true;
                Globals.Settings.Ports = _portBoxSource.ToList();
                await Globals.Container.GetInstance<IServerSettings>().UpdateSettingsAsync();
            }
            finally { _saving = false; }
        }
    }
}
