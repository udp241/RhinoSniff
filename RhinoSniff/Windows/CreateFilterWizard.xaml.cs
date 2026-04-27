using System;
using System.Collections.Generic;
using System.Linq;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;
using MaterialDesignThemes.Wpf;
using RhinoSniff.Models;

namespace RhinoSniff.Windows
{
    /// <summary>
    /// 3-step modal wizard for creating user-defined filters (My Filters).
    /// Raised by PacketFilters → MainWindow.ShowCreateFilterWizard. Writes to
    /// <see cref="RhinoSniff.Models.Settings.UserFilters"/> via the CreatedFilter property
    /// and fires <see cref="Completed"/> to let the host close the overlay and refresh cards.
    /// </summary>
    public partial class CreateFilterWizard : UserControl
    {
        // ── State ───────────────────────────────────────────────────────────
        private UserFilterSource _source = UserFilterSource.Local;
        private FilterAction _action = FilterAction.Highlight;
        private int _step = 0; // 0 = Source chooser, 1 = Form, 2 = Action, 3 = Review

        // Local form chip lists
        private readonly List<string> _localIps = new();
        private readonly List<string> _localCountries = new();
        private readonly List<string> _localIsps = new();
        private readonly List<string> _localBytes = new();

        // Cloud form chip lists
        private readonly List<string> _cloudTitleIds = new();
        private readonly List<string> _cloudBytes = new();

        /// <summary>The finished filter, or null if the user dismissed. Read by the host after <see cref="Completed"/>.</summary>
        public UserFilter CreatedFilter { get; private set; }

        /// <summary>Fires when user presses Create on Step 3. Host closes the overlay.</summary>
        public event EventHandler Completed;

        /// <summary>Fires when user presses Cancel / X / clicks outside. Host closes the overlay.</summary>
        public event EventHandler Cancelled;

        public CreateFilterWizard(UserFilter editExisting = null)
        {
            InitializeComponent();

            // Edit mode: pre-fill from existing filter (future use — current PacketFilters.cs
            // edit button will send an existing UserFilter; creating from scratch passes null).
            if (editExisting != null) PrefillFromExisting(editExisting);

            UpdateStepUI();
        }

        // ── Step 1a: Source chooser ─────────────────────────────────────────
        private void SourceLocal_Click(object sender, MouseButtonEventArgs e)
        {
            _source = UserFilterSource.Local;
            HighlightSourceCard(local: true);
            // Auto-advance: one-click selection.
            _step = 1;
            UpdateStepUI();
        }

        private void SourceCloud_Click(object sender, MouseButtonEventArgs e)
        {
            _source = UserFilterSource.Cloud;
            HighlightSourceCard(local: false);
            _step = 1;
            UpdateStepUI();
        }

        private void HighlightSourceCard(bool local)
        {
            SourceLocalBtn.BorderBrush = local
                ? new SolidColorBrush(Color.FromRgb(0x81, 0x8C, 0xF8))
                : (Brush)FindResource("CardBorder");
            SourceLocalBtn.BorderThickness = new Thickness(local ? 2 : 1);

            SourceCloudBtn.BorderBrush = !local
                ? new SolidColorBrush(Color.FromRgb(0x34, 0xD3, 0x99))
                : (Brush)FindResource("CardBorder");
            SourceCloudBtn.BorderThickness = new Thickness(!local ? 2 : 1);
        }

        // ── Step 1b Local: input field handlers ─────────────────────────────
        private void LocalIp_KeyDown(object sender, KeyEventArgs e)
        { if (e.Key == Key.Enter) AddLocalIp_Click(sender, e); }

        private void AddLocalIp_Click(object sender, RoutedEventArgs e)
        {
            var v = LocalIpInput.Text?.Trim();
            if (!string.IsNullOrWhiteSpace(v) && !_localIps.Contains(v, StringComparer.OrdinalIgnoreCase))
            {
                _localIps.Add(v);
                RenderChips(LocalIpChips, _localIps, RemoveLocalIp);
            }
            LocalIpInput.Text = "";
        }

        private void RemoveLocalIp(string v)
        {
            _localIps.RemoveAll(s => string.Equals(s, v, StringComparison.OrdinalIgnoreCase));
            RenderChips(LocalIpChips, _localIps, RemoveLocalIp);
        }

        private void LocalCountry_KeyDown(object sender, KeyEventArgs e)
        { if (e.Key == Key.Enter) AddLocalCountry_Click(sender, e); }

        private void AddLocalCountry_Click(object sender, RoutedEventArgs e)
        {
            var v = LocalCountryInput.Text?.Trim().ToUpperInvariant();
            if (string.IsNullOrWhiteSpace(v) || v.Length != 2 || !v.All(char.IsLetter)) { LocalCountryInput.Text = ""; return; }
            if (!_localCountries.Contains(v))
            {
                _localCountries.Add(v);
                RenderChips(LocalCountryChips, _localCountries, RemoveLocalCountry);
            }
            LocalCountryInput.Text = "";
        }

        private void RemoveLocalCountry(string v)
        {
            _localCountries.Remove(v);
            RenderChips(LocalCountryChips, _localCountries, RemoveLocalCountry);
        }

        private void LocalIsp_KeyDown(object sender, KeyEventArgs e)
        { if (e.Key == Key.Enter) AddLocalIsp_Click(sender, e); }

        private void AddLocalIsp_Click(object sender, RoutedEventArgs e)
        {
            var v = LocalIspInput.Text?.Trim();
            if (!string.IsNullOrWhiteSpace(v) && !_localIsps.Contains(v, StringComparer.OrdinalIgnoreCase))
            {
                _localIsps.Add(v);
                RenderChips(LocalIspChips, _localIsps, RemoveLocalIsp);
            }
            LocalIspInput.Text = "";
        }

        private void RemoveLocalIsp(string v)
        {
            _localIsps.RemoveAll(s => string.Equals(s, v, StringComparison.OrdinalIgnoreCase));
            RenderChips(LocalIspChips, _localIsps, RemoveLocalIsp);
        }

        private void LocalBytes_KeyDown(object sender, KeyEventArgs e)
        { if (e.Key == Key.Enter) AddLocalBytes_Click(sender, e); }

        private void AddLocalBytes_Click(object sender, RoutedEventArgs e)
        {
            AddBytesPatterns(LocalBytesInput, _localBytes, LocalBytesChips, RemoveLocalBytes);
        }

        private void RemoveLocalBytes(string v)
        {
            _localBytes.RemoveAll(s => string.Equals(s, v, StringComparison.OrdinalIgnoreCase));
            RenderChips(LocalBytesChips, _localBytes, RemoveLocalBytes);
        }

        // ── Step 1b Cloud: input field handlers ─────────────────────────────
        private void CloudTitleId_KeyDown(object sender, KeyEventArgs e)
        { if (e.Key == Key.Enter) AddCloudTitleId_Click(sender, e); }

        private void AddCloudTitleId_Click(object sender, RoutedEventArgs e)
        {
            var v = CloudTitleIdInput.Text?.Trim();
            if (!string.IsNullOrWhiteSpace(v) && _cloudTitleIds.Count < 10
                && !_cloudTitleIds.Contains(v, StringComparer.OrdinalIgnoreCase))
            {
                _cloudTitleIds.Add(v);
                RenderChips(CloudTitleIdChips, _cloudTitleIds, RemoveCloudTitleId);
            }
            CloudTitleIdInput.Text = "";
        }

        private void RemoveCloudTitleId(string v)
        {
            _cloudTitleIds.RemoveAll(s => string.Equals(s, v, StringComparison.OrdinalIgnoreCase));
            RenderChips(CloudTitleIdChips, _cloudTitleIds, RemoveCloudTitleId);
        }

        private void CloudBytes_KeyDown(object sender, KeyEventArgs e)
        { if (e.Key == Key.Enter) AddCloudBytes_Click(sender, e); }

        private void AddCloudBytes_Click(object sender, RoutedEventArgs e)
        {
            AddBytesPatterns(CloudBytesInput, _cloudBytes, CloudBytesChips, RemoveCloudBytes);
        }

        private void RemoveCloudBytes(string v)
        {
            _cloudBytes.RemoveAll(s => string.Equals(s, v, StringComparison.OrdinalIgnoreCase));
            RenderChips(CloudBytesChips, _cloudBytes, RemoveCloudBytes);
        }

        /// <summary>
        /// Shared bytes-pattern add helper. Accepts comma-separated patterns,
        /// strips whitespace between bytes, and rejects anything not pure hex.
        /// Comma-separated patterns: "FF FF FF, AB CD 01" → two patterns.
        /// </summary>
        private void AddBytesPatterns(TextBox input, List<string> list, WrapPanel chipsHost, Action<string> onRemove)
        {
            var raw = input.Text?.Trim();
            if (string.IsNullOrWhiteSpace(raw)) { input.Text = ""; return; }

            foreach (var part in raw.Split(','))
            {
                var hex = new string(part.Where(c => !char.IsWhiteSpace(c)).ToArray()).ToUpperInvariant();
                if (string.IsNullOrWhiteSpace(hex)) continue;
                if (hex.Length % 2 != 0) continue;
                if (!hex.All(c => (c >= '0' && c <= '9') || (c >= 'A' && c <= 'F'))) continue;
                if (!list.Contains(hex))
                    list.Add(hex);
            }

            RenderChips(chipsHost, list, onRemove);
            input.Text = "";
        }

        // ── Chip rendering (shared) ─────────────────────────────────────────
        private void RenderChips(WrapPanel host, List<string> source, Action<string> onRemove)
        {
            host.Children.Clear();
            foreach (var s in source)
            {
                var chip = new Border
                {
                    Background = (Brush)FindResource("InputBg"),
                    BorderBrush = (Brush)FindResource("Divider"),
                    BorderThickness = new Thickness(1),
                    CornerRadius = new CornerRadius(12),
                    Padding = new Thickness(8, 2, 4, 2),
                    Margin = new Thickness(0, 0, 6, 4)
                };
                var row = new StackPanel { Orientation = Orientation.Horizontal };
                row.Children.Add(new TextBlock
                {
                    Text = s,
                    FontSize = 11,
                    VerticalAlignment = VerticalAlignment.Center,
                    Foreground = (Brush)FindResource("TextPrimary"),
                    Margin = new Thickness(0, 0, 4, 0)
                });
                var xBtn = new Button
                {
                    Content = new PackIcon
                    {
                        Kind = PackIconKind.Close,
                        Width = 10, Height = 10,
                        Foreground = (Brush)FindResource("TextMuted")
                    },
                    Background = Brushes.Transparent,
                    BorderBrush = null,
                    Padding = new Thickness(2),
                    Width = 18, Height = 18,
                    Cursor = Cursors.Hand,
                    Style = (Style)FindResource("MaterialDesignFlatButton")
                };
                var captured = s;
                xBtn.Click += (_, _) => onRemove(captured);
                row.Children.Add(xBtn);
                chip.Child = row;
                host.Children.Add(chip);
            }
        }

        // ── Step 2: Action ──────────────────────────────────────────────────
        private void ActionHighlight_Click(object sender, MouseButtonEventArgs e)
        {
            _action = FilterAction.Highlight;
            HighlightActionCard();
        }

        private void ActionDiscard_Click(object sender, MouseButtonEventArgs e)
        {
            _action = FilterAction.Discard;
            HighlightActionCard();
        }

        private void HighlightActionCard()
        {
            var isHighlight = _action == FilterAction.Highlight;
            ActionHighlightBtn.BorderBrush = isHighlight
                ? new SolidColorBrush(Color.FromRgb(0x3B, 0x82, 0xF6))
                : (Brush)FindResource("CardBorder");
            ActionHighlightBtn.BorderThickness = new Thickness(isHighlight ? 2 : 1);

            ActionDiscardBtn.BorderBrush = !isHighlight
                ? new SolidColorBrush(Color.FromRgb(0x3B, 0x82, 0xF6))
                : (Brush)FindResource("CardBorder");
            ActionDiscardBtn.BorderThickness = new Thickness(!isHighlight ? 2 : 1);
        }

        // ── Navigation ──────────────────────────────────────────────────────
        private void Next_Click(object sender, RoutedEventArgs e)
        {
            // Validate before advancing.
            if (_step == 1)
            {
                if (_source == UserFilterSource.Local)
                {
                    if (string.IsNullOrWhiteSpace(LocalNameBox.Text))
                    {
                        Shake(LocalNameBox);
                        return;
                    }
                }
                else // Cloud
                {
                    if (string.IsNullOrWhiteSpace(CloudNameBox.Text))
                    {
                        Shake(CloudNameBox);
                        return;
                    }
                    if (_cloudBytes.Count == 0)
                    {
                        // Cloud requires at least one bytes pattern
                        Shake(CloudBytesInput);
                        return;
                    }
                    if (CountSelectedPlatforms() == 0)
                    {
                        PlatformsError.Visibility = Visibility.Visible;
                        return;
                    }
                    PlatformsError.Visibility = Visibility.Collapsed;
                }
            }

            _step++;
            if (_step == 3) BuildReview();
            UpdateStepUI();
        }

        private void Back_Click(object sender, RoutedEventArgs e)
        {
            if (_step == 0) return;
            _step--;
            UpdateStepUI();
        }

        private void Close_Click(object sender, RoutedEventArgs e) => Cancelled?.Invoke(this, EventArgs.Empty);

        private void Create_Click(object sender, RoutedEventArgs e)
        {
            CreatedFilter = BuildFilter();
            Completed?.Invoke(this, EventArgs.Empty);
        }

        // Red-flash a field that failed validation so the user sees it.
        private void Shake(Control c)
        {
            var orig = c.BorderBrush;
            c.BorderBrush = (Brush)FindResource("StatusDanger");
            Dispatcher.BeginInvoke(new Action(() =>
            {
                System.Threading.Tasks.Task.Delay(1200).ContinueWith(_ =>
                    Dispatcher.BeginInvoke(new Action(() => c.BorderBrush = orig)));
            }));
        }

        // ── UI state driver ─────────────────────────────────────────────────
        private void UpdateStepUI()
        {
            // Visibility of each panel
            PanelStep1a.Visibility = (_step == 0) ? Visibility.Visible : Visibility.Collapsed;
            PanelStep1bLocal.Visibility = (_step == 1 && _source == UserFilterSource.Local) ? Visibility.Visible : Visibility.Collapsed;
            PanelStep1bCloud.Visibility = (_step == 1 && _source == UserFilterSource.Cloud) ? Visibility.Visible : Visibility.Collapsed;
            PanelStep2.Visibility = (_step == 2) ? Visibility.Visible : Visibility.Collapsed;
            PanelStep3.Visibility = (_step == 3) ? Visibility.Visible : Visibility.Collapsed;

            // Step-indicator dots: dot at current + prior steps is filled, later steps are outlined.
            // Map wizard steps 0..3 -> UI dots 1..3: step 0 = dot 1 (source), step 1 = dot 1 (form),
            // step 2 = dot 2, step 3 = dot 3.
            var uiDot = _step switch { 0 => 1, 1 => 1, 2 => 2, _ => 3 };
            SetDot(StepDot1, uiDot >= 1);
            SetDot(StepDot2, uiDot >= 2);
            SetDot(StepDot3, uiDot >= 3);
            StepLine1.Fill = uiDot >= 2 ? (Brush)FindResource("AccentTealDark") : (Brush)FindResource("Divider");
            StepLine2.Fill = uiDot >= 3 ? (Brush)FindResource("AccentTealDark") : (Brush)FindResource("Divider");

            // Footer buttons: Back visible on steps 1..3, Cancel visible only on step 0.
            CancelBtn.Visibility = (_step == 0) ? Visibility.Visible : Visibility.Collapsed;
            BackBtn.Visibility = (_step >= 1) ? Visibility.Visible : Visibility.Collapsed;
            NextBtn.Visibility = (_step is 1 or 2) ? Visibility.Visible : Visibility.Collapsed;
            CreateBtn.Visibility = (_step == 3) ? Visibility.Visible : Visibility.Collapsed;
        }

        private void SetDot(Border dot, bool filled)
        {
            if (filled)
            {
                dot.Background = (Brush)FindResource("AccentTealDark");
                dot.BorderBrush = (Brush)FindResource("AccentTealDark");
                if (dot.Child is TextBlock tb) tb.Foreground = (Brush)FindResource("TextOnAccent");
            }
            else
            {
                dot.Background = (Brush)FindResource("InputBg");
                dot.BorderBrush = (Brush)FindResource("Divider");
                if (dot.Child is TextBlock tb) tb.Foreground = (Brush)FindResource("TextMuted");
            }
        }

        // ── Step 3: Review panel ────────────────────────────────────────────
        private void BuildReview()
        {
            ReviewPanel.Children.Clear();
            var f = BuildFilter();

            AddReviewRow("Source", f.Source == UserFilterSource.Local ? "Local Filter" : "Cloud Filter");
            AddReviewRow("Filter Name", string.IsNullOrWhiteSpace(f.Name) ? "—" : f.Name);
            AddReviewRow("Action", f.Action.ToString());
            AddReviewRow("Protocol", f.Protocol switch
            {
                FilterProtocol.Tcp => "TCP",
                FilterProtocol.Udp => "UDP",
                _ => "BOTH"
            });

            if (f.Source == UserFilterSource.Cloud)
            {
                AddReviewRow("Bytes Pattern (Hex)", f.BytesPatternsHex.Count switch
                {
                    0 => "—",
                    1 => "1 pattern",
                    var n => $"{n} patterns"
                });
                AddReviewRow("Share with community", f.ShareWithCommunity ? "Yes" : "—");
            }
            else
            {
                if (f.IpCidrs.Count > 0)
                    AddReviewRow("IP / CIDR", $"{f.IpCidrs.Count} entr{(f.IpCidrs.Count == 1 ? "y" : "ies")}");
                if (f.Countries.Count > 0)
                    AddReviewRow("Country", string.Join(", ", f.Countries));
                if (f.Isps.Count > 0)
                    AddReviewRow("ISP", $"{f.Isps.Count} entr{(f.Isps.Count == 1 ? "y" : "ies")}");
                if (f.BytesPatternsHex.Count > 0)
                    AddReviewRow("Bytes Pattern (Hex)", f.BytesPatternsHex.Count == 1 ? "1 pattern" : $"{f.BytesPatternsHex.Count} patterns");
            }
        }

        private void AddReviewRow(string label, string value)
        {
            var g = new Grid { Margin = new Thickness(0, 3, 0, 3) };
            g.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
            g.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
            g.Children.Add(new TextBlock
            {
                Text = label, FontSize = 11,
                Foreground = (Brush)FindResource("TextMuted"),
                HorizontalAlignment = HorizontalAlignment.Left
            });
            var right = new TextBlock
            {
                Text = value, FontSize = 11, FontWeight = FontWeights.SemiBold,
                Foreground = (Brush)FindResource("TextPrimary"),
                HorizontalAlignment = HorizontalAlignment.Right
            };
            Grid.SetColumn(right, 1);
            g.Children.Add(right);
            ReviewPanel.Children.Add(g);
        }

        // ── Final object construction ───────────────────────────────────────
        private UserFilter BuildFilter()
        {
            var f = new UserFilter
            {
                Source = _source,
                Action = _action,
                IsActive = false // User activates from the card, not the wizard
            };

            if (_source == UserFilterSource.Local)
            {
                f.Name = LocalNameBox.Text?.Trim() ?? "";
                f.Protocol = ProtocolFromCombo(LocalProtocolBox);
                f.IpCidrs = new List<string>(_localIps);
                f.Countries = new List<string>(_localCountries);
                f.Isps = new List<string>(_localIsps);
                f.BytesPatternsHex = new List<string>(_localBytes);
                f.PortStart = ParseIntOrDefault(LocalPortStart.Text, 0, 0, 65535);
                f.PortEnd = ParseIntOrDefault(LocalPortEnd.Text, 65535, 0, 65535);
                f.LenMin = ParseIntOrDefault(LocalLenMin.Text, 0, 0, 65535);
                f.LenMax = ParseIntOrDefault(LocalLenMax.Text, 65535, 0, 65535);
            }
            else
            {
                f.GameName = CloudGameBox.Text?.Trim() ?? "";
                f.Name = CloudNameBox.Text?.Trim() ?? "";
                f.Description = CloudDescBox.Text?.Trim() ?? "";
                f.TitleIds = new List<string>(_cloudTitleIds);
                f.BytesPatternsHex = new List<string>(_cloudBytes);
                f.Protocol = ProtocolFromCombo(CloudProtocolBox);
                f.ConnectionType = ConnectionFromCombo(CloudConnectionBox);
                f.Platforms = GatherSelectedPlatforms();
                f.PortStart = ParseIntOrDefault(CloudPortStart.Text, 0, 0, 65535);
                f.PortEnd = ParseIntOrDefault(CloudPortEnd.Text, 65535, 0, 65535);
                f.LenMin = ParseIntOrDefault(CloudLenMin.Text, 0, 0, 65535);
                f.LenMax = ParseIntOrDefault(CloudLenMax.Text, 65535, 0, 65535);
                f.ShareWithCommunity = ShareWithCommunityBox.IsChecked == true;
            }

            // Ensure port/len ranges are ordered (start ≤ end).
            if (f.PortStart > f.PortEnd) (f.PortStart, f.PortEnd) = (f.PortEnd, f.PortStart);
            if (f.LenMin > f.LenMax) (f.LenMin, f.LenMax) = (f.LenMax, f.LenMin);

            return f;
        }

        // ── Helpers ─────────────────────────────────────────────────────────
        private static FilterProtocol ProtocolFromCombo(ComboBox cb)
        {
            return (cb.SelectedItem as ComboBoxItem)?.Content?.ToString() switch
            {
                "TCP" => FilterProtocol.Tcp,
                "UDP" => FilterProtocol.Udp,
                _ => FilterProtocol.Both
            };
        }

        private static UserFilterConnectionType ConnectionFromCombo(ComboBox cb)
        {
            return (cb.SelectedItem as ComboBoxItem)?.Content?.ToString() switch
            {
                "Matchmaking" => UserFilterConnectionType.Matchmaking,
                "Party" => UserFilterConnectionType.Party,
                "Session" => UserFilterConnectionType.Session,
                _ => UserFilterConnectionType.None
            };
        }

        private static int ParseIntOrDefault(string s, int fallback, int min, int max)
        {
            if (!int.TryParse(s?.Trim(), out var v)) return fallback;
            if (v < min) return min;
            if (v > max) return max;
            return v;
        }

        private int CountSelectedPlatforms()
        {
            var count = 0;
            if (PlatformPS3.IsChecked == true) count++;
            if (PlatformPS4.IsChecked == true) count++;
            if (PlatformPS5.IsChecked == true) count++;
            if (PlatformXbox360.IsChecked == true) count++;
            if (PlatformXboxOne.IsChecked == true) count++;
            if (PlatformXboxSeriesX.IsChecked == true) count++;
            if (PlatformPC.IsChecked == true) count++;
            if (PlatformMobile.IsChecked == true) count++;
            if (PlatformIOS.IsChecked == true) count++;
            if (PlatformAndroid.IsChecked == true) count++;
            if (PlatformUniversal.IsChecked == true) count++;
            return count;
        }

        private List<FilterPlatform> GatherSelectedPlatforms()
        {
            var list = new List<FilterPlatform>();
            if (PlatformPS3.IsChecked == true) list.Add(FilterPlatform.PS3);
            if (PlatformPS4.IsChecked == true) list.Add(FilterPlatform.PS4);
            if (PlatformPS5.IsChecked == true) list.Add(FilterPlatform.PS5);
            if (PlatformXbox360.IsChecked == true) list.Add(FilterPlatform.Xbox360);
            if (PlatformXboxOne.IsChecked == true) list.Add(FilterPlatform.XboxOne);
            if (PlatformXboxSeriesX.IsChecked == true) list.Add(FilterPlatform.XboxSeriesX);
            if (PlatformPC.IsChecked == true) list.Add(FilterPlatform.PC);
            if (PlatformMobile.IsChecked == true) list.Add(FilterPlatform.Mobile);
            if (PlatformIOS.IsChecked == true) list.Add(FilterPlatform.iOS);
            if (PlatformAndroid.IsChecked == true) list.Add(FilterPlatform.Android);
            if (PlatformUniversal.IsChecked == true) list.Add(FilterPlatform.Universal);
            return list;
        }

        private void PrefillFromExisting(UserFilter f)
        {
            _source = f.Source;
            _action = f.Action;

            if (f.Source == UserFilterSource.Local)
            {
                LocalNameBox.Text = f.Name;
                SelectComboByText(LocalProtocolBox, f.Protocol switch
                {
                    FilterProtocol.Tcp => "TCP",
                    FilterProtocol.Udp => "UDP",
                    _ => "BOTH"
                });
                _localIps.AddRange(f.IpCidrs);
                _localCountries.AddRange(f.Countries);
                _localIsps.AddRange(f.Isps);
                _localBytes.AddRange(f.BytesPatternsHex);
                RenderChips(LocalIpChips, _localIps, RemoveLocalIp);
                RenderChips(LocalCountryChips, _localCountries, RemoveLocalCountry);
                RenderChips(LocalIspChips, _localIsps, RemoveLocalIsp);
                RenderChips(LocalBytesChips, _localBytes, RemoveLocalBytes);
                LocalPortStart.Text = f.PortStart.ToString();
                LocalPortEnd.Text = f.PortEnd.ToString();
                LocalLenMin.Text = f.LenMin.ToString();
                LocalLenMax.Text = f.LenMax.ToString();
            }
            else
            {
                CloudGameBox.Text = f.GameName;
                CloudNameBox.Text = f.Name;
                CloudDescBox.Text = f.Description;
                _cloudTitleIds.AddRange(f.TitleIds);
                _cloudBytes.AddRange(f.BytesPatternsHex);
                RenderChips(CloudTitleIdChips, _cloudTitleIds, RemoveCloudTitleId);
                RenderChips(CloudBytesChips, _cloudBytes, RemoveCloudBytes);
                SelectComboByText(CloudProtocolBox, f.Protocol switch
                {
                    FilterProtocol.Tcp => "TCP",
                    FilterProtocol.Udp => "UDP",
                    _ => "BOTH"
                });
                SelectComboByText(CloudConnectionBox, f.ConnectionType.ToString());
                PlatformPS3.IsChecked = f.Platforms.Contains(FilterPlatform.PS3);
                PlatformPS4.IsChecked = f.Platforms.Contains(FilterPlatform.PS4);
                PlatformPS5.IsChecked = f.Platforms.Contains(FilterPlatform.PS5);
                PlatformXbox360.IsChecked = f.Platforms.Contains(FilterPlatform.Xbox360);
                PlatformXboxOne.IsChecked = f.Platforms.Contains(FilterPlatform.XboxOne);
                PlatformXboxSeriesX.IsChecked = f.Platforms.Contains(FilterPlatform.XboxSeriesX);
                PlatformPC.IsChecked = f.Platforms.Contains(FilterPlatform.PC);
                PlatformMobile.IsChecked = f.Platforms.Contains(FilterPlatform.Mobile);
                PlatformIOS.IsChecked = f.Platforms.Contains(FilterPlatform.iOS);
                PlatformAndroid.IsChecked = f.Platforms.Contains(FilterPlatform.Android);
                PlatformUniversal.IsChecked = f.Platforms.Contains(FilterPlatform.Universal);
                CloudPortStart.Text = f.PortStart.ToString();
                CloudPortEnd.Text = f.PortEnd.ToString();
                CloudLenMin.Text = f.LenMin.ToString();
                CloudLenMax.Text = f.LenMax.ToString();
                ShareWithCommunityBox.IsChecked = f.ShareWithCommunity;
            }

            // Skip the source chooser entirely in edit mode.
            _step = 1;
            HighlightSourceCard(f.Source == UserFilterSource.Local);
            HighlightActionCard();
        }

        private static void SelectComboByText(ComboBox cb, string text)
        {
            foreach (var item in cb.Items)
            {
                if (item is ComboBoxItem i && string.Equals(i.Content?.ToString(), text, StringComparison.OrdinalIgnoreCase))
                {
                    cb.SelectedItem = i;
                    return;
                }
            }
        }
    }
}
