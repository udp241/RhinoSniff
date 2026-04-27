using System;
using System.Collections.Generic;
using System.Linq;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Controls.Primitives;
using System.Windows.Input;
using System.Windows.Media;
using MaterialDesignThemes.Wpf;
using RhinoSniff.Classes;
using RhinoSniff.Models;

namespace RhinoSniff.Windows
{
    public partial class TrafficRuleWizard : UserControl
    {
        // ── Wizard state ──────────────────────────────────────────────────
        private enum WizardStep { ModeSelect, TargetCustom, TargetFilter, Action, Settings, Review }
        private WizardStep _step = WizardStep.ModeSelect;
        private bool _modeCustom = true; // true = Custom, false = Filters

        // ── Rule being built ──────────────────────────────────────────────
        private TrafficTargetMode _targetMode = TrafficTargetMode.AllTraffic;
        private readonly List<string> _targetIPs = new();
        private FilterPreset _selectedFilter = FilterPreset.None;
        private TrafficProtocol _protocol = TrafficProtocol.Any;
        private TrafficDirection _direction = TrafficDirection.Both;
        private readonly List<PortEntry> _ports = new();
        private TrafficAction _action = TrafficAction.Drop;

        // ── Edit mode ─────────────────────────────────────────────────────
        private readonly TrafficRule _editSource;

        /// <summary>The rule produced by the wizard. Null if cancelled or closed.</summary>
        public TrafficRule CreatedRule { get; private set; }

        /// <summary>
        /// Fired when the wizard finishes (Create) or is dismissed (Cancel/X/Esc).
        /// The host should remove this control and hide the modal backdrop in response.
        /// CreatedRule is non-null only on successful creation.
        /// </summary>
        public event EventHandler Completed;

        // ── Filter tab state ──────────────────────────────────────────────
        // Removed Official/Mine distinction — RhinoSniff has no community filter system.
        // All filters (built-in FilterRegistry presets + user CustomFilters) live under My Filters.

        // ══════════════════════════════════════════════════════════════════
        // Constructor
        // ══════════════════════════════════════════════════════════════════

        public TrafficRuleWizard(TrafficRule editRule = null)
        {
            _editSource = editRule;
            InitializeComponent();
            InitSegmentedBars();
            InitActionCards();
            ApplyModeBorderStyle();

            if (_editSource != null) PreFillFromRule(_editSource);
            ShowStep(_step);
        }

        private void PreFillFromRule(TrafficRule r)
        {
            _targetMode = r.TargetMode;
            _targetIPs.Clear();
            _targetIPs.AddRange(r.TargetIPs ?? new List<string>());
            _selectedFilter = r.FilterPreset;
            _protocol = r.Protocol;
            _direction = r.Direction;
            _ports.Clear();
            _ports.AddRange(r.Ports ?? new List<PortEntry>());
            _action = r.Action;

            ProbSlider.Value = r.Probability;
            BurstToggle.IsChecked = r.BurstEnabled;
            BurstOnSlider.Value = r.BurstOnMs;
            BurstOffSlider.Value = r.BurstOffMs;
            DelaySlider.Value = r.DelayMs;
            JitterSlider.Value = r.JitterMs;
            RateSlider.Value = r.RateKbps;
            ReorderPctSlider.Value = r.ReorderPercent;
            ReorderWinSlider.Value = r.ReorderWindowMs;
            DupPctSlider.Value = r.DuplicatePercent;
            DupDelaySlider.Value = r.DuplicateDelayMs;

            _modeCustom = r.TargetMode != TrafficTargetMode.Filter;

            // Skip mode selection — go straight to target
            _step = _modeCustom ? WizardStep.TargetCustom : WizardStep.TargetFilter;
        }

        // ══════════════════════════════════════════════════════════════════
        // Step Navigation
        // ══════════════════════════════════════════════════════════════════

        private void ShowStep(WizardStep step)
        {
            _step = step;
            PanelModeSelect.Visibility = step == WizardStep.ModeSelect ? Visibility.Visible : Visibility.Collapsed;
            PanelTargetCustom.Visibility = step == WizardStep.TargetCustom ? Visibility.Visible : Visibility.Collapsed;
            PanelTargetFilter.Visibility = step == WizardStep.TargetFilter ? Visibility.Visible : Visibility.Collapsed;
            PanelAction.Visibility = step == WizardStep.Action ? Visibility.Visible : Visibility.Collapsed;
            PanelSettings.Visibility = step == WizardStep.Settings ? Visibility.Visible : Visibility.Collapsed;
            PanelReview.Visibility = step == WizardStep.Review ? Visibility.Visible : Visibility.Collapsed;

            // Footer buttons
            BackBtn.Visibility = step != WizardStep.ModeSelect ? Visibility.Visible : Visibility.Collapsed;
            NextBtn.Visibility = step != WizardStep.ModeSelect && step != WizardStep.Review
                ? Visibility.Visible : Visibility.Collapsed;
            CreateBtn.Visibility = step == WizardStep.Review ? Visibility.Visible : Visibility.Collapsed;
            CancelBtn.Visibility = step == WizardStep.ModeSelect ? Visibility.Visible : Visibility.Collapsed;

            // Refresh dynamic content
            if (step == WizardStep.TargetCustom)
            {
                RefreshTargetSelection();
                RefreshProtocolBar();
                RefreshDirectionBar();
                RefreshIpPills();
                RefreshPortPills();
                StepperHost1.Content = BuildStepper(1);
            }
            else if (step == WizardStep.TargetFilter)
            {
                RefreshFilterTab();
            }
            else if (step == WizardStep.Action)
            {
                RefreshActionCards();
                StepperHost2.Content = BuildStepper(2);
            }
            else if (step == WizardStep.Settings)
            {
                RefreshSettingsPanel();
                StepperHost3.Content = BuildStepper(3);
            }
            else if (step == WizardStep.Review)
            {
                BuildReview();
                StepperHost4.Content = BuildStepper(4);
            }
        }

        private void Next_Click(object sender, RoutedEventArgs e)
        {
            switch (_step)
            {
                case WizardStep.TargetCustom:
                    if (_targetMode == TrafficTargetMode.SpecificIPs && _targetIPs.Count == 0)
                    { Shake(); return; }
                    ShowStep(WizardStep.Action);
                    break;
                case WizardStep.TargetFilter:
                    if (_selectedFilter == FilterPreset.None)
                    { Shake(); return; }
                    ShowStep(WizardStep.Action);
                    break;
                case WizardStep.Action:
                    ShowStep(WizardStep.Settings);
                    break;
                case WizardStep.Settings:
                    ShowStep(WizardStep.Review);
                    break;
            }
        }

        private void Back_Click(object sender, RoutedEventArgs e)
        {
            switch (_step)
            {
                case WizardStep.TargetCustom:
                case WizardStep.TargetFilter:
                    ShowStep(WizardStep.ModeSelect);
                    break;
                case WizardStep.Action:
                    ShowStep(_modeCustom ? WizardStep.TargetCustom : WizardStep.TargetFilter);
                    break;
                case WizardStep.Settings:
                    ShowStep(WizardStep.Action);
                    break;
                case WizardStep.Review:
                    ShowStep(WizardStep.Settings);
                    break;
            }
        }

        private void Cancel_Click(object sender, RoutedEventArgs e) => Dismiss();
        private void Close_Click(object sender, RoutedEventArgs e) => Dismiss();

        /// <summary>External (host) trigger to close the wizard, e.g. backdrop click.</summary>
        public void Dismiss()
        {
            CreatedRule = null;
            Completed?.Invoke(this, EventArgs.Empty);
        }

        // ══════════════════════════════════════════════════════════════════
        // Step 0: Mode Selection
        // ══════════════════════════════════════════════════════════════════

        private void ModeCustom_Click(object sender, MouseButtonEventArgs e)
        {
            _modeCustom = true;
            ShowStep(WizardStep.TargetCustom);
        }

        private void ModeFilter_Click(object sender, MouseButtonEventArgs e)
        {
            _modeCustom = false;
            _targetMode = TrafficTargetMode.Filter;
            ShowStep(WizardStep.TargetFilter);
        }

        private void ApplyModeBorderStyle()
        {
            ModeCustomBtn.SetResourceReference(Border.BackgroundProperty, "InputBg");
            ModeCustomBtn.SetResourceReference(Border.BorderBrushProperty, "Divider");
            ModeFilterBtn.SetResourceReference(Border.BackgroundProperty, "InputBg");
            ModeFilterBtn.SetResourceReference(Border.BorderBrushProperty, "Divider");
        }

        // ══════════════════════════════════════════════════════════════════
        // Step 1a: Target (Custom)
        // ══════════════════════════════════════════════════════════════════

        private void TargetAll_Click(object sender, MouseButtonEventArgs e)
        {
            _targetMode = TrafficTargetMode.AllTraffic;
            RefreshTargetSelection();
        }

        private void TargetIps_Click(object sender, MouseButtonEventArgs e)
        {
            _targetMode = TrafficTargetMode.SpecificIPs;
            RefreshTargetSelection();
        }

        private void RefreshTargetSelection()
        {
            bool all = _targetMode == TrafficTargetMode.AllTraffic;
            StyleOptionBorder(TargetAllBtn, all);
            StyleOptionBorder(TargetIpsBtn, !all);
            IpInputPanel.Visibility = all ? Visibility.Collapsed : Visibility.Visible;
        }

        private void StyleOptionBorder(Border b, bool selected)
        {
            if (selected)
            {
                b.SetResourceReference(Border.BorderBrushProperty, "AccentBlue");
                b.SetResourceReference(Border.BackgroundProperty, "InputBg");
            }
            else
            {
                b.SetResourceReference(Border.BorderBrushProperty, "Divider");
                b.SetResourceReference(Border.BackgroundProperty, "CardBg");
            }
        }

        // ── IP pills ──────────────────────────────────────────────────────

        private void AddIp_Click(object sender, RoutedEventArgs e) => TryAddIp();
        private void IpInput_KeyDown(object sender, KeyEventArgs e) { if (e.Key == Key.Enter) TryAddIp(); }

        private void TryAddIp()
        {
            var ip = IpInput.Text.Trim();
            if (string.IsNullOrEmpty(ip)) return;
            if (!System.Net.IPAddress.TryParse(ip, out _)) return;
            if (_targetIPs.Contains(ip)) return;
            _targetIPs.Add(ip);
            IpInput.Clear();
            RefreshIpPills();
        }

        private void RefreshIpPills()
        {
            IpPillsPanel.Children.Clear();
            foreach (var ip in _targetIPs)
            {
                var pill = MakePill(ip, () => { _targetIPs.Remove(ip); RefreshIpPills(); });
                IpPillsPanel.Children.Add(pill);
            }
        }

        // ── Port pills ────────────────────────────────────────────────────

        private void AddPort_Click(object sender, RoutedEventArgs e) => TryAddPort();
        private void PortInput_KeyDown(object sender, KeyEventArgs e) { if (e.Key == Key.Enter) TryAddPort(); }

        private void TryAddPort()
        {
            var entry = PortEntry.TryParse(PortInput.Text);
            if (entry == null) return;
            if (_ports.Any(p => p.ToString() == entry.ToString())) return;
            _ports.Add(entry);
            PortInput.Clear();
            RefreshPortPills();
        }

        private void RefreshPortPills()
        {
            PortPillsPanel.Children.Clear();
            foreach (var p in _ports)
            {
                var pill = MakePill(p.ToString(), () => { _ports.Remove(p); RefreshPortPills(); });
                PortPillsPanel.Children.Add(pill);
            }
        }

        // ── Segmented bars ────────────────────────────────────────────────

        private void InitSegmentedBars()
        {
            BuildSegmented(ProtocolBar, new[] { "Any", "TCP", "UDP" }, 0, i =>
            {
                _protocol = i == 0 ? TrafficProtocol.Any : i == 1 ? TrafficProtocol.TCP : TrafficProtocol.UDP;
            });
            BuildSegmented(DirectionBar, new[] { "Both", "Inbound", "Outbound" }, 0, i =>
            {
                _direction = i == 0 ? TrafficDirection.Both : i == 1 ? TrafficDirection.Inbound : TrafficDirection.Outbound;
            });
        }

        private void RefreshProtocolBar()
        {
            int sel = _protocol == TrafficProtocol.Any ? 0 : _protocol == TrafficProtocol.TCP ? 1 : 2;
            SelectSegmented(ProtocolBar, sel);
        }

        private void RefreshDirectionBar()
        {
            int sel = _direction == TrafficDirection.Both ? 0 : _direction == TrafficDirection.Inbound ? 1 : 2;
            SelectSegmented(DirectionBar, sel);
        }

        private void BuildSegmented(UniformGrid grid, string[] labels, int defaultSel, Action<int> onSelect)
        {
            grid.Children.Clear();
            for (int i = 0; i < labels.Length; i++)
            {
                int idx = i;
                var btn = new Button
                {
                    Content = labels[i],
                    Height = 30,
                    FontSize = 11,
                    FontWeight = FontWeights.SemiBold,
                    Cursor = Cursors.Hand,
                    Tag = idx,
                    Style = (Style)FindResource("MaterialDesignFlatButton")
                };
                MaterialDesignThemes.Wpf.ButtonAssist.SetCornerRadius(btn, new CornerRadius(4));
                btn.Click += (_, _) =>
                {
                    onSelect(idx);
                    SelectSegmented(grid, idx);
                };
                grid.Children.Add(btn);
            }
            SelectSegmented(grid, defaultSel);
        }

        private void SelectSegmented(UniformGrid grid, int sel)
        {
            for (int i = 0; i < grid.Children.Count; i++)
            {
                var btn = (Button)grid.Children[i];
                if (i == sel)
                {
                    btn.SetResourceReference(Button.BackgroundProperty, "AccentBlue");
                    btn.SetResourceReference(Button.ForegroundProperty, "TextOnAccent");
                }
                else
                {
                    btn.SetResourceReference(Button.BackgroundProperty, "InputBg");
                    btn.SetResourceReference(Button.ForegroundProperty, "TextSecondary");
                }
            }
        }

        // ══════════════════════════════════════════════════════════════════
        // Step 1b: Filter Selection
        // ══════════════════════════════════════════════════════════════════

        private void FilterSearch_Changed(object sender, TextChangedEventArgs e) => RefreshFilterTab();

        private void RefreshFilterTab()
        {
            // My Filters tab is always active (Official removed)
            StyleFilterTab(FilterTabMine, true);

            FilterCardList.Children.Clear();
            var search = FilterSearch.Text?.Trim().ToLower() ?? "";

            // Show all built-in FilterRegistry presets (excluding None, Custom, TCP, UDP)
            // PLUS any user-defined CustomFilters from Settings
            var anyShown = false;

            foreach (var meta in FilterRegistry.All()
                .Where(m => m.Preset != FilterPreset.None && m.Preset != FilterPreset.Custom
                    && m.Preset != FilterPreset.TCP && m.Preset != FilterPreset.UDP)
                .Where(m => string.IsNullOrEmpty(search) ||
                    m.DisplayName.ToLower().Contains(search) ||
                    m.Description.ToLower().Contains(search)))
            {
                FilterCardList.Children.Add(BuildFilterCard(meta));
                anyShown = true;
            }

            var customs = Globals.Settings.CustomFilters ?? new List<CustomFilter>();
            foreach (var cf in customs.Where(c =>
                string.IsNullOrEmpty(search) || c.Name.ToLower().Contains(search)))
            {
                FilterCardList.Children.Add(BuildCustomFilterCard(cf));
                anyShown = true;
            }

            if (!anyShown)
            {
                var empty = new TextBlock
                {
                    Text = "No filters found",
                    FontSize = 11,
                    Margin = new Thickness(0, 8, 0, 8)
                };
                empty.SetResourceReference(TextBlock.ForegroundProperty, "TextFaint");
                FilterCardList.Children.Add(empty);
            }
        }

        private void StyleFilterTab(Border tab, bool active)
        {
            if (active)
            {
                tab.SetResourceReference(Border.BackgroundProperty, "AccentBlue");
                foreach (var child in LogicalTreeHelper.GetChildren(tab))
                    if (child is TextBlock tb) tb.SetResourceReference(TextBlock.ForegroundProperty, "TextOnAccent");
            }
            else
            {
                tab.SetResourceReference(Border.BackgroundProperty, "InputBg");
                foreach (var child in LogicalTreeHelper.GetChildren(tab))
                    if (child is TextBlock tb) tb.SetResourceReference(TextBlock.ForegroundProperty, "TextSecondary");
            }
        }

        private UIElement BuildFilterCard(FilterMeta meta)
        {
            bool selected = _selectedFilter == meta.Preset;
            var border = new Border
            {
                CornerRadius = new CornerRadius(6),
                Padding = new Thickness(10, 8, 10, 8),
                Margin = new Thickness(0, 0, 0, 4),
                Cursor = Cursors.Hand,
                BorderThickness = new Thickness(selected ? 2 : 1)
            };
            border.SetResourceReference(Border.BackgroundProperty, "InputBg");
            border.SetResourceReference(Border.BorderBrushProperty, selected ? "AccentBlue" : "Divider");

            var sp = new StackPanel();

            // Name + category
            var nameRow = new StackPanel { Orientation = Orientation.Horizontal };
            var name = new TextBlock { Text = meta.DisplayName, FontSize = 12, FontWeight = FontWeights.SemiBold };
            name.SetResourceReference(TextBlock.ForegroundProperty, "TextPrimary");
            nameRow.Children.Add(name);

            if (meta.Category != FilterCategory.NA)
            {
                var cat = new TextBlock
                {
                    Text = $"  ·  Filter Type: {meta.Category}",
                    FontSize = 10,
                    VerticalAlignment = VerticalAlignment.Center
                };
                cat.SetResourceReference(TextBlock.ForegroundProperty, "TextFaint");
                nameRow.Children.Add(cat);
            }
            sp.Children.Add(nameRow);

            // Description
            var desc = new TextBlock { Text = meta.Description, FontSize = 10, TextWrapping = TextWrapping.Wrap, Margin = new Thickness(0, 2, 0, 4) };
            desc.SetResourceReference(TextBlock.ForegroundProperty, "TextFaint");
            sp.Children.Add(desc);

            // Platform badges
            var badges = new WrapPanel { Orientation = Orientation.Horizontal };
            foreach (var plat in meta.Platforms)
            {
                var badge = new Border
                {
                    CornerRadius = new CornerRadius(3),
                    Padding = new Thickness(6, 1, 6, 1),
                    Margin = new Thickness(0, 0, 4, 0)
                };
                string bgKey = plat switch
                {
                    FilterPlatform.PlayStation => "AccentBlue",
                    FilterPlatform.Xbox => "StatusSuccess",
                    FilterPlatform.PC => "ActionThrottle",
                    _ => "TextFaint"
                };
                badge.SetResourceReference(Border.BackgroundProperty, bgKey);
                var label = new TextBlock { Text = plat.ToString(), FontSize = 9, FontWeight = FontWeights.SemiBold, Foreground = Brushes.White };
                badge.Child = label;
                badges.Children.Add(badge);
            }
            sp.Children.Add(badges);
            border.Child = sp;

            border.MouseLeftButtonDown += (_, _) =>
            {
                _selectedFilter = meta.Preset;
                _targetMode = TrafficTargetMode.Filter;
                RefreshFilterTab();
                // Auto-advance to action step
                ShowStep(WizardStep.Action);
            };

            return border;
        }

        private UIElement BuildCustomFilterCard(CustomFilter cf)
        {
            var border = new Border
            {
                CornerRadius = new CornerRadius(6),
                Padding = new Thickness(10, 8, 10, 8),
                Margin = new Thickness(0, 0, 0, 4),
                Cursor = Cursors.Hand,
                BorderThickness = new Thickness(1)
            };
            border.SetResourceReference(Border.BackgroundProperty, "InputBg");
            border.SetResourceReference(Border.BorderBrushProperty, "Divider");

            var sp = new StackPanel();
            var name = new TextBlock { Text = cf.Name, FontSize = 12, FontWeight = FontWeights.SemiBold };
            name.SetResourceReference(TextBlock.ForegroundProperty, "TextPrimary");
            sp.Children.Add(name);

            var detail = new TextBlock { Text = cf.ToString(), FontSize = 10, Margin = new Thickness(0, 2, 0, 0) };
            detail.SetResourceReference(TextBlock.ForegroundProperty, "TextFaint");
            sp.Children.Add(detail);

            border.Child = sp;

            border.MouseLeftButtonDown += (_, _) =>
            {
                // For custom user filters we use the Custom preset and store the filter name
                _selectedFilter = FilterPreset.Custom;
                _targetMode = TrafficTargetMode.Filter;
                RefreshFilterTab();
                ShowStep(WizardStep.Action);
            };

            return border;
        }

        // ══════════════════════════════════════════════════════════════════
        // Step 2: Action Selection
        // ══════════════════════════════════════════════════════════════════

        private void InitActionCards()
        {
            ActionCardList.Children.Clear();
            var actions = new[]
            {
                (TrafficAction.Drop, "Drop", "Block packets completely", PackIconKind.Cancel, "ActionDrop"),
                (TrafficAction.Lag, "Lag", "Add delay to packets", PackIconKind.ClockOutline, "ActionLag"),
                (TrafficAction.Throttle, "Throttle", "Limit bandwidth speed", PackIconKind.FlashOutline, "ActionThrottle"),
                (TrafficAction.Reorder, "Reorder", "Shuffle packet order", PackIconKind.ShuffleVariant, "ActionReorder"),
                (TrafficAction.Duplicate, "Duplicate", "Send packets twice", PackIconKind.ContentCopy, "ActionDuplicate"),
            };

            foreach (var (act, name, desc, icon, token) in actions)
            {
                var border = new Border
                {
                    CornerRadius = new CornerRadius(6),
                    Padding = new Thickness(12, 10, 12, 10),
                    Margin = new Thickness(0, 0, 0, 4),
                    Cursor = Cursors.Hand,
                    BorderThickness = new Thickness(2),
                    Tag = act
                };
                border.SetResourceReference(Border.BackgroundProperty, "InputBg");
                border.SetResourceReference(Border.BorderBrushProperty, "Divider");

                var grid = new Grid();
                grid.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
                grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
                grid.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });

                // Icon
                var ic = new Border
                {
                    Width = 32, Height = 32, CornerRadius = new CornerRadius(6),
                    Margin = new Thickness(0, 0, 10, 0), VerticalAlignment = VerticalAlignment.Center
                };
                var packIcon = new PackIcon { Kind = icon, Width = 18, Height = 18, HorizontalAlignment = HorizontalAlignment.Center, VerticalAlignment = VerticalAlignment.Center };
                packIcon.SetResourceReference(PackIcon.ForegroundProperty, token);
                ic.Child = packIcon;
                Grid.SetColumn(ic, 0);
                grid.Children.Add(ic);

                // Text
                var textSp = new StackPanel { VerticalAlignment = VerticalAlignment.Center };
                var nameTb = new TextBlock { Text = name, FontSize = 12, FontWeight = FontWeights.SemiBold };
                nameTb.SetResourceReference(TextBlock.ForegroundProperty, "TextPrimary");
                textSp.Children.Add(nameTb);
                var descTb = new TextBlock { Text = desc, FontSize = 10 };
                descTb.SetResourceReference(TextBlock.ForegroundProperty, "TextFaint");
                textSp.Children.Add(descTb);
                Grid.SetColumn(textSp, 1);
                grid.Children.Add(textSp);

                // Checkmark (shown when selected)
                var check = new PackIcon { Kind = PackIconKind.CheckCircle, Width = 18, Height = 18, VerticalAlignment = VerticalAlignment.Center, Visibility = Visibility.Collapsed };
                check.SetResourceReference(PackIcon.ForegroundProperty, token);
                Grid.SetColumn(check, 2);
                grid.Children.Add(check);

                border.Child = grid;
                border.MouseLeftButtonDown += (_, _) => { _action = act; RefreshActionCards(); };
                ActionCardList.Children.Add(border);
            }
        }

        private void RefreshActionCards()
        {
            foreach (Border card in ActionCardList.Children)
            {
                var act = (TrafficAction)card.Tag;
                bool sel = act == _action;
                string token = act switch
                {
                    TrafficAction.Drop => "ActionDrop",
                    TrafficAction.Lag => "ActionLag",
                    TrafficAction.Throttle => "ActionThrottle",
                    TrafficAction.Reorder => "ActionReorder",
                    TrafficAction.Duplicate => "ActionDuplicate",
                    _ => "Divider"
                };
                card.SetResourceReference(Border.BorderBrushProperty, sel ? token : "Divider");

                // Show/hide checkmark
                var grid = (Grid)card.Child;
                var check = grid.Children.OfType<PackIcon>().FirstOrDefault();
                if (check != null) check.Visibility = sel ? Visibility.Visible : Visibility.Collapsed;
            }
        }

        // ══════════════════════════════════════════════════════════════════
        // Step 3: Settings
        // ══════════════════════════════════════════════════════════════════

        private void RefreshSettingsPanel()
        {
            LagPanel.Visibility = _action == TrafficAction.Lag ? Visibility.Visible : Visibility.Collapsed;
            ThrottlePanel.Visibility = _action == TrafficAction.Throttle ? Visibility.Visible : Visibility.Collapsed;
            ReorderPanel.Visibility = _action == TrafficAction.Reorder ? Visibility.Visible : Visibility.Collapsed;
            DuplicatePanel.Visibility = _action == TrafficAction.Duplicate ? Visibility.Visible : Visibility.Collapsed;
            BurstPanel.Visibility = BurstToggle.IsChecked == true ? Visibility.Visible : Visibility.Collapsed;
        }

        private void ProbSlider_Changed(object sender, RoutedPropertyChangedEventArgs<double> e)
        {
            if (ProbLabel != null) ProbLabel.Text = $"{(int)ProbSlider.Value}%";
        }

        private void BurstToggle_Changed(object sender, RoutedEventArgs e)
        {
            BurstPanel.Visibility = BurstToggle.IsChecked == true ? Visibility.Visible : Visibility.Collapsed;
        }

        private void BurstOn_Changed(object sender, RoutedPropertyChangedEventArgs<double> e)
        {
            if (BurstOnLabel != null) BurstOnLabel.Text = $"{(int)BurstOnSlider.Value}ms";
        }

        private void BurstOff_Changed(object sender, RoutedPropertyChangedEventArgs<double> e)
        {
            if (BurstOffLabel != null) BurstOffLabel.Text = $"{(int)BurstOffSlider.Value}ms";
        }

        private void Delay_Changed(object sender, RoutedPropertyChangedEventArgs<double> e)
        {
            if (DelayLabel != null) DelayLabel.Text = $"{(int)DelaySlider.Value}ms";
        }

        private void Jitter_Changed(object sender, RoutedPropertyChangedEventArgs<double> e)
        {
            if (JitterLabel != null) JitterLabel.Text = $"±{(int)JitterSlider.Value}ms";
        }

        private void Rate_Changed(object sender, RoutedPropertyChangedEventArgs<double> e)
        {
            if (RateLabel != null) RateLabel.Text = $"{(int)RateSlider.Value} kbps";
        }

        private void ReorderPct_Changed(object sender, RoutedPropertyChangedEventArgs<double> e)
        {
            if (ReorderPctLabel != null) ReorderPctLabel.Text = $"{(int)ReorderPctSlider.Value}%";
        }

        private void ReorderWin_Changed(object sender, RoutedPropertyChangedEventArgs<double> e)
        {
            if (ReorderWinLabel != null) ReorderWinLabel.Text = $"{(int)ReorderWinSlider.Value}ms";
        }

        private void DupPct_Changed(object sender, RoutedPropertyChangedEventArgs<double> e)
        {
            if (DupPctLabel != null) DupPctLabel.Text = $"{(int)DupPctSlider.Value}%";
        }

        private void DupDelay_Changed(object sender, RoutedPropertyChangedEventArgs<double> e)
        {
            if (DupDelayLabel != null) DupDelayLabel.Text = $"{(int)DupDelaySlider.Value}ms";
        }

        // ══════════════════════════════════════════════════════════════════
        // Step 4: Review
        // ══════════════════════════════════════════════════════════════════

        private void BuildReview()
        {
            // Auto-fill name
            if (string.IsNullOrWhiteSpace(RuleNameInput.Text))
            {
                if (_editSource != null)
                    RuleNameInput.Text = _editSource.Name;
                else if (_targetMode == TrafficTargetMode.Filter && _selectedFilter != FilterPreset.None)
                    RuleNameInput.Text = FilterRegistry.Get(_selectedFilter).DisplayName;
            }

            ReviewTable.Children.Clear();

            string targetText = _targetMode switch
            {
                TrafficTargetMode.AllTraffic => "All Traffic",
                TrafficTargetMode.SpecificIPs => string.Join(", ", _targetIPs),
                TrafficTargetMode.Filter => FilterRegistry.Get(_selectedFilter).DisplayName,
                _ => "Unknown"
            };

            AddReviewRow("Target", targetText);
            AddReviewRow("Protocol", _protocol.ToString().ToUpper());
            AddReviewRow("Direction", _direction.ToString());
            AddReviewRow("Ports", _ports.Count == 0 ? "All" : string.Join(", ", _ports));
            AddReviewRow("Action", _action.ToString(), GetActionToken(_action));
            AddReviewRow("Probability", $"{(int)ProbSlider.Value}%");

            if (BurstToggle.IsChecked == true)
                AddReviewRow("Burst Mode", $"{(int)BurstOnSlider.Value}ms ON / {(int)BurstOffSlider.Value}ms OFF");
            else
                AddReviewRow("Burst Mode", "Disabled");

            if (_action == TrafficAction.Lag)
            {
                AddReviewRow("Delay", $"{(int)DelaySlider.Value}ms");
                if ((int)JitterSlider.Value > 0)
                    AddReviewRow("Jitter", $"±{(int)JitterSlider.Value}ms");
            }
            if (_action == TrafficAction.Throttle)
                AddReviewRow("Rate Limit", $"{(int)RateSlider.Value} kbps");
            if (_action == TrafficAction.Reorder)
            {
                AddReviewRow("Reorder %", $"{(int)ReorderPctSlider.Value}%");
                AddReviewRow("Reorder Window", $"{(int)ReorderWinSlider.Value}ms");
            }
            if (_action == TrafficAction.Duplicate)
            {
                AddReviewRow("Duplicate %", $"{(int)DupPctSlider.Value}%");
                if ((int)DupDelaySlider.Value > 0)
                    AddReviewRow("Delay", $"{(int)DupDelaySlider.Value}ms");
            }
        }

        private void AddReviewRow(string label, string value, string colorToken = null)
        {
            var border = new Border
            {
                Padding = new Thickness(12, 6, 12, 6),
                BorderThickness = new Thickness(0, 0, 0, 1)
            };
            border.SetResourceReference(Border.BorderBrushProperty, "Divider");

            var grid = new Grid();
            grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
            grid.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });

            var lbl = new TextBlock { Text = label, FontSize = 11 };
            lbl.SetResourceReference(TextBlock.ForegroundProperty, "TextSecondary");
            Grid.SetColumn(lbl, 0);
            grid.Children.Add(lbl);

            if (colorToken != null)
            {
                var badge = new Border { CornerRadius = new CornerRadius(4), Padding = new Thickness(8, 2, 8, 2) };
                badge.SetResourceReference(Border.BackgroundProperty, colorToken);
                var valTb = new TextBlock { Text = value, FontSize = 11, FontWeight = FontWeights.SemiBold, Foreground = Brushes.White };
                badge.Child = valTb;
                Grid.SetColumn(badge, 1);
                grid.Children.Add(badge);
            }
            else
            {
                var val = new TextBlock { Text = value, FontSize = 11, FontWeight = FontWeights.SemiBold };
                val.SetResourceReference(TextBlock.ForegroundProperty, "TextPrimary");
                Grid.SetColumn(val, 1);
                grid.Children.Add(val);
            }

            border.Child = grid;
            ReviewTable.Children.Add(border);
        }

        private string GetActionToken(TrafficAction a) => a switch
        {
            TrafficAction.Drop => "ActionDrop",
            TrafficAction.Lag => "ActionLag",
            TrafficAction.Throttle => "ActionThrottle",
            TrafficAction.Reorder => "ActionReorder",
            TrafficAction.Duplicate => "ActionDuplicate",
            _ => "TextFaint"
        };

        // ══════════════════════════════════════════════════════════════════
        // Create Rule
        // ══════════════════════════════════════════════════════════════════

        private void Create_Click(object sender, RoutedEventArgs e)
        {
            var name = RuleNameInput.Text?.Trim();
            if (string.IsNullOrWhiteSpace(name)) { Shake(); return; }

            CreatedRule = new TrafficRule
            {
                Name = name,
                // Preserve prior Enabled state on edit — previously hardcoded true, which
                // silently re-enabled rules the user had toggled off (S1 fix).
                Enabled = _editSource?.Enabled ?? true,
                TargetMode = _targetMode,
                TargetIPs = new List<string>(_targetIPs),
                FilterPreset = _selectedFilter,
                Protocol = _protocol,
                Direction = _direction,
                Ports = new List<PortEntry>(_ports),
                Action = _action,
                Probability = (int)ProbSlider.Value,
                BurstEnabled = BurstToggle.IsChecked == true,
                BurstOnMs = (int)BurstOnSlider.Value,
                BurstOffMs = (int)BurstOffSlider.Value,
                DelayMs = (int)DelaySlider.Value,
                JitterMs = (int)JitterSlider.Value,
                RateKbps = (int)RateSlider.Value,
                ReorderPercent = (int)ReorderPctSlider.Value,
                ReorderWindowMs = (int)ReorderWinSlider.Value,
                DuplicatePercent = (int)DupPctSlider.Value,
                DuplicateDelayMs = (int)DupDelaySlider.Value
            };

            Completed?.Invoke(this, EventArgs.Empty);
        }

        // ══════════════════════════════════════════════════════════════════
        // Stepper Builder
        // ══════════════════════════════════════════════════════════════════

        private UIElement BuildStepper(int currentStep)
        {
            var sp = new StackPanel
            {
                Orientation = Orientation.Horizontal,
                HorizontalAlignment = HorizontalAlignment.Center
            };

            var steps = new[] { "TARGET", "ACTION", "SETTINGS", "REVIEW" };
            for (int i = 0; i < steps.Length; i++)
            {
                int stepNum = i + 1;
                bool completed = stepNum < currentStep;
                bool active = stepNum == currentStep;

                // Circle
                var circle = new Border
                {
                    Width = 28, Height = 28, CornerRadius = new CornerRadius(14),
                    HorizontalAlignment = HorizontalAlignment.Center
                };

                if (completed)
                {
                    circle.SetResourceReference(Border.BackgroundProperty, "StatusSuccess");
                    circle.Child = new PackIcon
                    {
                        Kind = PackIconKind.Check, Width = 14, Height = 14,
                        Foreground = Brushes.White,
                        HorizontalAlignment = HorizontalAlignment.Center,
                        VerticalAlignment = VerticalAlignment.Center
                    };
                }
                else if (active)
                {
                    circle.SetResourceReference(Border.BackgroundProperty, "AccentBlue");
                    var num = new TextBlock
                    {
                        Text = stepNum.ToString(), FontSize = 12, FontWeight = FontWeights.Bold,
                        Foreground = Brushes.White,
                        HorizontalAlignment = HorizontalAlignment.Center,
                        VerticalAlignment = VerticalAlignment.Center
                    };
                    circle.Child = num;
                }
                else
                {
                    circle.SetResourceReference(Border.BackgroundProperty, "InputBg");
                    var num = new TextBlock { Text = stepNum.ToString(), FontSize = 12, FontWeight = FontWeights.Bold };
                    num.SetResourceReference(TextBlock.ForegroundProperty, "TextFaint");
                    num.HorizontalAlignment = HorizontalAlignment.Center;
                    num.VerticalAlignment = VerticalAlignment.Center;
                    circle.Child = num;
                }

                var stepPanel = new StackPanel { HorizontalAlignment = HorizontalAlignment.Center, Margin = new Thickness(0, 0, 0, 0) };
                stepPanel.Children.Add(circle);
                var label = new TextBlock
                {
                    Text = steps[i], FontSize = 9, FontWeight = FontWeights.SemiBold,
                    HorizontalAlignment = HorizontalAlignment.Center, Margin = new Thickness(0, 3, 0, 0)
                };
                label.SetResourceReference(TextBlock.ForegroundProperty, active ? "TextPrimary" : "TextFaint");
                stepPanel.Children.Add(label);

                sp.Children.Add(stepPanel);

                // Connector line between steps
                if (i < steps.Length - 1)
                {
                    var line = new Border
                    {
                        Width = 40, Height = 2, VerticalAlignment = VerticalAlignment.Center,
                        Margin = new Thickness(6, 0, 6, 12)
                    };
                    line.SetResourceReference(Border.BackgroundProperty,
                        stepNum < currentStep ? "StatusSuccess" : "Divider");
                    sp.Children.Add(line);
                }
            }
            return sp;
        }

        // ══════════════════════════════════════════════════════════════════
        // Pill Builder
        // ══════════════════════════════════════════════════════════════════

        private UIElement MakePill(string text, Action onRemove)
        {
            var border = new Border
            {
                CornerRadius = new CornerRadius(4),
                Padding = new Thickness(8, 3, 4, 3),
                Margin = new Thickness(0, 0, 4, 4)
            };
            border.SetResourceReference(Border.BackgroundProperty, "AccentBlue");

            var sp = new StackPanel { Orientation = Orientation.Horizontal };
            var tb = new TextBlock
            {
                Text = text, FontSize = 11, FontWeight = FontWeights.SemiBold,
                Foreground = Brushes.White, VerticalAlignment = VerticalAlignment.Center
            };
            sp.Children.Add(tb);

            var closeBtn = new Button
            {
                Width = 16, Height = 16, Padding = new Thickness(0),
                Margin = new Thickness(4, 0, 0, 0),
                Cursor = Cursors.Hand,
                Background = Brushes.Transparent, BorderBrush = null,
                Style = (Style)FindResource("MaterialDesignFlatButton")
            };
            closeBtn.Content = new PackIcon
            {
                Kind = PackIconKind.Close, Width = 10, Height = 10,
                Foreground = Brushes.White,
                HorizontalAlignment = HorizontalAlignment.Center,
                VerticalAlignment = VerticalAlignment.Center
            };
            closeBtn.Click += (_, _) => onRemove();
            sp.Children.Add(closeBtn);

            border.Child = sp;
            return border;
        }

        // ══════════════════════════════════════════════════════════════════
        // Utils
        // ══════════════════════════════════════════════════════════════════

        private void Shake()
        {
            // Quick visual shake to indicate validation error
            var transform = new TranslateTransform();
            this.RenderTransform = transform;
            var anim = new System.Windows.Media.Animation.DoubleAnimation
            {
                From = -5, To = 5,
                Duration = TimeSpan.FromMilliseconds(50),
                AutoReverse = true,
                RepeatBehavior = new System.Windows.Media.Animation.RepeatBehavior(3)
            };
            anim.Completed += (_, _) => this.RenderTransform = null;
            transform.BeginAnimation(TranslateTransform.XProperty, anim);
        }
    }
}
