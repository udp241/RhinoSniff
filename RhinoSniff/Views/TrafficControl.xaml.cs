using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Controls.Primitives;
using System.Windows.Media;
using System.Windows.Shapes;
using MaterialDesignThemes.Wpf;
using RhinoSniff.Classes;
using RhinoSniff.Interfaces;
using RhinoSniff.Models;
using RhinoSniff.Windows;

namespace RhinoSniff.Views
{
    public partial class TrafficControl : UserControl
    {
        private readonly MainWindow _host;
        private bool _running;
        private TrafficControlEngine _engine;

        public TrafficControl(MainWindow host)
        {
            _host = host;
            InitializeComponent();
            RefreshRuleList();
        }

        // ── Start / Stop ──────────────────────────────────────────────────

        private void StartStop_Click(object sender, RoutedEventArgs e)
        {
            if (!_running)
            {
                // Guard: must have at least one rule
                if (Globals.Settings.TrafficRules == null || Globals.Settings.TrafficRules.Count == 0)
                {
                    ShowToast("Create a rule first before starting Traffic Control");
                    return;
                }
                Start();
            }
            else
            {
                Stop();
            }
        }

        private void Start()
        {
            _running = true;
            UpdateStatePill();
            ResetStats();

            try
            {
                var enabledRules = Globals.Settings.TrafficRules?.Where(r => r.Enabled).ToList()
                    ?? new List<TrafficRule>();
                _engine = new TrafficControlEngine(enabledRules);
                _engine.StatsUpdated += OnStatsUpdated;
                _engine.Start();
                _host?.SetTrafficControlRunningIndicator(true);
                _host?.NotifyPublic(NotificationType.Info, "Traffic Control started.");
            }
            catch (Exception ex)
            {
                _running = false;
                UpdateStatePill();
                _host?.SetTrafficControlRunningIndicator(false);
                ShowToast($"Failed to start: {ex.Message}");
            }
        }

        private void Stop()
        {
            _running = false;
            UpdateStatePill();
            try
            {
                if (_engine != null)
                {
                    _engine.StatsUpdated -= OnStatsUpdated;
                    _engine.Dispose();
                }
            }
            catch { }
            _engine = null;
            _host?.SetTrafficControlRunningIndicator(false);
            _host?.NotifyPublic(NotificationType.Info, "Traffic Control stopped.");
        }

        private void OnStatsUpdated(long processed, long dropped, long delayed,
            long reordered, long duplicated, long throttled)
        {
            UpdateStats(processed, dropped, delayed, reordered, duplicated, throttled);
        }

        /// <summary>Call from MainWindow when navigating away or closing — ensures clean shutdown.</summary>
        public void ForceStop()
        {
            if (_running) Stop();
        }

        public bool IsRunning => _running;

        private void UpdateStatePill()
        {
            if (_running)
            {
                StatePill.SetResourceReference(Border.BackgroundProperty, "PillCapturingBg");
                StateDot.SetResourceReference(Shape.FillProperty, "StatusSuccess");
                StateText.SetResourceReference(TextBlock.ForegroundProperty, "PillCapturingText");
                StateText.Text = "RUNNING";

                StartStopButton.SetResourceReference(Button.BackgroundProperty, "StatusDanger");
                StartStopIcon.Kind = PackIconKind.Stop;
                StartStopText.Text = "Stop";
            }
            else
            {
                StatePill.SetResourceReference(Border.BackgroundProperty, "PillStoppedBg");
                StateDot.SetResourceReference(Shape.FillProperty, "StatusDanger");
                StateText.SetResourceReference(TextBlock.ForegroundProperty, "PillStoppedText");
                StateText.Text = "STOPPED";

                StartStopButton.SetResourceReference(Button.BackgroundProperty, "AccentBlue");
                StartStopIcon.Kind = PackIconKind.Play;
                StartStopText.Text = "Start";
            }
        }

        // ── Stats ─────────────────────────────────────────────────────────

        public void UpdateStats(long processed, long dropped, long delayed,
            long reordered, long duplicated, long throttled)
        {
            if (!Dispatcher.CheckAccess())
            {
                Dispatcher.BeginInvoke(new Action(() =>
                    UpdateStats(processed, dropped, delayed, reordered, duplicated, throttled)));
                return;
            }
            StatProcessed.Text = processed.ToString("N0");
            StatDropped.Text = dropped.ToString("N0");
            StatDelayed.Text = delayed.ToString("N0");
            StatReordered.Text = reordered.ToString("N0");
            StatDuplicated.Text = duplicated.ToString("N0");
            StatThrottled.Text = throttled.ToString("N0");
        }

        public void ResetStats()
        {
            UpdateStats(0, 0, 0, 0, 0, 0);
        }

        // ── Add Rule ──────────────────────────────────────────────────────

        private void AddRule_Click(object sender, RoutedEventArgs e)
        {
            _host?.ShowTrafficRuleWizard(null, rule =>
            {
                if (rule == null) return; // dismissed
                Globals.Settings.TrafficRules ??= new List<TrafficRule>();
                Globals.Settings.TrafficRules.Add(rule);
                SaveSettings();
                RefreshRuleList();
                PushRulesToEngine(); // B4: live add takes effect without restart
            });
        }

        // ── Edit Rule ─────────────────────────────────────────────────────

        private void EditRule(TrafficRule rule)
        {
            _host?.ShowTrafficRuleWizard(rule, edited =>
            {
                if (edited == null) return; // dismissed
                var idx = Globals.Settings.TrafficRules.IndexOf(rule);
                if (idx >= 0) Globals.Settings.TrafficRules[idx] = edited;
                SaveSettings();
                RefreshRuleList();
                PushRulesToEngine(); // B4: live edit takes effect without restart
            });
        }

        // ── Delete Rule ───────────────────────────────────────────────────

        private void DeleteRule(TrafficRule rule)
        {
            var result = Globals.Container.GetInstance<IThemeUtils>().MsgBox(new MsgBox
            {
                Icon = MsgBox.MsgBoxIcon.Question,
                Button = MsgBox.MsgBoxBtn.YesNo,
                Message = $"Delete traffic rule \"{rule.Name}\"? This cannot be undone."
            });
            if (result == MsgBox.MsgBoxResult.No) return;

            Globals.Settings.TrafficRules?.Remove(rule);
            SaveSettings();
            RefreshRuleList();
            PushRulesToEngine(); // B4: live delete takes effect without restart
        }

        // ── Toggle Rule ───────────────────────────────────────────────────

        private void ToggleRule(TrafficRule rule, bool enabled)
        {
            rule.Enabled = enabled;
            SaveSettings();
            // Toggle already takes effect via the shared rule object reference (engine
            // re-reads rule.Enabled per packet), but pushing keeps the engine's pre-init
            // burst/throttle dictionaries in sync if a previously-disabled burst rule
            // is now enabled.
            PushRulesToEngine();
        }

        /// <summary>
        /// B4 helper: push the current enabled-rule snapshot to the engine if it's running.
        /// No-op when stopped — Start() reads the rules fresh from settings on its own.
        /// </summary>
        private void PushRulesToEngine()
        {
            if (_engine == null || !_running) return;
            try
            {
                var enabled = Globals.Settings.TrafficRules?.Where(r => r.Enabled).ToList()
                    ?? new List<TrafficRule>();
                _engine.UpdateRules(enabled);
            }
            catch { /* never let a settings push crash the UI */ }
        }

        // ── Rule List ─────────────────────────────────────────────────────

        public void RefreshRuleList()
        {
            var rules = Globals.Settings.TrafficRules ?? new List<TrafficRule>();
            RulesHeaderText.Text = $"Rules ({rules.Count})";

            if (rules.Count == 0)
            {
                EmptyState.Visibility = Visibility.Visible;
                RuleListScroll.Visibility = Visibility.Collapsed;
            }
            else
            {
                EmptyState.Visibility = Visibility.Collapsed;
                RuleListScroll.Visibility = Visibility.Visible;
            }

            var items = new List<UIElement>();
            foreach (var rule in rules)
                items.Add(BuildRuleRow(rule));
            RuleList.ItemsSource = items;
        }

        private UIElement BuildRuleRow(TrafficRule rule)
        {
            // Root border
            var row = new Border
            {
                CornerRadius = new CornerRadius(4),
                Padding = new Thickness(12, 8, 12, 8),
                Margin = new Thickness(6, 2, 6, 2),
                Cursor = System.Windows.Input.Cursors.Arrow
            };
            row.SetResourceReference(Border.BackgroundProperty, "InputBg");

            var grid = new Grid();
            grid.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });   // 0: toggle
            grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) }); // 1: info
            grid.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });   // 2: buttons

            // ── Column 0: Toggle ──────────────────────────────────────────
            var toggle = new ToggleButton
            {
                IsChecked = rule.Enabled,
                VerticalAlignment = VerticalAlignment.Center,
                Margin = new Thickness(0, 0, 10, 0),
                Style = (Style)FindResource("MaterialDesignSwitchToggleButton")
            };
            toggle.Checked += (_, _) => ToggleRule(rule, true);
            toggle.Unchecked += (_, _) => ToggleRule(rule, false);
            Grid.SetColumn(toggle, 0);
            grid.Children.Add(toggle);

            // ── Column 1: Info block ──────────────────────────────────────
            var infoPanel = new StackPanel { VerticalAlignment = VerticalAlignment.Center };
            Grid.SetColumn(infoPanel, 1);

            // Row 1: name + action badge
            var nameRow = new StackPanel { Orientation = Orientation.Horizontal };

            // U1: small filter icon when rule targets a Filter preset.
            // Custom and SpecificIPs targets get no icon — only Filter-mode rules show this.
            if (rule.TargetMode == TrafficTargetMode.Filter)
            {
                var filterIcon = new PackIcon
                {
                    Kind = PackIconKind.FilterOutline,
                    Width = 13,
                    Height = 13,
                    VerticalAlignment = VerticalAlignment.Center,
                    Margin = new Thickness(0, 0, 5, 0)
                };
                filterIcon.SetResourceReference(PackIcon.ForegroundProperty, "TextFaint");
                nameRow.Children.Add(filterIcon);
            }

            var nameText = new TextBlock
            {
                Text = rule.Name,
                FontSize = 12,
                FontWeight = FontWeights.SemiBold,
                VerticalAlignment = VerticalAlignment.Center,
                Margin = new Thickness(0, 0, 8, 0)
            };
            nameText.SetResourceReference(TextBlock.ForegroundProperty, "TextPrimary");
            nameRow.Children.Add(nameText);

            // Action badge (icon + label)
            var badge = BuildActionBadge(rule.Action);
            nameRow.Children.Add(badge);
            infoPanel.Children.Add(nameRow);

            // Row 2: detail chips
            var detailRow = new WrapPanel
            {
                Orientation = Orientation.Horizontal,
                Margin = new Thickness(0, 3, 0, 0)
            };
            detailRow.Children.Add(MakeChip("TARGET", rule.TargetDisplay));
            detailRow.Children.Add(MakeChip("PROTOCOL", rule.Protocol.ToString().ToUpper()));
            detailRow.Children.Add(MakeChip("DIRECTION", rule.Direction.ToString().ToLower()));
            detailRow.Children.Add(MakeChip("PROBABILITY", $"{rule.Probability}%"));

            // Action-specific chips
            if (rule.Action == TrafficAction.Lag)
                detailRow.Children.Add(MakeChip("DELAY", $"{rule.DelayMs}ms"));
            else if (rule.Action == TrafficAction.Throttle)
                detailRow.Children.Add(MakeChip("RATE", $"{rule.RateKbps} kbps"));

            infoPanel.Children.Add(detailRow);
            grid.Children.Add(infoPanel);

            // ── Column 2: Up / Down / Gear / Trash buttons ────────────────
            var btnPanel = new StackPanel
            {
                Orientation = Orientation.Horizontal,
                VerticalAlignment = VerticalAlignment.Center
            };
            Grid.SetColumn(btnPanel, 2);

            // Rules are evaluated top-to-bottom by the engine, so order matters.
            // Up/down move the rule within the list; auto-disable at bounds.
            var rules = Globals.Settings.TrafficRules ?? new List<TrafficRule>();
            var idx = rules.IndexOf(rule);

            var upBtn = MakeIconButton(PackIconKind.ChevronUp, "Move up");
            upBtn.IsEnabled = idx > 0;
            upBtn.Click += (_, _) => MoveRule(rule, -1);
            btnPanel.Children.Add(upBtn);

            var downBtn = MakeIconButton(PackIconKind.ChevronDown, "Move down");
            downBtn.IsEnabled = idx >= 0 && idx < rules.Count - 1;
            downBtn.Click += (_, _) => MoveRule(rule, +1);
            btnPanel.Children.Add(downBtn);

            var gearBtn = MakeIconButton(PackIconKind.CogOutline, "Edit rule");
            gearBtn.Click += (_, _) => EditRule(rule);
            btnPanel.Children.Add(gearBtn);

            var trashBtn = MakeIconButton(PackIconKind.DeleteOutline, "Delete rule");
            trashBtn.Click += (_, _) => DeleteRule(rule);
            btnPanel.Children.Add(trashBtn);

            grid.Children.Add(btnPanel);
            row.Child = grid;
            return row;
        }

        // ── Rule reorder ──────────────────────────────────────────────────

        private void MoveRule(TrafficRule rule, int direction)
        {
            if (Globals.Settings.TrafficRules == null) return;
            var rules = Globals.Settings.TrafficRules;
            var idx = rules.IndexOf(rule);
            if (idx < 0) return;
            var newIdx = idx + direction;
            if (newIdx < 0 || newIdx >= rules.Count) return;
            rules.RemoveAt(idx);
            rules.Insert(newIdx, rule);
            SaveSettings();
            RefreshRuleList();
            PushRulesToEngine(); // B4: rule order is first-match-wins; push so the engine
                                 // sees the new evaluation order on the next packet.
        }

        // ── UI Helpers ────────────────────────────────────────────────────

        private UIElement BuildActionBadge(TrafficAction action)
        {
            string tokenKey;
            PackIconKind icon;
            string label;
            switch (action)
            {
                case TrafficAction.Drop:
                    tokenKey = "ActionDrop"; icon = PackIconKind.Cancel; label = "Drop"; break;
                case TrafficAction.Lag:
                    tokenKey = "ActionLag"; icon = PackIconKind.ClockOutline; label = "Lag"; break;
                case TrafficAction.Throttle:
                    tokenKey = "ActionThrottle"; icon = PackIconKind.FlashOutline; label = "Throttle"; break;
                case TrafficAction.Reorder:
                    tokenKey = "ActionReorder"; icon = PackIconKind.ShuffleVariant; label = "Reorder"; break;
                case TrafficAction.Duplicate:
                    tokenKey = "ActionDuplicate"; icon = PackIconKind.ContentCopy; label = "Duplicate"; break;
                default:
                    tokenKey = "TextFaint"; icon = PackIconKind.HelpCircleOutline; label = "?"; break;
            }

            var sp = new StackPanel { Orientation = Orientation.Horizontal, VerticalAlignment = VerticalAlignment.Center };
            var ic = new PackIcon { Kind = icon, Width = 13, Height = 13, VerticalAlignment = VerticalAlignment.Center, Margin = new Thickness(0, 0, 3, 0) };
            ic.SetResourceReference(PackIcon.ForegroundProperty, tokenKey);
            sp.Children.Add(ic);

            var tb = new TextBlock { Text = label, FontSize = 10, FontWeight = FontWeights.SemiBold, VerticalAlignment = VerticalAlignment.Center };
            tb.SetResourceReference(TextBlock.ForegroundProperty, tokenKey);
            sp.Children.Add(tb);
            return sp;
        }

        private UIElement MakeChip(string header, string value)
        {
            var sp = new StackPanel
            {
                Orientation = Orientation.Horizontal,
                Margin = new Thickness(0, 0, 12, 0)
            };

            var h = new TextBlock
            {
                Text = header,
                FontSize = 9,
                FontWeight = FontWeights.SemiBold,
                VerticalAlignment = VerticalAlignment.Center,
                Margin = new Thickness(0, 0, 4, 0)
            };
            h.SetResourceReference(TextBlock.ForegroundProperty, "TextFaint");

            var v = new TextBlock
            {
                Text = value,
                FontSize = 10,
                FontFamily = new FontFamily("Consolas"),
                VerticalAlignment = VerticalAlignment.Center
            };
            v.SetResourceReference(TextBlock.ForegroundProperty, "TextSecondary");

            sp.Children.Add(h);
            sp.Children.Add(v);
            return sp;
        }

        private Button MakeIconButton(PackIconKind kind, string tooltip)
        {
            var btn = new Button
            {
                Width = 28,
                Height = 28,
                Padding = new Thickness(0),
                Cursor = System.Windows.Input.Cursors.Hand,
                ToolTip = tooltip,
                Background = Brushes.Transparent,
                BorderBrush = null,
                Style = (Style)FindResource("MaterialDesignFlatButton")
            };
            var ic = new PackIcon
            {
                Kind = kind,
                Width = 15,
                Height = 15,
                HorizontalAlignment = HorizontalAlignment.Center,
                VerticalAlignment = VerticalAlignment.Center
            };
            ic.SetResourceReference(PackIcon.ForegroundProperty, "TextFaint");
            btn.Content = ic;
            return btn;
        }

        // ── Toast ─────────────────────────────────────────────────────────

        private void ShowToast(string message)
        {
            ToastText.Text = message;
            ToastBar.Visibility = Visibility.Visible;
            // Auto-dismiss after 4 seconds
            var timer = new System.Windows.Threading.DispatcherTimer
            {
                Interval = TimeSpan.FromSeconds(4)
            };
            timer.Tick += (_, _) =>
            {
                timer.Stop();
                ToastBar.Visibility = Visibility.Collapsed;
            };
            timer.Start();
        }

        private void ToastDismiss_Click(object sender, RoutedEventArgs e)
        {
            ToastBar.Visibility = Visibility.Collapsed;
        }

        // ── Persistence ───────────────────────────────────────────────────

        private async void SaveSettings()
        {
            try { await Globals.Container.GetInstance<IServerSettings>().UpdateSettingsAsync(); }
            catch { }
        }
    }
}
