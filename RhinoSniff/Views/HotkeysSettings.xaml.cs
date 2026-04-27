using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
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
    public partial class HotkeysSettings : UserControl
    {
        private readonly MainWindow _host;

        // Category grouping shown in the UI. Order here = display order.
        private static readonly (string Title, string Icon, (HotkeyAction Action, string Label)[] Items)[] Categories =
        {
            ("PACKET CAPTURE", "Play", new[]
            {
                (HotkeyAction.ToggleCapture, "Start / Stop Capture"),
                (HotkeyAction.ClearCapture, "Clear Capture Results"),
                (HotkeyAction.SwitchTrafficView, "Switch Traffic View (All / Filtered)"),
            }),
            ("ARP SPOOFING", "AccessPointNetwork", new[]
            {
                (HotkeyAction.ToggleArp, "Start / Stop ARP Monitoring"),
            }),
            ("NAVIGATION", "Compass", new[]
            {
                (HotkeyAction.GoToNetworkMonitor, "Go to Network Monitor"),
                (HotkeyAction.GoToPacketFilters, "Go to Packet Filters"),
                (HotkeyAction.GoToArp, "Go to ARP Network Discovery"),
                (HotkeyAction.GoToSettings, "Go to Settings"),
            }),
            ("EXPORT", "FileExportOutline", new[]
            {
                (HotkeyAction.QuickExportCsv, "Quick Export (CSV)"),
            }),
        };

        public HotkeysSettings(MainWindow host)
        {
            _host = host;
            InitializeComponent();
            Globals.Settings.Hotkeys ??= new Dictionary<HotkeyAction, HotkeyBinding>();
            Render();
        }

        private void Render()
        {
            CategoriesHost.Children.Clear();
            foreach (var cat in Categories)
            {
                CategoriesHost.Children.Add(BuildCategoryCard(cat.Title, cat.Icon, cat.Items));
            }
            UpdateBoundCount();
        }

        private void UpdateBoundCount()
        {
            var n = Globals.Settings.Hotkeys.Count(kv => kv.Value != null && kv.Value.IsSet);
            BoundPillText.Text = n == 1 ? "1 BOUND" : $"{n} BOUND";
        }

        private Border BuildCategoryCard(string title, string iconKind, (HotkeyAction Action, string Label)[] items)
        {
            var card = new Border
            {
                Background = (Brush)FindResource("CardBg"),
                BorderBrush = (Brush)FindResource("CardBorder"),
                BorderThickness = new Thickness(1),
                CornerRadius = new CornerRadius(8),
                Padding = new Thickness(16),
                Margin = new Thickness(0, 0, 0, 12)
            };

            var stack = new StackPanel();

            var header = new StackPanel { Orientation = Orientation.Horizontal, Margin = new Thickness(0, 0, 0, 10) };
            if (Enum.TryParse<PackIconKind>(iconKind, out var kind))
            {
                header.Children.Add(new PackIcon
                {
                    Kind = kind, Width = 16, Height = 16,
                    Foreground = (Brush)FindResource("AccentTeal"),
                    VerticalAlignment = VerticalAlignment.Center,
                    Margin = new Thickness(0, 0, 8, 0)
                });
            }
            header.Children.Add(new TextBlock
            {
                Text = title, FontSize = 11, FontWeight = FontWeights.Bold,
                Foreground = (Brush)FindResource("TextSecondary"),
                VerticalAlignment = VerticalAlignment.Center
            });
            stack.Children.Add(header);

            foreach (var item in items)
                stack.Children.Add(BuildRow(item.Action, item.Label));

            card.Child = stack;
            return card;
        }

        private Grid BuildRow(HotkeyAction action, string label)
        {
            var row = new Grid { Margin = new Thickness(0, 0, 0, 8) };
            row.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
            row.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(210) });
            row.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });

            var name = new TextBlock
            {
                Text = label, FontSize = 12,
                Foreground = (Brush)FindResource("TextPrimary"),
                VerticalAlignment = VerticalAlignment.Center
            };
            Grid.SetColumn(name, 0);
            row.Children.Add(name);

            var capture = new TextBox
            {
                Height = 30, VerticalContentAlignment = VerticalAlignment.Center,
                FontSize = 11, IsReadOnly = true, Cursor = Cursors.Hand,
                Background = (Brush)FindResource("InputBg"),
                BorderBrush = (Brush)FindResource("InputBorder"),
                Foreground = (Brush)FindResource("TextPrimary"),
                Padding = new Thickness(8, 0, 8, 0),
                Tag = action,
                ToolTip = "Click to bind — then press a key combo. Backspace/Delete to clear."
            };
            var existing = Globals.Settings.Hotkeys.TryGetValue(action, out var cur) ? cur : null;
            capture.Text = existing != null && existing.IsSet ? existing.Display() : "Not set";
            capture.PreviewKeyDown += CaptureBox_PreviewKeyDown;
            capture.GotFocus += (_, _) => capture.Text = "Press a combo...";
            capture.LostFocus += (_, _) =>
            {
                var b = Globals.Settings.Hotkeys.TryGetValue(action, out var x) ? x : null;
                capture.Text = b != null && b.IsSet ? b.Display() : "Not set";
            };
            Grid.SetColumn(capture, 1);
            row.Children.Add(capture);

            var testBtn = new Button
            {
                Height = 26, Margin = new Thickness(8, 0, 0, 0), Padding = new Thickness(10, 0, 10, 0),
                Background = (Brush)FindResource("SidebarItemHover"),
                Foreground = (Brush)FindResource("TextPrimary"),
                Style = (Style)FindResource("MaterialDesignFlatButton"),
                Cursor = Cursors.Hand,
                Tag = action,
                ToolTip = "Fire this action now (test wiring)"
            };
            ButtonAssist.SetCornerRadius(testBtn, new CornerRadius(4));
            var testContent = new StackPanel { Orientation = Orientation.Horizontal };
            testContent.Children.Add(new PackIcon { Kind = PackIconKind.FlashOutline, Width = 12, Height = 12, VerticalAlignment = VerticalAlignment.Center });
            testContent.Children.Add(new TextBlock { Text = "Test", Margin = new Thickness(4, 0, 0, 0), FontSize = 11 });
            testBtn.Content = testContent;
            testBtn.Click += TestBtn_Click;
            Grid.SetColumn(testBtn, 2);
            row.Children.Add(testBtn);

            return row;
        }

        private async void CaptureBox_PreviewKeyDown(object sender, KeyEventArgs e)
        {
            if (sender is not TextBox tb || tb.Tag is not HotkeyAction action) return;
            e.Handled = true;

            // Clear binding
            if (e.Key == Key.Back || e.Key == Key.Delete || e.Key == Key.Escape)
            {
                Globals.Settings.Hotkeys[action] = new HotkeyBinding();
                tb.Text = "Not set";
                await PersistAndReapply(action);
                return;
            }

            // Ignore pure modifier keys pressed alone
            if (e.Key is Key.LeftCtrl or Key.RightCtrl
                or Key.LeftShift or Key.RightShift
                or Key.LeftAlt or Key.RightAlt
                or Key.LWin or Key.RWin
                or Key.System) return;

            var actualKey = e.Key == Key.System ? e.SystemKey : e.Key;

            uint mods = 0;
            if ((Keyboard.Modifiers & ModifierKeys.Alt) == ModifierKeys.Alt) mods |= 1;
            if ((Keyboard.Modifiers & ModifierKeys.Control) == ModifierKeys.Control) mods |= 2;
            if ((Keyboard.Modifiers & ModifierKeys.Shift) == ModifierKeys.Shift) mods |= 4;
            if ((Keyboard.Modifiers & ModifierKeys.Windows) == ModifierKeys.Windows) mods |= 8;

            if (mods == 0)
            {
                _host?.NotifyPublic(NotificationType.Alert,
                    "Hotkeys require at least one modifier (Ctrl / Shift / Alt / Win).");
                return;
            }

            var vk = (uint)KeyInterop.VirtualKeyFromKey(actualKey);
            if (vk == 0) return;

            var binding = new HotkeyBinding { Modifiers = mods, Vk = vk };
            Globals.Settings.Hotkeys[action] = binding;
            tb.Text = binding.Display();
            await PersistAndReapply(action);
        }

        private async Task PersistAndReapply(HotkeyAction action)
        {
            await Globals.Container.GetInstance<IServerSettings>().UpdateSettingsAsync();
            UpdateBoundCount();

            // Reapply just this action to avoid blowing away other working bindings on conflict
            var mgr = _host?.Hotkeys;
            if (mgr == null) return;
            var binding = Globals.Settings.Hotkeys.TryGetValue(action, out var b) ? b : null;
            var result = mgr.Register(action, binding);
            switch (result)
            {
                case GlobalHotkeyManager.RegisterResult.Ok:
                    if (binding != null && binding.IsSet)
                        _host?.NotifyPublic(NotificationType.Info, $"Bound {binding.Display()} → {action}");
                    else
                        _host?.NotifyPublic(NotificationType.Info, $"Cleared hotkey for {action}");
                    break;
                case GlobalHotkeyManager.RegisterResult.Conflict:
                    _host?.NotifyPublic(NotificationType.Alert,
                        $"That combo is already taken by another app. Pick a different one.");
                    break;
                case GlobalHotkeyManager.RegisterResult.InvalidCombo:
                    _host?.NotifyPublic(NotificationType.Alert, "Invalid combo.");
                    break;
                case GlobalHotkeyManager.RegisterResult.Error:
                    _host?.NotifyPublic(NotificationType.Error, "Failed to register hotkey.");
                    break;
            }
        }

        private void TestBtn_Click(object sender, RoutedEventArgs e)
        {
            if (sender is not FrameworkElement fe || fe.Tag is not HotkeyAction action) return;
            _host?.FireHotkeyAction(action);
            _host?.NotifyPublic(NotificationType.Info, $"Test: fired {action}");
        }

        private async void ResetAll_Click(object sender, RoutedEventArgs e)
        {
            var n = Globals.Settings.Hotkeys.Count(kv => kv.Value != null && kv.Value.IsSet);
            if (n == 0) return;
            var confirm = MessageBox.Show(Window.GetWindow(this),
                $"Clear all {n} hotkey binding{(n == 1 ? "" : "s")}?",
                "Reset Hotkeys", MessageBoxButton.YesNo, MessageBoxImage.Question);
            if (confirm != MessageBoxResult.Yes) return;
            Globals.Settings.Hotkeys.Clear();
            await Globals.Container.GetInstance<IServerSettings>().UpdateSettingsAsync();
            _host?.Hotkeys?.UnregisterAll();
            Render();
            _host?.NotifyPublic(NotificationType.Info, "All hotkeys cleared.");
        }
    }
}
