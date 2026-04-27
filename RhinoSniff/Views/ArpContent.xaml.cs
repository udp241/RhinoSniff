using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Text.RegularExpressions;
using System.Threading;
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
using SharpPcap;
using SharpPcap.Npcap;

namespace RhinoSniff.Views
{
    /// <summary>
    /// Content-area ARP page (Phase 4). Replaces the side-panel wizard.
    /// Engine untouched: calls MainWindow.Set/GetArpDevices + Start/StopArpPoisoning + SyncArpToolbarState.
    /// </summary>
    public partial class ArpContent : UserControl
    {
        private readonly MainWindow _mainWindow;
        private readonly ICaptureDevice _device;
        private readonly NpcapDevice _npcapDevice;
        private readonly BindingList<ScannedDevice> _devices = new();
        private CancellationTokenSource _scanCts;

        private IPAddress _gatewayIp;
        private PhysicalAddress _gatewayMac;
        private ScannedDevice _selected;

        public ArpContent(MainWindow mainWindow, ICaptureDevice device)
        {
            _mainWindow = mainWindow;
            _device = device;
            _npcapDevice = (NpcapDevice)device;

            InitializeComponent();
            DeviceGrid.ItemsSource = _devices;
            _devices.ListChanged += (_, _) => UpdatePills();

            // Restore state if ARP already configured
            var existing = _mainWindow.GetArpDevices();
            if (existing.SourceLocalAddress != null)
            {
                _gatewayIp = existing.SourceLocalAddress;
                _gatewayMac = existing.SourcePhysicalAddress;
                GatewayText.Text = _gatewayIp.ToString();
                GatewayMacText.Text = _gatewayMac != null ? FormatMac(_gatewayMac) : "--:--:--:--:--:--";
                NullRouteBox.IsChecked = existing.IsNullRouted;

                // v2.9.0: prefer the Targets list (multi). Fall back to legacy single-target
                // field if Targets is empty (covers ArpDevice values created pre-v2.9 or by
                // legacy callers).
                var savedTargets = existing.Targets != null && existing.Targets.Count > 0
                    ? existing.Targets
                    : (existing.TargetLocalAddress != null && existing.TargetPhysicalAddress != null
                        ? new System.Collections.Generic.List<ArpTarget>
                          {
                              new() { Ip = existing.TargetLocalAddress, Mac = existing.TargetPhysicalAddress }
                          }
                        : null);

                if (savedTargets != null)
                {
                    foreach (var t in savedTargets)
                    {
                        if (t?.Ip == null) continue;
                        var dev = new ScannedDevice
                        {
                            IpAddress = t.Ip.ToString(),
                            MacAddress = t.Mac != null ? FormatMac(t.Mac) : "",
                            RawIp = t.Ip,
                            RawMac = t.Mac,
                            Source = "saved",
                            IsSelected = true
                        };
                        _devices.Add(dev);
                    }
                    ToggleBtn.IsEnabled = true;
                    SaveBtn.IsEnabled = !_mainWindow.IsPoisoningPublic;
                }

                UpdateToggleVisual();
            }
            else
            {
                AutoDetectGateway();
            }
        }

        // ── Gateway ────────────────────────────────────────────────────

        private void AutoDetectGateway()
        {
            try
            {
                var gw = _npcapDevice.Interface.GatewayAddresses;
                if (gw != null && gw.Count > 0)
                {
                    _gatewayIp = gw.FirstOrDefault(a =>
                        a.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork);
                    if (_gatewayIp != null)
                    {
                        GatewayText.Text = _gatewayIp.ToString();
                        GatewayMacText.Text = "resolving...";
                        _ = ResolveGatewayMacAsync();
                        return;
                    }
                }
                GatewayText.Text = "Not detected";
                GatewayMacText.Text = "add device manually";
            }
            catch (Exception ex)
            {
                GatewayText.Text = "Error";
                GatewayMacText.Text = ex.Message;
                _ = ex.AutoDumpExceptionAsync();
            }
        }

        private async Task ResolveGatewayMacAsync()
        {
            try
            {
                var mac = await Task.Run(() => ResolveMacFromIp(_gatewayIp));
                await Dispatcher.InvokeAsync(() =>
                {
                    if (mac != null)
                    {
                        _gatewayMac = mac;
                        GatewayMacText.Text = FormatMac(mac);
                    }
                    else
                    {
                        GatewayMacText.Text = "could not resolve";
                    }
                });
            }
            catch (Exception ex)
            {
                await ex.AutoDumpExceptionAsync();
            }
        }

        // ── Scan ──────────────────────────────────────────────────────

        private async void Scan_Click(object sender, RoutedEventArgs e)
        {
            if (_gatewayIp == null)
            {
                SetStatus("No gateway detected. Add devices manually via IP input above.");
                return;
            }

            _scanCts?.Cancel();
            _scanCts = new CancellationTokenSource();
            var token = _scanCts.Token;

            try
            {
                ScanBtn.IsEnabled = false;
                ScanText.Text = "Scanning...";
                ScanIcon.Kind = PackIconKind.Loading;
                SetStatus("Reading ARP table...");

                await Task.Run(() => ReadArpTable(token), token);

                if (token.IsCancellationRequested) return;

                if (!_devices.Any(d => d.Source == "arp"))
                {
                    await Dispatcher.InvokeAsync(() => { ScanText.Text = "Deep scan..."; SetStatus("Ping sweeping subnet..."); });
                    await Task.Run(() => PingSweepAndReRead(token), token);
                }

                SetStatus($"Scan complete. Found {_devices.Count} device(s).");
            }
            catch (OperationCanceledException) { }
            catch (Exception ex) { await ex.AutoDumpExceptionAsync(); SetStatus($"Scan error: {ex.Message}"); }
            finally
            {
                await Dispatcher.InvokeAsync(() =>
                {
                    ScanBtn.IsEnabled = true;
                    ScanText.Text = "Scan Network";
                    ScanIcon.Kind = PackIconKind.Wifi;
                });
            }
        }

        private void ReadArpTable(CancellationToken token)
        {
            try
            {
                if (_npcapDevice.Addresses == null || _npcapDevice.Addresses.Count == 0) return;
                var adapterIp = _npcapDevice.Addresses[0].Addr.ipAddress;
                var process = new Process
                {
                    StartInfo = new ProcessStartInfo
                    {
                        FileName = "arp.exe",
                        Arguments = $"-a -N {adapterIp}",
                        UseShellExecute = false,
                        RedirectStandardOutput = true,
                        CreateNoWindow = true
                    }
                };
                process.Start();
                var output = process.StandardOutput.ReadToEnd();
                process.WaitForExit();

                if (token.IsCancellationRequested) return;
                ParseArpOutput(output);
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                _ = ex.AutoDumpExceptionAsync();
            }
        }

        private void PingSweepAndReRead(CancellationToken token)
        {
            try
            {
                var subnet = string.Join(".", _gatewayIp.ToString().Split('.').Take(3));
                var tasks = new List<Task>();
                for (int i = 1; i <= 254; i++)
                {
                    if (token.IsCancellationRequested) return;
                    var ip = $"{subnet}.{i}";
                    tasks.Add(Task.Run(async () =>
                    {
                        try
                        {
                            using var p = new Ping();
                            await p.SendPingAsync(ip, 200);
                        }
                        catch { }
                    }));
                    if (tasks.Count >= 20)
                    {
                        Task.WaitAll(tasks.ToArray());
                        tasks.Clear();
                    }
                }
                if (tasks.Count > 0) Task.WaitAll(tasks.ToArray());
                if (token.IsCancellationRequested) return;
                ReadArpTable(token);
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                _ = ex.AutoDumpExceptionAsync();
            }
        }

        private void ParseArpOutput(string output)
        {
            var gatewayStr = _gatewayIp?.ToString();
            var gatewaySubnet = gatewayStr?.Split('.')[0];
            var results = new List<ScannedDevice>();

            foreach (var line in output.Split('\n'))
            {
                var trimmed = line.Trim();
                if (!trimmed.EndsWith("static") && !trimmed.EndsWith("dynamic")) continue;

                var macMatch = Regex.Match(trimmed, "(.{2}-.{2}-.{2}-.{2}-.{2}-.{2})");
                var ipMatch = Regex.Match(trimmed, @"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})");
                if (!macMatch.Success || !ipMatch.Success) continue;
                if (!IPAddress.TryParse(ipMatch.Groups[0].Value, out var ip)) continue;

                var ipStr = ip.ToString();
                if (ipStr.Contains("255")) continue;
                if (gatewaySubnet != null && ipStr.Split('.')[0] != gatewaySubnet) continue;
                if (ip.Equals(_gatewayIp)) continue;

                var macStr = macMatch.Groups[0].Value.ToUpper();
                if (macStr == "FF-FF-FF-FF-FF-FF") continue;
                if (results.Any(d => d.IpAddress == ipStr)) continue;

                results.Add(new ScannedDevice
                {
                    IpAddress = ipStr,
                    MacAddress = macStr.Replace('-', ':'),
                    RawMac = PhysicalAddress.Parse(macStr),
                    RawIp = ip,
                    Source = "arp"
                });
            }

            if (results.Count > 0)
            {
                Dispatcher.Invoke(() =>
                {
                    foreach (var dev in results)
                    {
                        if (!_devices.Any(d => d.IpAddress == dev.IpAddress))
                            _devices.Add(dev);
                    }
                });
            }
        }

        // ── Manual add ────────────────────────────────────────────────

        private void ManualIp_KeyDown(object sender, KeyEventArgs e)
        {
            if (e.Key == Key.Enter) ManualAdd_Click(sender, e);
        }

        private async void ManualAdd_Click(object sender, RoutedEventArgs e)
        {
            var ipText = ManualIpBox.Text?.Trim();
            if (string.IsNullOrEmpty(ipText) || !IPAddress.TryParse(ipText, out var address))
            {
                SetStatus("Enter a valid IPv4 address.");
                return;
            }
            if (_devices.Any(d => d.IpAddress == ipText))
            {
                SetStatus($"{ipText} already in list.");
                return;
            }

            ManualAddBtn.IsEnabled = false;
            SetStatus($"Resolving MAC for {ipText}...");

            try
            {
                var mac = await Task.Run(() => ResolveMacFromIp(address));
                if (mac == null)
                {
                    SetStatus($"Could not resolve MAC for {ipText}. Is the device online?");
                    return;
                }
                var dev = new ScannedDevice
                {
                    IpAddress = ipText,
                    MacAddress = FormatMac(mac),
                    RawIp = address,
                    RawMac = mac,
                    Source = "manual"
                };
                _devices.Add(dev);
                DeviceGrid.SelectedItem = dev;
                ManualIpBox.Text = "";
                SetStatus($"Added {ipText} ({FormatMac(mac)}).");
            }
            catch (Exception ex)
            {
                await ex.AutoDumpExceptionAsync();
                SetStatus($"Failed: {ex.Message}");
            }
            finally { ManualAddBtn.IsEnabled = true; }
        }

        // ── Refresh / Clear ───────────────────────────────────────────

        private void Refresh_Click(object sender, RoutedEventArgs e)
        {
            if (_gatewayIp == null) AutoDetectGateway();
            else _ = ResolveGatewayMacAsync();
            Scan_Click(sender, e);
        }

        private void Clear_Click(object sender, RoutedEventArgs e)
        {
            if (_mainWindow.IsPoisoningPublic)
            {
                SetStatus("Cannot clear while ARP is active. Stop ARP first.");
                return;
            }
            _scanCts?.Cancel();
            _devices.Clear();
            _selected = null;
            SaveBtn.IsEnabled = false;
            ToggleBtn.IsEnabled = false;
            SetStatus("Device list cleared.");
        }

        // ── Selection / Save / Toggle ─────────────────────────────────

        private void DeviceGrid_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            // v2.9.0: row selection no longer drives "save" enable. Checkbox column does.
            // Keep _selected for legacy code paths that still touch it (status text fallback).
            _selected = DeviceGrid.SelectedItem as ScannedDevice;
            UpdatePills();
        }

        private void DeviceCheckBox_Click(object sender, RoutedEventArgs e)
        {
            // Checkbox toggles Mode=TwoWay binding before this fires, so just refresh state
            UpdatePills();
            var checkedCount = _devices.Count(d => d.IsSelected);
            SaveBtn.IsEnabled = checkedCount > 0 && !_mainWindow.IsPoisoningPublic;
        }

        private void Save_Click(object sender, RoutedEventArgs e)
        {
            var selected = _devices.Where(d => d.IsSelected && d.RawIp != null && d.RawMac != null).ToList();
            if (selected.Count == 0) { SetStatus("Check one or more devices first."); return; }
            if (_gatewayMac == null) { SetStatus("Gateway MAC not resolved. Refresh to retry."); return; }

            var targets = selected.Select(d => new ArpTarget { Ip = d.RawIp, Mac = d.RawMac }).ToList();
            // Keep first selected in legacy fields too (back-compat for any caller that reads them)
            var first = targets[0];

            _mainWindow.SetArpDevices(new ArpDevice
            {
                SourceLocalAddress = _gatewayIp,
                SourcePhysicalAddress = _gatewayMac,
                TargetLocalAddress = first.Ip,
                TargetPhysicalAddress = first.Mac,
                Targets = targets,
                IsNullRouted = NullRouteBox.IsChecked == true
            });

            ToggleBtn.IsEnabled = true;
            SetStatus(targets.Count == 1
                ? $"Saved: intercepting {selected[0].IpAddress} via {_gatewayIp}."
                : $"Saved: intercepting {targets.Count} targets via {_gatewayIp}.");
        }

        private void Toggle_Click(object sender, RoutedEventArgs e)
        {
            if (_mainWindow.IsPoisoningPublic)
            {
                _mainWindow.StopArpPoisoning();
                SetStatus("ARP stopped.");
            }
            else
            {
                if (!_mainWindow.StartArpPoisoning())
                {
                    SetStatus("Start failed. Save targets first.");
                    return;
                }
                var checkedCount = _devices.Count(d => d.IsSelected);
                SetStatus(checkedCount == 1
                    ? $"ARP active: intercepting {_devices.First(d => d.IsSelected).IpAddress}."
                    : $"ARP active: intercepting {checkedCount} targets.");
            }
            UpdateToggleVisual();
            _mainWindow.SyncArpToolbarState();
        }

        private void UpdateToggleVisual()
        {
            var active = _mainWindow.IsPoisoningPublic;
            ToggleText.Text = active ? "Stop ARP" : "Start ARP";
            ToggleIcon.Kind = active ? PackIconKind.Stop : PackIconKind.Play;
            if (active)
            {
                ToggleBtn.SetResourceReference(Control.BackgroundProperty, "StatusDanger");
                ToggleBtn.SetResourceReference(Control.BorderBrushProperty, "StatusDanger");
            }
            else
            {
                ToggleBtn.SetResourceReference(Control.BackgroundProperty, "AccentTealDark");
                ToggleBtn.SetResourceReference(Control.BorderBrushProperty, "AccentTealDark");
            }
            var checkedCount = _devices.Count(d => d.IsSelected);
            SaveBtn.IsEnabled = checkedCount > 0 && !active;
        }

        // ── UI helpers ────────────────────────────────────────────────

        private void UpdatePills()
        {
            var count = _devices.Count;
            DeviceCountPill.Text = $"{count} DEVICE{(count == 1 ? "" : "S")}";
            EmptyState.Visibility = count == 0 ? Visibility.Visible : Visibility.Collapsed;
            DeviceGrid.Visibility = count == 0 ? Visibility.Collapsed : Visibility.Visible;

            var checkedCount = _devices.Count(d => d.IsSelected);
            if (checkedCount > 0)
            {
                SelectedPill.Text = checkedCount == 1
                    ? $"1 SELECTED"
                    : $"{checkedCount} SELECTED";
                SelectedPill.SetResourceReference(TextBlock.ForegroundProperty, "PillCapturingText");
                ((Border)SelectedPill.Parent).SetResourceReference(Border.BackgroundProperty, "PillCapturingBg");
            }
            else
            {
                SelectedPill.Text = "NONE SELECTED";
                SelectedPill.SetResourceReference(TextBlock.ForegroundProperty, "PillStoppedText");
                ((Border)SelectedPill.Parent).SetResourceReference(Border.BackgroundProperty, "PillStoppedBg");
            }
        }

        private void SetStatus(string text) => Dispatcher.Invoke(() => StatusLine.Text = text);

        private static PhysicalAddress ResolveMacFromIp(IPAddress ip)
        {
            try
            {
                using var pinger = new Ping();
                pinger.Send(ip, 1000);

                var proc = new Process
                {
                    StartInfo = new ProcessStartInfo
                    {
                        FileName = "arp.exe",
                        Arguments = $"-a {ip}",
                        UseShellExecute = false,
                        RedirectStandardOutput = true,
                        CreateNoWindow = true
                    }
                };
                proc.Start();
                var output = proc.StandardOutput.ReadToEnd();
                proc.WaitForExit();

                foreach (var line in output.Split('\n'))
                {
                    var trimmed = line.Trim();
                    if (!trimmed.EndsWith("static") && !trimmed.EndsWith("dynamic")) continue;
                    var m = Regex.Match(trimmed, "(.{2}-.{2}-.{2}-.{2}-.{2}-.{2})");
                    if (m.Success) return PhysicalAddress.Parse(m.Groups[0].Value.ToUpper());
                }
            }
            catch { }
            return null;
        }

        private static string FormatMac(PhysicalAddress mac)
            => BitConverter.ToString(mac.GetAddressBytes()).Replace('-', ':');

        public void CancelScan() => _scanCts?.Cancel();

        public class ScannedDevice : System.ComponentModel.INotifyPropertyChanged
        {
            public string IpAddress { get; set; }
            public string MacAddress { get; set; }
            public string Source { get; set; }
            public PhysicalAddress RawMac { get; set; }
            public IPAddress RawIp { get; set; }

            private bool _isSelected;
            public bool IsSelected
            {
                get => _isSelected;
                set
                {
                    if (_isSelected == value) return;
                    _isSelected = value;
                    PropertyChanged?.Invoke(this, new System.ComponentModel.PropertyChangedEventArgs(nameof(IsSelected)));
                }
            }

            public event System.ComponentModel.PropertyChangedEventHandler PropertyChanged;
        }
    }
}
