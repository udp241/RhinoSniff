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
using MaterialDesignThemes.Wpf;
using RhinoSniff.Interfaces;
using RhinoSniff.Models;
using RhinoSniff.Windows;
using SharpPcap;
using SharpPcap.Npcap;

namespace RhinoSniff.Views
{
    public partial class Arp : Page
    {
        private readonly MainWindow _mainWindow;
        private readonly NpcapDevice _npcapDevice;
        private readonly ICaptureDevice _device;
        private readonly BindingList<ScannedDevice> _scannedDevices = new();
        private CancellationTokenSource _scanCts;

        private IPAddress _gatewayIp;
        private PhysicalAddress _gatewayMac;

        public Arp(MainWindow mainWindow, ICaptureDevice device)
        {
            InitializeComponent();
            _mainWindow = mainWindow;
            _device = device;
            _npcapDevice = (NpcapDevice)device;
            DeviceList.ItemsSource = _scannedDevices;

            if (_mainWindow.IsPoisoningPublic)
            {
                ShowStep2Configured();
                return;
            }

            AutoDetectGateway();
        }

        // ═══════════════════════════════════════════
        //  STEP 1: Gateway
        // ═══════════════════════════════════════════

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
                        GatewayIpText.Text = _gatewayIp.ToString();
                        ResolveGatewayMac(_gatewayIp);
                        return;
                    }
                }
                GatewayIpText.Text = "Not detected";
                GatewayMacText.Text = "Enter manually below";
            }
            catch (Exception ex)
            {
                GatewayIpText.Text = "Error";
                GatewayMacText.Text = ex.Message;
                _ = ex.AutoDumpExceptionAsync();
            }
        }

        private async void ResolveGatewayMac(IPAddress ip)
        {
            try
            {
                GatewayMacText.Text = "Resolving...";
                var mac = await Task.Run(() => ResolveMacFromIp(ip));
                await Dispatcher.InvokeAsync(() =>
                {
                    if (mac != null)
                    {
                        _gatewayMac = mac;
                        GatewayMacText.Text = FormatMac(mac);
                    }
                    else
                    {
                        GatewayMacText.Text = "Could not resolve";
                    }
                });
            }
            catch (Exception ex)
            {
                await Dispatcher.InvokeAsync(() => GatewayMacText.Text = "Error");
                await ex.AutoDumpExceptionAsync();
            }
        }

        private void NextToStep2_Click(object sender, RoutedEventArgs e)
        {
            // Manual override
            if (!string.IsNullOrWhiteSpace(ManualGatewayBox.Text))
            {
                if (!IPAddress.TryParse(ManualGatewayBox.Text.Trim(), out var manual))
                {
                    ShowMsg("Invalid IP address format.");
                    return;
                }
                _gatewayIp = manual;
                _gatewayMac = null;
                ResolveGatewayMac(manual);
            }

            if (_gatewayIp == null)
            {
                ShowMsg("No gateway detected. Enter one manually.");
                return;
            }

            // Switch to Step 2
            Step1Panel.Visibility = Visibility.Collapsed;
            Step2Panel.Visibility = Visibility.Visible;
            DeviceList.Visibility = Visibility.Visible;
            BottomControls.Visibility = Visibility.Visible;
            ConfirmedGatewayText.Text = _gatewayIp.ToString();

            // Auto-scan
            Scan_Click(null, null);
        }

        private void BackToStep1_Click(object sender, RoutedEventArgs e)
        {
            // Cancel any running scan
            _scanCts?.Cancel();
            Step2Panel.Visibility = Visibility.Collapsed;
            DeviceList.Visibility = Visibility.Collapsed;
            BottomControls.Visibility = Visibility.Collapsed;
            Step1Panel.Visibility = Visibility.Visible;
        }

        // ═══════════════════════════════════════════
        //  STEP 2: Network Scan
        // ═══════════════════════════════════════════

        private async void Scan_Click(object sender, RoutedEventArgs e)
        {
            _scanCts?.Cancel();
            _scanCts = new CancellationTokenSource();
            var token = _scanCts.Token;

            try
            {
                ScanBtn.IsEnabled = false;
                ScanBtnText.Text = "SCANNING...";
                ScanIcon.Kind = PackIconKind.Loading;
                _scannedDevices.Clear();

                // Step 1: Read existing ARP table (fast, reliable)
                await Task.Run(() => ReadArpTable(token), token);

                if (token.IsCancellationRequested) return;

                // Step 2: If nothing found, do a small targeted ping sweep then re-read
                if (_scannedDevices.Count == 0)
                {
                    await Dispatcher.InvokeAsync(() =>
                        ScanBtnText.Text = "DEEP SCANNING...");

                    await Task.Run(() => PingSweepAndReRead(token), token);
                }
            }
            catch (OperationCanceledException) { }
            catch (Exception ex)
            {
                await ex.AutoDumpExceptionAsync();
            }
            finally
            {
                await Dispatcher.InvokeAsync(() =>
                {
                    ScanBtn.IsEnabled = true;
                    ScanBtnText.Text = "SCAN NETWORK";
                    ScanIcon.Kind = PackIconKind.Magnify;
                });
            }
        }

        /// <summary>
        /// Just read the ARP table — standard ARP probing approach.
        /// Devices that have communicated recently are already in the table.
        /// </summary>
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

        /// <summary>
        /// Fallback: ping common addresses, then re-read ARP table.
        /// Only runs if initial read found nothing.
        /// </summary>
        private void PingSweepAndReRead(CancellationToken token)
        {
            try
            {
                var subnet = string.Join(".", _gatewayIp.ToString().Split('.').Take(3));
                var tasks = new List<Task>();

                // Ping 1-254 with short timeout, 20 at a time to not flood
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

                    // Batch: wait every 20 pings to avoid flooding
                    if (tasks.Count >= 20)
                    {
                        Task.WaitAll(tasks.ToArray());
                        tasks.Clear();
                    }
                }
                if (tasks.Count > 0)
                    Task.WaitAll(tasks.ToArray());

                if (token.IsCancellationRequested) return;

                // Re-read ARP table after pings populated it
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

                // Check duplicates against what we already collected
                if (results.Any(d => d.IpAddress == ipStr)) continue;

                results.Add(new ScannedDevice
                {
                    IpAddress = ipStr,
                    MacAddress = macStr.Replace('-', ':'),
                    RawMac = PhysicalAddress.Parse(macStr),
                    RawIp = ip
                });
            }

            // Single UI update with all results — no repeated Dispatcher.Invoke calls
            if (results.Count > 0)
            {
                Dispatcher.Invoke(() =>
                {
                    foreach (var dev in results)
                    {
                        if (!_scannedDevices.Any(d => d.IpAddress == dev.IpAddress))
                            _scannedDevices.Add(dev);
                    }
                });
            }
        }

        // ═══════════════════════════════════════════
        //  MANUAL ADD
        // ═══════════════════════════════════════════

        private async void ManualAdd_Click(object sender, RoutedEventArgs e)
        {
            var ipText = ManualClientBox.Text?.Trim();
            if (string.IsNullOrEmpty(ipText) || !IPAddress.TryParse(ipText, out var address))
            {
                ShowMsg("Enter a valid IPv4 address.");
                return;
            }

            ManualAddBtn.IsEnabled = false;
            ManualAddText.Text = "...";

            try
            {
                var mac = await Task.Run(() => ResolveMacFromIp(address));
                if (mac == null)
                {
                    ShowMsg("Could not resolve MAC. Make sure the device is online and on the same network.");
                    return;
                }

                var macStr = FormatMac(mac);
                var exists = _scannedDevices.Any(d => d.IpAddress == ipText);
                if (!exists)
                {
                    _scannedDevices.Add(new ScannedDevice
                    {
                        IpAddress = ipText,
                        MacAddress = macStr,
                        RawMac = mac,
                        RawIp = address
                    });
                }

                // Auto-select
                var item = _scannedDevices.FirstOrDefault(d => d.IpAddress == ipText);
                if (item != null) DeviceList.SelectedItem = item;

                ManualClientBox.Text = "";
                ShowStatus($"Added {ipText} ({macStr})");
            }
            catch (Exception ex)
            {
                await ex.AutoDumpExceptionAsync();
                ShowStatus($"Failed: {ex.Message}");
            }
            finally
            {
                ManualAddBtn.IsEnabled = true;
                ManualAddText.Text = "ADD";
            }
        }

        // ═══════════════════════════════════════════
        //  SAVE + START/STOP ARP
        // ═══════════════════════════════════════════

        private void SaveArp_Click(object sender, RoutedEventArgs e)
        {
            if (DeviceList.SelectedItem is not ScannedDevice selected)
            {
                ShowMsg("Select a device from the list first.");
                return;
            }

            if (_gatewayMac == null)
            {
                ShowMsg("Gateway MAC not resolved. Go back and try again.");
                return;
            }

            _mainWindow.SetArpDevices(new ArpDevice
            {
                SourceLocalAddress = _gatewayIp,
                SourcePhysicalAddress = _gatewayMac,
                TargetLocalAddress = selected.RawIp,
                TargetPhysicalAddress = selected.RawMac,
                IsNullRouted = NullRouteToggle.IsChecked == true
            });

            ToggleArpBtn.IsEnabled = true;
            ShowStatus($"Saved: intercepting {selected.IpAddress} via {_gatewayIp}");
        }

        private void ToggleArp_Click(object sender, RoutedEventArgs e)
        {
            if (_mainWindow.IsPoisoningPublic)
            {
                _mainWindow.StopArpPoisoning();
                ToggleArpText.Text = "START ARP";
                ToggleArpIcon.Kind = PackIconKind.Play;
                ToggleArpBtn.SetResourceReference(System.Windows.Controls.Control.BackgroundProperty, "AccentTealDark");
                ToggleArpBtn.SetResourceReference(System.Windows.Controls.Control.BorderBrushProperty, "AccentTealDark");
                ShowStatus("ARP stopped.");
            }
            else
            {
                if (!_mainWindow.StartArpPoisoning())
                {
                    ShowStatus("Failed. Save ARP settings first.");
                    return;
                }
                ToggleArpText.Text = "STOP ARP";
                ToggleArpIcon.Kind = PackIconKind.Stop;
                ToggleArpBtn.SetResourceReference(System.Windows.Controls.Control.BackgroundProperty, "StatusDanger");
                ToggleArpBtn.SetResourceReference(System.Windows.Controls.Control.BorderBrushProperty, "StatusDanger");
                ShowStatus("ARP active — intercepting traffic.");
            }
            _mainWindow.SyncArpToolbarState();
        }

        // ═══════════════════════════════════════════
        //  HELPERS
        // ═══════════════════════════════════════════

        /// <summary>
        /// Ping an IP then read its MAC from the ARP table.
        /// Used for gateway resolution and manual device add.
        /// </summary>
        private static PhysicalAddress ResolveMacFromIp(IPAddress ip)
        {
            try
            {
                // Ping to populate ARP table
                using var pinger = new Ping();
                pinger.Send(ip, 1000);

                // Read ARP table for this IP
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
                    if (m.Success)
                        return PhysicalAddress.Parse(m.Groups[0].Value.ToUpper());
                }
            }
            catch { }
            return null;
        }

        private static string FormatMac(PhysicalAddress mac)
        {
            return BitConverter.ToString(mac.GetAddressBytes()).Replace('-', ':');
        }

        private void ShowStatus(string text)
        {
            StatusBorder.Visibility = Visibility.Visible;
            StatusText.Text = text;
        }

        /// <summary>
        /// Called by MainWindow when the side panel closes — cancels any running scan.
        /// </summary>
        public void CancelScan()
        {
            _scanCts?.Cancel();
        }

        private void ShowMsg(string msg)
        {
            Globals.Container.GetInstance<IThemeUtils>().MsgBox(new MsgBox
            {
                Icon = MsgBox.MsgBoxIcon.Warning,
                Button = MsgBox.MsgBoxBtn.Ok,
                Message = msg
            });
        }

        private void ShowStep2Configured()
        {
            Step1Panel.Visibility = Visibility.Collapsed;
            Step2Panel.Visibility = Visibility.Visible;
            DeviceList.Visibility = Visibility.Visible;
            BottomControls.Visibility = Visibility.Visible;

            var dev = _mainWindow.GetArpDevices();
            ConfirmedGatewayText.Text = dev.SourceLocalAddress?.ToString() ?? "?";
            _gatewayIp = dev.SourceLocalAddress;
            _gatewayMac = dev.SourcePhysicalAddress;

            ToggleArpBtn.IsEnabled = true;
            ToggleArpText.Text = "STOP ARP";
            ToggleArpIcon.Kind = PackIconKind.Stop;
            ToggleArpBtn.SetResourceReference(System.Windows.Controls.Control.BackgroundProperty, "StatusDanger");
            ToggleArpBtn.SetResourceReference(System.Windows.Controls.Control.BorderBrushProperty, "StatusDanger");
            ShowStatus($"ARP active: intercepting {dev.TargetLocalAddress}");
        }

        public class ScannedDevice
        {
            public string IpAddress { get; set; }
            public string MacAddress { get; set; }
            public PhysicalAddress RawMac { get; set; }
            public IPAddress RawIp { get; set; }
        }
    }
}
