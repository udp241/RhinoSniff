using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Controls.Primitives;
using System.Windows.Media;
using MaterialDesignThemes.Wpf;
using RhinoSniff.Classes;

namespace RhinoSniff.Views
{
    public partial class PacketTester : UserControl
    {
        private enum Protocol { Udp, Tcp }
        private enum PayloadType { Hex, Ascii }

        private Protocol _proto = Protocol.Udp;
        private PayloadType _payloadType = PayloadType.Hex;
        private CancellationTokenSource _cts;

        public PacketTester()
        {
            InitializeComponent();
        }

        /// <summary>Called by MainWindow context-menu Packet Test handler.</summary>
        public void PrefillIp(string ip)
        {
            if (string.IsNullOrEmpty(ip)) return;
            IpBox.Text = ip;
            IpBox.Focus();
            IpBox.CaretIndex = IpBox.Text.Length;
        }

        private void Proto_Click(object sender, RoutedEventArgs e)
        {
            var udp = sender == UdpToggle;
            _proto = udp ? Protocol.Udp : Protocol.Tcp;
            UdpToggle.IsChecked = udp;
            TcpToggle.IsChecked = !udp;
        }

        private void Payload_Click(object sender, RoutedEventArgs e)
        {
            var hex = sender == HexToggle;
            _payloadType = hex ? PayloadType.Hex : PayloadType.Ascii;
            HexToggle.IsChecked = hex;
            AsciiToggle.IsChecked = !hex;
        }

        private async void Send_Click(object sender, RoutedEventArgs e)
        {
            // ── Validate ──────────────────────────────────────────────────
            var ipText = IpBox.Text?.Trim();
            if (!IPAddress.TryParse(ipText, out var ip) || ip.AddressFamily != AddressFamily.InterNetwork)
            { StatusLine.Text = "Enter a valid IPv4 address."; return; }

            if (!int.TryParse(PortBox.Text, out var port) || port < 1 || port > 65535)
            { StatusLine.Text = "Invalid port (1-65535)."; return; }

            if (!int.TryParse(SrcPortBox.Text, out var srcPort) || srcPort < 0 || srcPort > 65535)
            { StatusLine.Text = "Invalid source port (0-65535)."; return; }

            if (!int.TryParse(CountBox.Text, out var count) || count < 1) count = 1;
            if (!int.TryParse(IntervalBox.Text, out var interval) || interval < 0) interval = 0;
            var loop = LoopBox.IsChecked == true;

            byte[] payload;
            try { payload = ParsePayload(PayloadBox.Text ?? "", _payloadType); }
            catch (Exception ex) { StatusLine.Text = $"Payload error: {ex.Message}"; return; }

            // UDP datagram cap (theoretical 65507 minus IP/UDP headers; OS will reject larger).
            // TCP can in principle send any size but a sane cap protects us from a paste-bomb.
            const int MaxPayload = 65000;
            if (payload.Length > MaxPayload)
            { StatusLine.Text = $"Payload too large ({payload.Length} bytes). Max is {MaxPayload}."; return; }

            // Non-private IP warning
            if (!IsPrivate(ip) && !Globals.Settings.DisableRemoteNetworkWarning)
            {
                bool approved;
                try { approved = await ConfirmRemoteTargetAsync(ip); }
                catch (Exception ex) { StatusLine.Text = $"Warning dialog error: {ex.Message}"; return; }
                if (!approved) { StatusLine.Text = "Cancelled."; return; }
            }

            // ── Run ───────────────────────────────────────────────────────
            _cts = new CancellationTokenSource();
            var token = _cts.Token;
            SendBtn.IsEnabled = false;
            StopBtn.IsEnabled = true;
            SendText.Text = loop ? "Looping..." : "Sending...";
            SendIcon.Kind = PackIconKind.Loading;

            AppendLog($"--- {_proto.ToString().ToUpper()} → {ip}:{port} src={(srcPort == 0 ? "auto" : srcPort.ToString())} " +
                      $"bytes={payload.Length} count={(loop ? "loop" : count.ToString())} ---");

            var sent = 0;
            var failed = 0;
            var cancelled = false;

            try
            {
                while (!token.IsCancellationRequested)
                {
                    if (!loop && sent >= count) break;

                    try
                    {
                        if (_proto == Protocol.Udp) await SendUdp(ip, port, srcPort, payload, token);
                        else                        await SendTcp(ip, port, srcPort, payload, token);
                        sent++;
                        AppendLog($"  sent #{sent} ({payload.Length} bytes)");
                    }
                    catch (OperationCanceledException) { cancelled = true; break; }
                    catch (Exception ex)
                    {
                        failed++;
                        AppendLog($"  fail #{sent + failed}: {ex.Message}");
                        // In loop mode, keep trying; in count mode, abort on failure.
                        if (!loop) break;
                    }

                    if (!loop && sent >= count) break;
                    if (interval > 0)
                    {
                        try { await Task.Delay(interval, token); }
                        catch (OperationCanceledException) { cancelled = true; break; }
                    }
                }

                AppendLog($"--- Stopped. Sent {sent}{(failed > 0 ? $", {failed} failed" : "")}. ---");
                StatusLine.Text = cancelled
                    ? $"Cancelled. Sent {sent}{(failed > 0 ? $", {failed} failed" : "")}."
                    : $"Done. Sent {sent}{(failed > 0 ? $", {failed} failed" : "")}.";
            }
            catch (Exception ex)
            {
                // async void safety net — without this, an unexpected exception crashes the app.
                AppendLog($"  ERROR: {ex.Message}");
                StatusLine.Text = $"Error: {ex.Message}";
            }
            finally
            {
                SendBtn.IsEnabled = true;
                StopBtn.IsEnabled = false;
                SendText.Text = "Send";
                SendIcon.Kind = PackIconKind.Send;
            }
        }

        private void Stop_Click(object sender, RoutedEventArgs e) => _cts?.Cancel();

        private async Task SendUdp(IPAddress ip, int port, int srcPort, byte[] data, CancellationToken token)
        {
            UdpClient udp;
            if (srcPort == 0)
            {
                udp = new UdpClient(AddressFamily.InterNetwork);
            }
            else
            {
                // SO_REUSEADDR before bind so rapid loops with explicit src-port don't hit
                // SocketException("Address already in use") during TIME_WAIT.
                udp = new UdpClient();
                udp.Client.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, true);
                udp.Client.Bind(new IPEndPoint(IPAddress.Any, srcPort));
            }
            try
            {
                await udp.SendAsync(data, data.Length, new IPEndPoint(ip, port)).WaitAsync(token);
            }
            finally { udp.Dispose(); }
        }

        private async Task SendTcp(IPAddress ip, int port, int srcPort, byte[] data, CancellationToken token)
        {
            TcpClient tcp;
            if (srcPort == 0)
            {
                tcp = new TcpClient(AddressFamily.InterNetwork);
            }
            else
            {
                tcp = new TcpClient();
                tcp.Client.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, true);
                tcp.Client.Bind(new IPEndPoint(IPAddress.Any, srcPort));
            }
            try
            {
                using var cts = CancellationTokenSource.CreateLinkedTokenSource(token);
                cts.CancelAfter(3000); // hardcoded 3s connect timeout — see backlog
                await tcp.ConnectAsync(ip, port, cts.Token);
                using var stream = tcp.GetStream();
                await stream.WriteAsync(data, 0, data.Length, token);
                await stream.FlushAsync(token);
            }
            finally { tcp.Dispose(); }
        }

        private static byte[] ParsePayload(string text, PayloadType type)
        {
            if (string.IsNullOrWhiteSpace(text)) return Array.Empty<byte>();
            if (type == PayloadType.Ascii) return Encoding.UTF8.GetBytes(text);

            // Hex: accept FF 00 A1, 0xFF,0x00,0xA1, FF00A1, FF-00-A1, FF:00:A1
            var cleaned = new StringBuilder(text.Length);
            int i = 0;
            while (i < text.Length)
            {
                char c = text[i];
                if (char.IsWhiteSpace(c) || c == ',' || c == '-' || c == ':') { i++; continue; }
                if (c == '0' && i + 1 < text.Length && (text[i + 1] == 'x' || text[i + 1] == 'X')) { i += 2; continue; }
                if (!IsHex(c)) throw new FormatException($"Invalid hex char '{c}'");
                cleaned.Append(c);
                i++;
            }
            var s = cleaned.ToString();
            if ((s.Length & 1) != 0) throw new FormatException("Hex string has odd number of digits");
            var bytes = new byte[s.Length / 2];
            for (int k = 0; k < bytes.Length; k++)
                bytes[k] = Convert.ToByte(s.Substring(k * 2, 2), 16);
            return bytes;
        }

        private static bool IsHex(char c) =>
            (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');

        // RFC 1918 + loopback + link-local
        private static bool IsPrivate(IPAddress ip)
        {
            if (IPAddress.IsLoopback(ip)) return true;
            var b = ip.GetAddressBytes();
            if (b.Length != 4) return false;
            if (b[0] == 10) return true;
            if (b[0] == 172 && b[1] >= 16 && b[1] <= 31) return true;
            if (b[0] == 192 && b[1] == 168) return true;
            if (b[0] == 169 && b[1] == 254) return true; // link-local
            if (b[0] == 127) return true;
            return false;
        }

        private async Task<bool> ConfirmRemoteTargetAsync(IPAddress ip)
        {
            var dialog = new Border
            {
                BorderThickness = new Thickness(1),
                CornerRadius = new CornerRadius(8),
                Padding = new Thickness(20),
                MaxWidth = 460
            };
            dialog.SetResourceReference(Border.BackgroundProperty, "CardBg");
            dialog.SetResourceReference(Border.BorderBrushProperty, "StatusWarning");
            var stack = new StackPanel();

            var icon = new PackIcon
            {
                Kind = PackIconKind.AlertOctagonOutline,
                Width = 28, Height = 28,
                HorizontalAlignment = HorizontalAlignment.Center,
                Margin = new Thickness(0, 0, 0, 10)
            };
            icon.SetResourceReference(PackIcon.ForegroundProperty, "StatusWarning");
            stack.Children.Add(icon);

            var title = new TextBlock
            {
                Text = "Remote network warning",
                FontSize = 15, FontWeight = FontWeights.SemiBold,
                HorizontalAlignment = HorizontalAlignment.Center,
                Margin = new Thickness(0, 0, 0, 10)
            };
            title.SetResourceReference(TextBlock.ForegroundProperty, "TextPrimary");
            stack.Children.Add(title);

            var body = new TextBlock
            {
                Text = "You are about to send packets to a public (remote) IP address. Make sure you have explicit authorization to test this network/host. Misuse may be illegal.",
                TextWrapping = TextWrapping.Wrap, FontSize = 12,
                TextAlignment = TextAlignment.Center,
                Margin = new Thickness(0, 0, 0, 14)
            };
            body.SetResourceReference(TextBlock.ForegroundProperty, "TextSecondary");
            stack.Children.Add(body);

            var dontWarnText = new TextBlock
            {
                Text = "Don't warn me again for remote targets",
                FontSize = 11,
                TextWrapping = TextWrapping.Wrap
            };
            dontWarnText.SetResourceReference(TextBlock.ForegroundProperty, "TextSecondary");
            var dontWarn = new CheckBox
            {
                Content = dontWarnText,
                Margin = new Thickness(0, 0, 0, 14),
                HorizontalAlignment = HorizontalAlignment.Center
            };
            dontWarn.SetResourceReference(Control.ForegroundProperty, "TextSecondary");
            stack.Children.Add(dontWarn);

            var btnRow = new StackPanel { Orientation = Orientation.Horizontal, HorizontalAlignment = HorizontalAlignment.Center };
            var cancel = new Button
            {
                Content = "Cancel", Height = 32, Padding = new Thickness(16, 0, 16, 0),
                Margin = new Thickness(0, 0, 6, 0), Cursor = System.Windows.Input.Cursors.Hand,
                Background = Brushes.Transparent,
                BorderThickness = new Thickness(1),
                Style = (Style)FindResource("MaterialDesignOutlinedButton")
            };
            cancel.SetResourceReference(Control.ForegroundProperty, "TextSecondary");
            cancel.SetResourceReference(Control.BorderBrushProperty, "CardBorder");
            ButtonAssist.SetCornerRadius(cancel, new CornerRadius(16));
            var proceed = new Button
            {
                Content = "I understand", Height = 32, Padding = new Thickness(18, 0, 18, 0),
                Cursor = System.Windows.Input.Cursors.Hand,
                BorderThickness = new Thickness(1),
                FontWeight = FontWeights.SemiBold,
                Style = (Style)FindResource("MaterialDesignFlatButton")
            };
            proceed.SetResourceReference(Control.BackgroundProperty, "StatusWarning");
            proceed.SetResourceReference(Control.ForegroundProperty, "TextOnAccent");
            proceed.SetResourceReference(Control.BorderBrushProperty, "StatusWarning");
            ButtonAssist.SetCornerRadius(proceed, new CornerRadius(16));

            var tcs = new TaskCompletionSource<bool>();
            cancel.Click += (_, _) => { DialogHost.Close("PacketTesterDialog", false); tcs.TrySetResult(false); };
            proceed.Click += (_, _) =>
            {
                if (dontWarn.IsChecked == true)
                {
                    Globals.Settings.DisableRemoteNetworkWarning = true;
                    _ = Globals.Container.GetInstance<RhinoSniff.Interfaces.IServerSettings>().UpdateSettingsAsync();
                }
                DialogHost.Close("PacketTesterDialog", true);
                tcs.TrySetResult(true);
            };
            btnRow.Children.Add(cancel);
            btnRow.Children.Add(proceed);
            stack.Children.Add(btnRow);

            dialog.Child = stack;
            await DialogHost.Show(dialog, "PacketTesterDialog");
            return await tcs.Task;
        }

        private void AppendLog(string line) => Dispatcher.Invoke(() =>
        {
            LogBox.AppendText($"[{DateTime.Now:HH:mm:ss.fff}] {line}\n");
            LogScroller.ScrollToBottom();
        });

        private void ClearLog_Click(object sender, RoutedEventArgs e) => LogBox.Clear();
    }
}
