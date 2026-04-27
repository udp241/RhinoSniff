using System;
using System.Diagnostics;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Controls.Primitives;
using System.Windows.Media;
using MaterialDesignThemes.Wpf;

namespace RhinoSniff.Views
{
    public partial class PingTool : UserControl
    {
        public enum PingMode { Icmp, Tcp, Udp }

        private PingMode _mode = PingMode.Icmp;
        private CancellationTokenSource _cts;
        private int _sent, _replied, _lost;
        private long _totalMs;

        public PingTool()
        {
            InitializeComponent();
        }

        private void Proto_Click(object sender, RoutedEventArgs e)
        {
            IcmpToggle.IsChecked = sender == IcmpToggle;
            TcpToggle.IsChecked = sender == TcpToggle;
            UdpToggle.IsChecked = sender == UdpToggle;
            _mode = sender == TcpToggle ? PingMode.Tcp : sender == UdpToggle ? PingMode.Udp : PingMode.Icmp;

            PortPanel.Visibility = _mode == PingMode.Icmp ? Visibility.Collapsed : Visibility.Visible;
            PayloadPanel.Visibility = _mode == PingMode.Icmp ? Visibility.Visible : Visibility.Collapsed;
        }

        private async void Start_Click(object sender, RoutedEventArgs e)
        {
            var target = TargetBox.Text?.Trim();
            if (string.IsNullOrEmpty(target)) { StatusLine.Text = "Enter a target."; return; }

            IPAddress ip;
            try
            {
                if (!IPAddress.TryParse(target, out ip))
                {
                    var entries = await Dns.GetHostAddressesAsync(target);
                    ip = Array.Find(entries, a => a.AddressFamily == AddressFamily.InterNetwork);
                    if (ip == null) { StatusLine.Text = $"Could not resolve {target}."; return; }
                    AppendLog($"Resolved {target} → {ip}");
                }
            }
            catch (Exception ex) { StatusLine.Text = $"DNS failed: {ex.Message}"; return; }

            if (!int.TryParse(CountBox.Text, out var count) || count < 1) count = 4;
            if (!int.TryParse(TimeoutBox.Text, out var timeout) || timeout < 50) timeout = 1000;
            if (!int.TryParse(IntervalBox.Text, out var interval) || interval < 0) interval = 1000;
            int port = 0, payload = 32;
            if (_mode != PingMode.Icmp && (!int.TryParse(PortBox.Text, out port) || port < 1 || port > 65535))
            { StatusLine.Text = "Invalid port."; return; }
            if (_mode == PingMode.Icmp && (!int.TryParse(PayloadBox.Text, out payload) || payload < 0 || payload > 65500))
                payload = 32;

            _sent = _replied = _lost = 0;
            _totalMs = 0;
            UpdateStats();

            StartBtn.IsEnabled = false;
            StopBtn.IsEnabled = true;
            StartText.Text = "Running...";
            StartIcon.Kind = PackIconKind.Loading;

            var targetLabel = _mode == PingMode.Icmp ? ip.ToString() : $"{ip}:{port}";
            AppendLog($"--- Pinging {targetLabel} [{_mode.ToString().ToUpper()}] ---");
            StatusLine.Text = $"Pinging {targetLabel}...";

            _cts = new CancellationTokenSource();
            var token = _cts.Token;

            try
            {
                for (int i = 0; i < count; i++)
                {
                    if (token.IsCancellationRequested) break;
                    await SendOne(ip, port, timeout, payload, i + 1, token);
                    if (i < count - 1 && interval > 0)
                    {
                        try { await Task.Delay(interval, token); } catch { break; }
                    }
                }
            }
            catch (OperationCanceledException) { }
            finally
            {
                AppendLog($"--- Done. Sent={_sent} Replied={_replied} Lost={_lost} ---");
                StatusLine.Text = $"Finished. {_replied}/{_sent} replies.";
                StartBtn.IsEnabled = true;
                StopBtn.IsEnabled = false;
                StartText.Text = "Start";
                StartIcon.Kind = PackIconKind.Play;
            }
        }

        private async Task SendOne(IPAddress ip, int port, int timeout, int payloadSize, int seq, CancellationToken token)
        {
            _sent++;
            var sw = Stopwatch.StartNew();
            bool replied = false;
            string detail = "";

            try
            {
                switch (_mode)
                {
                    case PingMode.Icmp:
                    {
                        using var pinger = new Ping();
                        var payload = new byte[payloadSize];
                        for (int i = 0; i < payload.Length; i++) payload[i] = (byte)('a' + (i % 26));
                        var reply = await pinger.SendPingAsync(ip, timeout, payload);
                        sw.Stop();
                        if (reply.Status == IPStatus.Success)
                        {
                            replied = true;
                            detail = $"seq={seq} time={reply.RoundtripTime}ms ttl={reply.Options?.Ttl ?? 0} size={payloadSize}";
                            _totalMs += reply.RoundtripTime;
                        }
                        else detail = $"seq={seq} {reply.Status}";
                        break;
                    }
                    case PingMode.Tcp:
                    {
                        using var client = new TcpClient();
                        var connect = client.ConnectAsync(ip, port);
                        using var cts = CancellationTokenSource.CreateLinkedTokenSource(token);
                        cts.CancelAfter(timeout);
                        var done = await Task.WhenAny(connect, Task.Delay(timeout, cts.Token));
                        sw.Stop();
                        if (done == connect && client.Connected)
                        {
                            replied = true;
                            detail = $"seq={seq} tcp_connect time={sw.ElapsedMilliseconds}ms";
                            _totalMs += sw.ElapsedMilliseconds;
                        }
                        else detail = $"seq={seq} timeout / refused";
                        break;
                    }
                    case PingMode.Udp:
                    {
                        using var udp = new UdpClient();
                        udp.Client.ReceiveTimeout = timeout;
                        await udp.SendAsync(Array.Empty<byte>(), 0, new IPEndPoint(ip, port));
                        var recv = udp.ReceiveAsync();
                        var done = await Task.WhenAny(recv, Task.Delay(timeout, token));
                        sw.Stop();
                        // If ICMP unreachable arrives, SendAsync/ReceiveAsync would throw SocketException.
                        replied = true;
                        detail = $"seq={seq} udp sent, no ICMP unreachable (open|filtered) time={sw.ElapsedMilliseconds}ms";
                        _totalMs += sw.ElapsedMilliseconds;
                        break;
                    }
                }
            }
            catch (SocketException sx)
            {
                sw.Stop();
                detail = $"seq={seq} {sx.SocketErrorCode}";
            }
            catch (Exception ex)
            {
                sw.Stop();
                detail = $"seq={seq} error: {ex.Message}";
            }

            if (replied) _replied++; else _lost++;
            AppendLog((replied ? "  ok   " : "  fail ") + detail);
            UpdateStats();
        }

        private void UpdateStats()
        {
            Dispatcher.Invoke(() =>
            {
                SentStat.Text = _sent.ToString();
                RepliedStat.Text = _replied.ToString();
                LostStat.Text = _lost.ToString();
                AvgStat.Text = _replied > 0 ? (_totalMs / _replied).ToString() : "—";
                LossStat.Text = _sent > 0 ? $"{_lost * 100 / _sent}%" : "0%";
            });
        }

        private void AppendLog(string line)
        {
            Dispatcher.Invoke(() =>
            {
                var ts = DateTime.Now.ToString("HH:mm:ss.fff");
                LogBox.AppendText($"[{ts}] {line}\n");
                LogScroller.ScrollToBottom();
            });
        }

        private void ClearLog_Click(object sender, RoutedEventArgs e)
        {
            LogBox.Clear();
            _sent = _replied = _lost = 0;
            _totalMs = 0;
            UpdateStats();
        }

        private void Stop_Click(object sender, RoutedEventArgs e) => _cts?.Cancel();
    }
}
