using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Controls.Primitives;
using System.Windows.Input;
using System.Windows.Media;
using MaterialDesignThemes.Wpf;

namespace RhinoSniff.Views
{
    public partial class NmapScanner : UserControl
    {
        public enum Protocol { Tcp, Udp }

        public class PortResult
        {
            public int Port { get; set; }
            public string Proto { get; set; }
            public string Service { get; set; }
            public long ElapsedMs { get; set; }
            public string ElapsedText => $"{ElapsedMs} ms";
        }

        private readonly ObservableCollection<PortResult> _results = new();
        private CancellationTokenSource _cts;
        private Protocol _proto = Protocol.Tcp;

        // Tiny well-known service hint map — not exhaustive, just covers common ones.
        private static readonly Dictionary<int, string> ServiceHints = new()
        {
            [21] = "ftp", [22] = "ssh", [23] = "telnet", [25] = "smtp", [53] = "dns",
            [67] = "dhcp", [68] = "dhcp", [80] = "http", [110] = "pop3", [123] = "ntp",
            [135] = "msrpc", [137] = "netbios", [138] = "netbios", [139] = "netbios-ssn",
            [143] = "imap", [161] = "snmp", [389] = "ldap", [443] = "https", [445] = "smb",
            [465] = "smtps", [500] = "isakmp", [514] = "syslog", [515] = "lpd",
            [587] = "submission", [636] = "ldaps", [993] = "imaps", [995] = "pop3s",
            [1194] = "openvpn", [1433] = "mssql", [1521] = "oracle", [1723] = "pptp",
            [2049] = "nfs", [3074] = "xbox-live", [3128] = "http-proxy",
            [3306] = "mysql", [3389] = "rdp", [3478] = "stun", [3479] = "psn",
            [3480] = "psn", [3659] = "psn", [5060] = "sip", [5222] = "xmpp",
            [5353] = "mdns", [5432] = "postgresql", [5900] = "vnc", [6379] = "redis",
            [6667] = "irc", [8080] = "http-alt", [8443] = "https-alt",
            [9987] = "teamspeak", [27015] = "source", [27017] = "mongodb"
        };

        public NmapScanner()
        {
            InitializeComponent();
            ResultsList.ItemsSource = _results;
        }

        /// <summary>Called by MainWindow context-menu Port Scan handler.</summary>
        public void PrefillIp(string ip)
        {
            if (string.IsNullOrEmpty(ip)) return;
            TargetBox.Text = ip;
            TargetBox.Focus();
            TargetBox.CaretIndex = TargetBox.Text.Length;
        }

        private void Proto_Click(object sender, RoutedEventArgs e)
        {
            var isTcp = sender == TcpToggle;
            _proto = isTcp ? Protocol.Tcp : Protocol.Udp;
            TcpToggle.IsChecked = isTcp;
            UdpToggle.IsChecked = !isTcp;
            UdpHint.Visibility = isTcp ? Visibility.Collapsed : Visibility.Visible;
        }

        // Steppers
        private void ThreadsDec_Click(object s, RoutedEventArgs e) => Bump(ThreadsBox, -8, 1, 500);
        private void ThreadsInc_Click(object s, RoutedEventArgs e) => Bump(ThreadsBox, +8, 1, 500);
        private void TimeoutDec_Click(object s, RoutedEventArgs e) => Bump(TimeoutBox, -100, 50, 10000);
        private void TimeoutInc_Click(object s, RoutedEventArgs e) => Bump(TimeoutBox, +100, 50, 10000);

        private static void Bump(TextBox box, int delta, int min, int max)
        {
            if (!int.TryParse(box.Text, out var v)) v = min;
            v = Math.Clamp(v + delta, min, max);
            box.Text = v.ToString();
        }

        private async void Run_Click(object sender, RoutedEventArgs e)
        {
            var target = TargetBox.Text?.Trim();
            if (string.IsNullOrEmpty(target))
            {
                StatusLine.Text = "Enter a target.";
                return;
            }
            if (!int.TryParse(PortStartBox.Text, out var pStart) || pStart < 1 || pStart > 65535 ||
                !int.TryParse(PortEndBox.Text, out var pEnd) || pEnd < 1 || pEnd > 65535 ||
                pStart > pEnd)
            {
                StatusLine.Text = "Invalid port range (1-65535, start ≤ end).";
                return;
            }
            if (!int.TryParse(ThreadsBox.Text, out var threads) || threads < 1) threads = 64;
            if (!int.TryParse(TimeoutBox.Text, out var timeoutMs) || timeoutMs < 50) timeoutMs = 500;

            IPAddress targetIp;
            try
            {
                if (!IPAddress.TryParse(target, out targetIp))
                {
                    var entry = await Dns.GetHostAddressesAsync(target);
                    targetIp = Array.Find(entry, a => a.AddressFamily == AddressFamily.InterNetwork);
                    if (targetIp == null) { StatusLine.Text = $"Could not resolve {target}."; return; }
                }
            }
            catch (Exception ex) { StatusLine.Text = $"DNS lookup failed: {ex.Message}"; return; }

            _results.Clear();
            ResultsEmpty.Visibility = Visibility.Collapsed;
            ResultsHeader.Visibility = Visibility.Collapsed;
            ScanProgress.Value = 0;
            RunBtn.Visibility = Visibility.Collapsed;
            CancelBtn.Visibility = Visibility.Visible;
            RunText.Text = "Scanning...";
            RunIcon.Kind = PackIconKind.Loading;

            var protoLabel = _proto == Protocol.Tcp ? "TCP" : "UDP";
            var total = pEnd - pStart + 1;
            CardProtocol.Text = protoLabel;
            CardProgress.Text = $"0/{total}";
            CardDuration.Text = "N/A";
            CardOpenCount.Text = "0";

            _cts = new CancellationTokenSource();
            var token = _cts.Token;
            var sw = Stopwatch.StartNew();
            var done = 0;
            var openCount = 0;

            StatusLine.Text = $"Scanning {targetIp} ports {pStart}-{pEnd} ({protoLabel}) with {threads} threads, {timeoutMs}ms timeout...";
            ScanStateText.Text = $"Progress: 0/{total}";

            try
            {
                using var semaphore = new SemaphoreSlim(threads);
                var tasks = new List<Task>();

                for (int port = pStart; port <= pEnd; port++)
                {
                    if (token.IsCancellationRequested) break;
                    var p = port;
                    await semaphore.WaitAsync(token);
                    tasks.Add(Task.Run(async () =>
                    {
                        try
                        {
                            var (open, elapsed) = _proto == Protocol.Tcp
                                ? await ProbeTcpAsync(targetIp, p, timeoutMs, token)
                                : await ProbeUdpAsync(targetIp, p, timeoutMs, token);

                            if (open)
                            {
                                await Dispatcher.InvokeAsync(() =>
                                {
                                    _results.Add(new PortResult
                                    {
                                        Port = p,
                                        Proto = protoLabel,
                                        Service = ServiceHints.TryGetValue(p, out var svc) ? svc : "",
                                        ElapsedMs = elapsed
                                    });
                                    Interlocked.Increment(ref openCount);
                                    CardOpenCount.Text = openCount.ToString();
                                    ResultsHeader.Visibility = Visibility.Visible;
                                });
                            }
                        }
                        catch { }
                        finally
                        {
                            semaphore.Release();
                            var d = Interlocked.Increment(ref done);
                            if (d % 20 == 0 || d == total)
                                await Dispatcher.InvokeAsync(() =>
                                {
                                    ScanProgress.Value = d * 100.0 / total;
                                    CardProgress.Text = $"{d}/{total}";
                                    if (!token.IsCancellationRequested)
                                        ScanStateText.Text = $"Progress: {d}/{total}";
                                });
                        }
                    }, token));
                }

                await Task.WhenAll(tasks);
                sw.Stop();
                var ms = sw.ElapsedMilliseconds;
                CardDuration.Text = $"{ms}ms";
                CardProgress.Text = $"{done}/{total}";
                if (token.IsCancellationRequested)
                {
                    ScanStateText.Text = $"Finished (cancelled, {ms}ms)";
                    StatusLine.Text = $"Cancelled. Scanned {done}/{total} ports in {sw.Elapsed.TotalSeconds:F1}s. {openCount} open.";
                }
                else
                {
                    ScanStateText.Text = $"Finished (completed, {ms}ms)";
                    StatusLine.Text = $"Scan complete. {total} ports in {sw.Elapsed.TotalSeconds:F1}s. {openCount} open.";
                }
            }
            catch (OperationCanceledException)
            {
                sw.Stop();
                var ms = sw.ElapsedMilliseconds;
                CardDuration.Text = $"{ms}ms";
                ScanStateText.Text = $"Finished (cancelled, {ms}ms)";
                StatusLine.Text = $"Cancelled. {openCount} open so far.";
            }
            finally
            {
                ScanProgress.Value = 100;
                RunBtn.Visibility = Visibility.Visible;
                CancelBtn.Visibility = Visibility.Collapsed;
                RunText.Text = "Start Scan";
                RunIcon.Kind = PackIconKind.Play;
                if (_results.Count == 0)
                    ResultsEmpty.Visibility = Visibility.Visible;
            }
        }

        private void Cancel_Click(object sender, RoutedEventArgs e) => _cts?.Cancel();

        private static async Task<(bool open, long elapsed)> ProbeTcpAsync(IPAddress ip, int port, int timeoutMs, CancellationToken token)
        {
            var sw = Stopwatch.StartNew();
            try
            {
                using var client = new TcpClient();
                var connectTask = client.ConnectAsync(ip, port);
                using var cts = CancellationTokenSource.CreateLinkedTokenSource(token);
                cts.CancelAfter(timeoutMs);
                var completed = await Task.WhenAny(connectTask, Task.Delay(timeoutMs, cts.Token));
                sw.Stop();
                return (completed == connectTask && client.Connected, sw.ElapsedMilliseconds);
            }
            catch { sw.Stop(); return (false, sw.ElapsedMilliseconds); }
        }

        private static async Task<(bool open, long elapsed)> ProbeUdpAsync(IPAddress ip, int port, int timeoutMs, CancellationToken token)
        {
            // Definite-Open gating (Bug D v2.6.5):
            //   data back on recvTask ................. OPEN (report)
            //   timeout (no response, no ICMP unreach)  open|filtered (DROP per acceptance — too noisy)
            //   SocketException (ICMP port unreach) ... CLOSED (drop)
            var sw = Stopwatch.StartNew();
            try
            {
                using var udp = new UdpClient();
                udp.Client.ReceiveTimeout = timeoutMs;
                var empty = Array.Empty<byte>();
                await udp.SendAsync(empty, 0, new IPEndPoint(ip, port));

                var recvTask = udp.ReceiveAsync();
                var completed = await Task.WhenAny(recvTask, Task.Delay(timeoutMs, token));
                sw.Stop();
                if (completed != recvTask) return (false, sw.ElapsedMilliseconds); // timeout → drop
                try
                {
                    await recvTask; // rethrows if the receive faulted (e.g. ICMP unreach → ConnectionReset)
                    return (true, sw.ElapsedMilliseconds); // got a reply = definite open
                }
                catch { return (false, sw.ElapsedMilliseconds); } // closed or errored
            }
            catch (SocketException) { sw.Stop(); return (false, sw.ElapsedMilliseconds); }
            catch { sw.Stop(); return (false, sw.ElapsedMilliseconds); }
        }
    }
}
