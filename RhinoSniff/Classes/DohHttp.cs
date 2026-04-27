using System;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;
using Newtonsoft.Json.Linq;

namespace RhinoSniff.Classes
{
    /// <summary>
    /// DNS-over-HTTPS helper. Bypasses Windows' system resolver (and therefore the hosts file)
    /// by resolving hostnames via Cloudflare 1.1.1.1 JSON DoH endpoint, then connecting directly
    /// to the resolved IP. Same pattern as isp.c's DoH fix — per-process, system-wide blocks stay intact.
    /// </summary>
    public static class DohHttp
    {
        private const string DohUrl = "https://1.1.1.1/dns-query";

        // DoH client itself: connects to literal 1.1.1.1 IP, so no DNS needed.
        // Cert is valid for cloudflare-dns.com + 1.1.1.1 SANs — normal validation works.
        private static readonly HttpClient _dohClient = new(new SocketsHttpHandler
        {
            UseProxy = false,
            UseCookies = false
        })
        {
            Timeout = TimeSpan.FromSeconds(8)
        };

        /// <summary>Resolve a hostname to an IPv4 via Cloudflare DoH. Returns null on failure.</summary>
        public static async Task<IPAddress> ResolveAsync(string host, CancellationToken ct = default)
        {
            try
            {
                using var req = new HttpRequestMessage(HttpMethod.Get, $"{DohUrl}?name={Uri.EscapeDataString(host)}&type=A");
                req.Headers.Accept.Clear();
                req.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/dns-json"));
                using var resp = await _dohClient.SendAsync(req, ct);
                if (!resp.IsSuccessStatusCode) return null;

                var body = await resp.Content.ReadAsStringAsync(ct);
                var doc = JObject.Parse(body);
                if (doc["Answer"] is not JArray answers) return null;

                foreach (var a in answers)
                {
                    // type 1 = A record
                    if ((int?)a["type"] == 1 && IPAddress.TryParse((string)a["data"], out var ip))
                        return ip;
                }
                return null;
            }
            catch
            {
                return null;
            }
        }

        /// <summary>
        /// Build an HttpClient that does its own DNS via DoH for every outbound connection.
        /// Other processes on the machine are unaffected — their resolver still hits the hosts file.
        /// </summary>
        public static HttpClient CreateClient(TimeSpan? timeout = null)
        {
            var handler = new SocketsHttpHandler
            {
                UseProxy = false,
                UseCookies = false,
                ConnectCallback = async (context, ct) =>
                {
                    IPAddress ip;
                    if (!IPAddress.TryParse(context.DnsEndPoint.Host, out ip))
                    {
                        ip = await ResolveAsync(context.DnsEndPoint.Host, ct);
                        if (ip == null)
                            throw new IOException($"DoH could not resolve {context.DnsEndPoint.Host}");
                    }
                    var socket = new Socket(SocketType.Stream, ProtocolType.Tcp) { NoDelay = true };
                    try
                    {
                        await socket.ConnectAsync(new IPEndPoint(ip, context.DnsEndPoint.Port), ct);
                        return new NetworkStream(socket, ownsSocket: true);
                    }
                    catch
                    {
                        socket.Dispose();
                        throw;
                    }
                }
            };
            return new HttpClient(handler)
            {
                Timeout = timeout ?? TimeSpan.FromSeconds(12)
            };
        }
    }
}
