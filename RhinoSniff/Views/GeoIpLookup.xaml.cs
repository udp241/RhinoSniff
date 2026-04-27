using System;
using System.Net;
using System.Net.Http;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using MaterialDesignThemes.Wpf;
using Newtonsoft.Json;
using RhinoSniff.Classes;
using RhinoSniff.Models;

namespace RhinoSniff.Views
{
    public partial class GeoIpLookup : UserControl
    {
        // DoH-backed HttpClient bypasses Windows' resolver → sidesteps RhinoGPS's hosts blocks
        // on ip-api.com / ipapi.co / ipinfo.io. Same pattern as isp.c.
        private static readonly HttpClient _http = DohHttp.CreateClient(TimeSpan.FromSeconds(12));

        public GeoIpLookup()
        {
            InitializeComponent();
        }

        /// <summary>Called by MainWindow context-menu Geo IP Lookup handler.
        /// Pre-fills the IP and immediately runs the lookup.</summary>
        public void PrefillIpAndLookup(string ip)
        {
            if (string.IsNullOrEmpty(ip)) return;
            IpBox.Text = ip;
            Lookup_Click(this, new RoutedEventArgs());
        }

        private void IpBox_KeyDown(object sender, KeyEventArgs e)
        {
            if (e.Key == Key.Enter) Lookup_Click(sender, e);
        }

        private async void Lookup_Click(object sender, RoutedEventArgs e)
        {
            var text = IpBox.Text?.Trim();
            if (string.IsNullOrEmpty(text) || !IPAddress.TryParse(text, out var ip))
            {
                ShowError("Enter a valid IPv4 address.");
                return;
            }

            ResultCard.Visibility = Visibility.Collapsed;
            ErrorCard.Visibility = Visibility.Collapsed;
            LookupBtn.IsEnabled = false;
            LookupText.Text = "Looking up...";
            LookupIcon.Kind = PackIconKind.Loading;

            try
            {
                // Single-shot ip-api call, fields bitmask = 66846719 matches Web.cs
                var url = $"http://ip-api.com/json/{ip}?fields=66846719";
                using var resp = await _http.GetAsync(url);

                if (resp.StatusCode == HttpStatusCode.Forbidden || resp.StatusCode == (HttpStatusCode)429)
                {
                    ShowError("ip-api rate-limited this request. Wait ~60s and retry.");
                    return;
                }
                if (!resp.IsSuccessStatusCode)
                {
                    ShowError($"ip-api returned HTTP {(int)resp.StatusCode} {resp.StatusCode}.");
                    return;
                }

                var body = await resp.Content.ReadAsStringAsync();
                var parsed = JsonConvert.DeserializeObject<StatusGeoResponse>(body);

                if (parsed == null)
                {
                    ShowError("Could not parse ip-api response.");
                    return;
                }
                if (parsed.Status != "success")
                {
                    var msg = string.IsNullOrWhiteSpace(parsed.Message) ? "unknown" : parsed.Message;
                    ShowError($"ip-api: {msg}. Private/reserved addresses are not resolvable.");
                    return;
                }

                ResultIp.Text = ip.ToString();
                CountryText.Text = Fallback(parsed.Country, parsed.CountryCode);
                RegionText.Text = Fallback(parsed.Region, "—");
                CityText.Text = Fallback(parsed.City, "—");
                ZipText.Text = Fallback(parsed.Zip, "—");
                LatText.Text = Fallback(parsed.Latitude, "—");
                LonText.Text = Fallback(parsed.Longitude, "—");
                TzText.Text = Fallback(parsed.Timezone, "—");
                IspText.Text = Fallback(parsed.Isp, "—");
                OrgText.Text = Fallback(parsed.Organization, "—");
                AsnText.Text = Fallback(parsed.Asn, "—");
                HostText.Text = Fallback(parsed.Hostname, "—");
                ContText.Text = Fallback(parsed.Continent, "—");

                ProxyPill.Visibility = parsed.IsProxy ? Visibility.Visible : Visibility.Collapsed;
                HostingPill.Visibility = parsed.IsHosting ? Visibility.Visible : Visibility.Collapsed;
                MobilePill.Visibility = parsed.IsHotspot ? Visibility.Visible : Visibility.Collapsed;

                ResultCard.Visibility = Visibility.Visible;
            }
            catch (TaskCanceledException)
            {
                ShowError("Lookup timed out (12s). DoH resolver or ip-api may be slow — retry.");
            }
            catch (Exception ex)
            {
                await ex.AutoDumpExceptionAsync();
                ShowError($"Lookup failed: {ex.Message}");
            }
            finally
            {
                LookupBtn.IsEnabled = true;
                LookupText.Text = "Lookup";
                LookupIcon.Kind = PackIconKind.Magnify;
            }
        }

        private static string Fallback(string value, string fallback)
            => string.IsNullOrWhiteSpace(value) ? fallback : value;

        private void ShowError(string msg)
        {
            ErrorText.Text = msg;
            ErrorCard.Visibility = Visibility.Visible;
            ResultCard.Visibility = Visibility.Collapsed;
        }

        private class StatusGeoResponse : GeolocationResponse
        {
            [JsonProperty("status")] public string Status { get; set; }
            [JsonProperty("message")] public string Message { get; set; }
        }
    }
}
