using System;
using System.Threading.Tasks;
using RhinoSniff.Models;

// WinRT namespaces — available because project TFM is net6.0-windows10.0.19041.0
using Windows.Networking.Connectivity;
using Windows.Networking.NetworkOperators;

namespace RhinoSniff.Classes
{
    /// <summary>
    /// Phase 5 — wraps <c>NetworkOperatorTetheringManager</c> for the built-in Windows 10+
    /// Mobile Hotspot. Not tested by Claude — Rhino please verify on RhinoDedi / laptop.
    ///
    /// Known requirements:
    /// - Admin (app already has requireAdministrator in app.manifest)
    /// - "Mobile Hotspot" feature must be enabled/supported by the OS (not all SKUs)
    /// - The internet-facing profile must be the one passed to <c>CreateFromConnectionProfile</c>
    ///
    /// The WinRT API uses <c>NetworkOperatorTetheringAccessPointConfiguration</c> for SSID +
    /// passphrase. State is an async <c>TetheringOperationalState</c> — starting/stopping
    /// is async via <c>StartTetheringAsync</c> / <c>StopTetheringAsync</c>.
    /// </summary>
    public class HotspotManager
    {
        public class Status
        {
            public bool Supported { get; set; }
            public bool Running { get; set; }
            public int ClientCount { get; set; }
            public string Ssid { get; set; } = "";
            public string Passphrase { get; set; } = "";
            public string Error { get; set; }
        }

        /// <summary>
        /// Quick support check without starting anything. Returns null Error if supported.
        /// </summary>
        public Status GetStatus()
        {
            var s = new Status();
            try
            {
                var profile = NetworkInformation.GetInternetConnectionProfile();
                if (profile == null)
                {
                    s.Supported = false;
                    s.Error = "No active internet connection profile. Connect to Wi-Fi or Ethernet first.";
                    return s;
                }

                var mgr = NetworkOperatorTetheringManager.CreateFromConnectionProfile(profile);
                if (mgr == null)
                {
                    s.Supported = false;
                    s.Error = "Mobile Hotspot is not supported by this system.";
                    return s;
                }

                s.Supported = true;
                s.Running = mgr.TetheringOperationalState == TetheringOperationalState.On;
                s.ClientCount = (int)mgr.ClientCount;

                var cfg = mgr.GetCurrentAccessPointConfiguration();
                if (cfg != null)
                {
                    s.Ssid = cfg.Ssid ?? "";
                    s.Passphrase = cfg.Passphrase ?? "";
                }
            }
            catch (Exception e)
            {
                s.Supported = false;
                s.Error = "Hotspot check failed: " + e.Message;
                _ = e.AutoDumpExceptionAsync();
            }
            return s;
        }

        /// <summary>
        /// Apply SSID + passphrase without changing running state.
        /// </summary>
        public async Task<(bool Ok, string Error)> ApplyConfigAsync(string ssid, string passphrase)
        {
            if (string.IsNullOrWhiteSpace(ssid)) return (false, "SSID cannot be empty.");
            if (passphrase == null || passphrase.Length < 8) return (false, "Passphrase must be at least 8 characters (WPA2 minimum).");

            try
            {
                var profile = NetworkInformation.GetInternetConnectionProfile();
                if (profile == null) return (false, "No active internet connection profile.");
                var mgr = NetworkOperatorTetheringManager.CreateFromConnectionProfile(profile);
                if (mgr == null) return (false, "Mobile Hotspot not supported.");

                var cfg = mgr.GetCurrentAccessPointConfiguration() ?? new NetworkOperatorTetheringAccessPointConfiguration();
                cfg.Ssid = ssid;
                cfg.Passphrase = passphrase;

                // ConfigureAccessPointAsync returns IAsyncAction (void). Success is indicated
                // by not throwing; read-back via GetCurrentAccessPointConfiguration if needed.
                await mgr.ConfigureAccessPointAsync(cfg);
                return (true, null);
            }
            catch (Exception e)
            {
                await e.AutoDumpExceptionAsync();
                return (false, e.Message);
            }
        }

        public async Task<(bool Ok, string Error)> StartAsync()
        {
            try
            {
                var profile = NetworkInformation.GetInternetConnectionProfile();
                if (profile == null) return (false, "No active internet connection profile.");
                var mgr = NetworkOperatorTetheringManager.CreateFromConnectionProfile(profile);
                if (mgr == null) return (false, "Mobile Hotspot not supported.");
                if (mgr.TetheringOperationalState == TetheringOperationalState.On) return (true, null);

                var result = await mgr.StartTetheringAsync();
                if (result.Status != TetheringOperationStatus.Success)
                    return (false, $"Start failed: {result.Status} — {result.AdditionalErrorMessage}");
                return (true, null);
            }
            catch (Exception e)
            {
                await e.AutoDumpExceptionAsync();
                return (false, e.Message);
            }
        }

        public async Task<(bool Ok, string Error)> StopAsync()
        {
            try
            {
                var profile = NetworkInformation.GetInternetConnectionProfile();
                if (profile == null) return (false, "No active internet connection profile.");
                var mgr = NetworkOperatorTetheringManager.CreateFromConnectionProfile(profile);
                if (mgr == null) return (false, "Mobile Hotspot not supported.");
                if (mgr.TetheringOperationalState == TetheringOperationalState.Off) return (true, null);

                var result = await mgr.StopTetheringAsync();
                if (result.Status != TetheringOperationStatus.Success)
                    return (false, $"Stop failed: {result.Status} — {result.AdditionalErrorMessage}");
                return (true, null);
            }
            catch (Exception e)
            {
                await e.AutoDumpExceptionAsync();
                return (false, e.Message);
            }
        }
    }
}
