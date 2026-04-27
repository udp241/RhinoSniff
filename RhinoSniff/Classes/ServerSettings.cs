using System;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Threading.Tasks;
using RhinoSniff.Interfaces;
using RhinoSniff.Models;
using Newtonsoft.Json;

namespace RhinoSniff.Classes
{
    public class ServerSettings : IServerSettings
    {
        private static readonly string SettingsDir = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "RhinoSniff");

        private static readonly string SettingsFile = Path.Combine(SettingsDir, "settings.bin");

        public async Task GetSettingsAsync()
        {
            try
            {
                if (!Directory.Exists(SettingsDir))
                    Directory.CreateDirectory(SettingsDir);

                if (!File.Exists(SettingsFile))
                {
                    Globals.Settings = new Settings();
                    Globals.Settings.Ports.AddRange(new ushort[] { 80, 443, 53 });
                    Globals.Settings.PortsInitialized = true;
                    await UpdateSettingsAsync();
                    return;
                }

                var contents = await File.ReadAllTextAsync(SettingsFile);
                var decryptedContents = await Security.DecryptAsync(contents);

                var jsonResp = JsonConvert.DeserializeObject<Settings>(decryptedContents);
                Globals.Settings = jsonResp ?? new Settings();
                
                // ═══ SETTINGS VALIDATION — fix corrupted values from crashes ═══
                var needsSave = false;
                
                // Dedup ports list
                if (Globals.Settings.Ports.Count != Globals.Settings.Ports.Distinct().Count())
                {
                    Globals.Settings.Ports = Globals.Settings.Ports.Distinct().ToList();
                    needsSave = true;
                }

                // First-time migration: add default blacklist ports ONCE
                // After this flag is set, user can empty the list and it stays empty
                if (!Globals.Settings.PortsInitialized)
                {
                    if (Globals.Settings.Ports.Count == 0)
                        Globals.Settings.Ports.AddRange(new ushort[] { 80, 443, 53 });
                    Globals.Settings.PortsInitialized = true;
                    needsSave = true;
                }

                // v2.8.2 migration: bump pre-existing installs off the old default-blue
                // accent default to the new RhinoSniff teal default. Only auto-bumps if the
                // user is still on the exact old default (case-insensitive) — anyone who
                // picked their own accent keeps it.
                if (string.Equals(Globals.Settings.AccentColorHex, "#2563eb", System.StringComparison.OrdinalIgnoreCase) ||
                    string.Equals(Globals.Settings.AccentColorHex, "#FF2563EB", System.StringComparison.OrdinalIgnoreCase))
                {
                    Globals.Settings.AccentColorHex = "#00897b";
                    needsSave = true;
                }

                // v2.9.4.11 migration: legacy 'HexColor' field was the original accent storage
                // before AccentColorHex existed. If the user's file still only has HexColor set
                // (non-default) and AccentColorHex is on the default teal, copy HexColor across
                // so the swatch picker + StampWindowBorder see the real chosen accent.
                if (!string.IsNullOrWhiteSpace(Globals.Settings.HexColor) &&
                    !string.Equals(Globals.Settings.HexColor, "#00897B", System.StringComparison.OrdinalIgnoreCase) &&
                    !string.Equals(Globals.Settings.HexColor, "#00897b", System.StringComparison.OrdinalIgnoreCase) &&
                    (string.Equals(Globals.Settings.AccentColorHex, "#00897B", System.StringComparison.OrdinalIgnoreCase) ||
                     string.Equals(Globals.Settings.AccentColorHex, "#00897b", System.StringComparison.OrdinalIgnoreCase)))
                {
                    Globals.Settings.AccentColorHex = Globals.Settings.HexColor;
                    needsSave = true;
                }

                // If both packet types are off, that's corrupted — turn both on
                if (!Globals.Settings.ShowTcpPackets && !Globals.Settings.ShowUdpPackets)
                {
                    Globals.Settings.ShowTcpPackets = true;
                    Globals.Settings.ShowUdpPackets = true;
                    needsSave = true;
                }

                // ── Phase 3 migration: legacy single IspFilter → IspFilters list ──
                if (!string.IsNullOrWhiteSpace(Globals.Settings.IspFilter))
                {
                    Globals.Settings.IspFilters ??= new System.Collections.Generic.List<string>();
                    var legacy = Globals.Settings.IspFilter.Trim();
                    if (!Globals.Settings.IspFilters.Contains(legacy, StringComparer.OrdinalIgnoreCase))
                        Globals.Settings.IspFilters.Add(legacy);
                    Globals.Settings.IspFilter = "";
                    needsSave = true;
                }

                // ── v2.9.4.36 migration: orphaned HiddenIsps denylist → IspFilters ──
                // IspFilters used to be an allowlist, HiddenIsps a parallel denylist with no UI.
                // They're now unified: IspFilters is the denylist. Merge any legacy HiddenIsps
                // entries into IspFilters and clear HiddenIsps so the old orphaned list is empty.
                if (Globals.Settings.HiddenIsps != null && Globals.Settings.HiddenIsps.Count > 0)
                {
                    Globals.Settings.IspFilters ??= new System.Collections.Generic.List<string>();
                    foreach (var hidden in Globals.Settings.HiddenIsps)
                    {
                        if (string.IsNullOrWhiteSpace(hidden)) continue;
                        if (!Globals.Settings.IspFilters.Contains(hidden, StringComparer.OrdinalIgnoreCase))
                            Globals.Settings.IspFilters.Add(hidden);
                    }
                    Globals.Settings.HiddenIsps.Clear();
                    needsSave = true;
                }

                // ── Phase 3 migration: legacy single ConsoleIpFilter → DeviceFilterIps list ──
                if (!string.IsNullOrWhiteSpace(Globals.Settings.ConsoleIpFilter))
                {
                    Globals.Settings.DeviceFilterIps ??= new System.Collections.Generic.List<string>();
                    var legacy = Globals.Settings.ConsoleIpFilter.Trim();
                    if (!Globals.Settings.DeviceFilterIps.Contains(legacy, StringComparer.OrdinalIgnoreCase))
                        Globals.Settings.DeviceFilterIps.Add(legacy);
                    Globals.Settings.ConsoleIpFilter = "";
                    needsSave = true;
                }

                // Null-guard new Phase 3 collections (old settings files won't have them)
                if (Globals.Settings.FilterActions == null)
                {
                    Globals.Settings.FilterActions = new System.Collections.Generic.Dictionary<FilterPreset, FilterAction>();
                    needsSave = true;
                }
                if (Globals.Settings.IspFilters == null)
                {
                    Globals.Settings.IspFilters = new System.Collections.Generic.List<string>();
                    needsSave = true;
                }
                if (Globals.Settings.DeviceFilterIps == null)
                {
                    Globals.Settings.DeviceFilterIps = new System.Collections.Generic.List<string>();
                    needsSave = true;
                }

                // ── Phase 5 null-guards ──
                if (Globals.Settings.Hotkeys == null)
                {
                    Globals.Settings.Hotkeys = new System.Collections.Generic.Dictionary<HotkeyAction, HotkeyBinding>();
                    needsSave = true;
                }

                // ── Phase 9 null-guard ──
                if (Globals.Settings.UserFilters == null)
                {
                    Globals.Settings.UserFilters = new System.Collections.Generic.List<UserFilter>();
                    needsSave = true;
                }

                if (needsSave)
                    await UpdateSettingsAsync();
            }
            catch (Exception e)
            {
                await e.AutoDumpExceptionAsync();
                // If settings are corrupted (e.g. new encryption scheme), reset to defaults
                Globals.Settings = new Settings();
                await UpdateSettingsAsync();
            }
        }

        [Obfuscation(Feature = "virtualization", Exclude = false)]
        public async Task<bool> UpdateSettingsAsync()
        {
            try
            {
                if (!Directory.Exists(SettingsDir))
                    Directory.CreateDirectory(SettingsDir);

                var json = JsonConvert.SerializeObject(Globals.Settings);
                var encryptedJson = await Security.EncryptAsync(json);
                await File.WriteAllTextAsync(SettingsFile, encryptedJson);
                return true;
            }
            catch (Exception e)
            {
                await e.AutoDumpExceptionAsync();
                return false;
            }
        }
    }
}
