using System.Collections.Generic;
using Newtonsoft.Json;

namespace RhinoSniff.Models
{
    public class Settings
    {
        [JsonProperty("AutoShowPanel")] public bool AutoShowPanel { get; set; } = true;

        [JsonProperty("Background")] public string Background { get; set; } = "None";

        [JsonProperty("ColorType")] public ColorType ColorType { get; set; } = ColorType.Default;

        [JsonProperty("DiscordStatus")] public bool DiscordStatus { get; set; } = true;

        [JsonProperty("Dynamic Remove")] public bool DynamicRemove { get; set; } = true;

        [JsonProperty("EnableLabels")] public bool EnableLabels { get; set; }

        [JsonProperty("Filter")] public FilterPreset Filter { get; set; } = FilterPreset.None;

        [JsonProperty("Geolocate")] public bool Geolocate { get; set; } = true;

        [JsonProperty("HardwareAccel")] public bool HardwareAccel { get; set; } = true;

        [JsonProperty("HexColor")] public string HexColor { get; set; } = "#00897B";

        [JsonProperty("HideInvalidInterfaces")]
        public bool HideInterfaces { get; set; }

        [JsonProperty("InterfaceName")] public string InterfaceName { get; set; }

        [JsonProperty("Labels")] public List<Label> Labels { get; set; } = new();

        [JsonProperty("PacketAnalyser")] public bool PacketAnalyser { get; set; }

        [JsonProperty("Ports", ObjectCreationHandling = ObjectCreationHandling.Replace)]
        public List<ushort> Ports { get; set; } = new();

        [JsonProperty("PortsInverse")] public bool PortsInverse { get; set; }

        [JsonProperty("PortsInitialized")] public bool PortsInitialized { get; set; }

        [JsonProperty("ShowUdpPackets")] public bool ShowUdpPackets { get; set; } = true;

        [JsonProperty("ShowTcpPackets")] public bool ShowTcpPackets { get; set; } = true;

        [JsonProperty("RememberInterface")] public bool RememberInterface { get; set; } = true;

        [JsonProperty("ShowFlags")] public bool ShowFlags { get; set; } = true;

        [JsonProperty("TopMost")] public bool TopMost { get; set; }

        [JsonProperty("SoundAlerts")] public bool SoundAlerts { get; set; }

        [JsonProperty("ConsoleIpFilter")] public string ConsoleIpFilter { get; set; } = "";

        [JsonProperty("CustomFilters")] public List<CustomFilter> CustomFilters { get; set; } = new();

        [JsonProperty("IspFilter")] public string IspFilter { get; set; } = "";

        [JsonProperty("ActiveGameFilters")] public List<FilterPreset> ActiveGameFilters { get; set; } = new();

        [JsonProperty("ShowOtherInfoTab")] public bool ShowOtherInfoTab { get; set; } = true;

        [JsonProperty("AutoRemoveInactive")] public bool AutoRemoveInactive { get; set; }

        [JsonProperty("DarkMode")] public bool DarkMode { get; set; } = true;

        [JsonProperty("SidebarCollapsed")] public bool SidebarCollapsed { get; set; }

        // ── Phase 3 ─────────────────────────────────────────────────────────
        /// <summary>Per-preset action (Highlight or Discard). Missing key = Highlight.</summary>
        [JsonProperty("FilterActions")]
        public Dictionary<FilterPreset, FilterAction> FilterActions { get; set; } = new();

        /// <summary>Multi-ISP substring allowlist. Replaces legacy single <see cref="IspFilter"/>.</summary>
        [JsonProperty("IspFilters")]
        public List<string> IspFilters { get; set; } = new();

        [JsonProperty("IspFilterBehavior")]
        public IspFilterBehavior IspFilterBehavior { get; set; } = IspFilterBehavior.Hide;

        /// <summary>
        /// ISP denylist. Packets whose ISP contains any of these substrings (case-insensitive)
        /// are hidden from Network Monitor. Separate from <see cref="IspFilters"/> (allowlist) —
        /// this is populated by the right-click "Hide ISP: X" context menu.
        /// </summary>
        [JsonProperty("HiddenIsps")]
        public List<string> HiddenIsps { get; set; } = new();

        /// <summary>
        /// Device Filter allowlist. When non-empty, only packets whose source OR destination IPv4
        /// matches one of these entries are kept. Independent of ARP (which does MITM).
        /// </summary>
        [JsonProperty("DeviceFilterIps")]
        public List<string> DeviceFilterIps { get; set; } = new();

        // ── Phase 4 ─────────────────────────────────────────────────────────
        /// <summary>Suppress the "non-private IP" warning modal in Packet Tester.</summary>
        [JsonProperty("DisableRemoteNetworkWarning")]
        public bool DisableRemoteNetworkWarning { get; set; }

        // ── Phase 5 ─────────────────────────────────────────────────────────
        /// <summary>Global hotkey bindings. Missing key = unbound.</summary>
        [JsonProperty("Hotkeys")]
        public Dictionary<HotkeyAction, HotkeyBinding> Hotkeys { get; set; } = new();

        // ── Phase 6 ─────────────────────────────────────────────────────────
        /// <summary>Master toggle for in-app toast notifications.</summary>
        [JsonProperty("EnableNotifications")]
        public bool EnableNotifications { get; set; } = true;

        /// <summary>Auto-save capture data to disk on exit.</summary>
        [JsonProperty("AutoSaveCapture")]
        public bool AutoSaveCapture { get; set; }

        /// <summary>Automatically detect newly-available network interfaces.</summary>
        [JsonProperty("AutoDetectInterfaces")]
        public bool AutoDetectInterfaces { get; set; } = true;

        /// <summary>Store recent TCP/UDP payloads per IP for flow inspection.</summary>
        [JsonProperty("NetworkInspectMode")]
        public bool NetworkInspectMode { get; set; }

        /// <summary>Maximum unique IP rows kept in the capture grid before pruning oldest.</summary>
        [JsonProperty("MaxPacketsInMemory")]
        public int MaxPacketsInMemory { get; set; } = 10000;

        /// <summary>SharpPcap kernel buffer size in KB, applied at capture init.</summary>
        [JsonProperty("CaptureBufferSizeKb")]
        public int CaptureBufferSizeKb { get; set; } = 1024;

        /// <summary>Phase 6 accent color (hex). Replaces legacy ColorType preset.</summary>
        [JsonProperty("AccentColorHex")]
        public string AccentColorHex { get; set; } = "#00897b";

        /// <summary>v2.9.2 user-pickable app font. Default = Gotham (bundled).
        /// Read by ThemeManager.ApplyFont, exposed in Settings → Appearance dropdown.</summary>
        [JsonProperty("FontFamily")]
        public string FontFamily { get; set; } = "Gotham";

        // ── Phase 8 — Traffic Control ────────────────────────────────────────
        /// <summary>Persisted traffic control rules.</summary>
        [JsonProperty("TrafficRules")]
        public List<TrafficRule> TrafficRules { get; set; } = new();

        // ── Phase 9 — User-created filters (My Filters) ─────────────────────
        /// <summary>
        /// User-created filters rendered in the "My Filters" tab of the Packet Filters page.
        /// Each filter tracks its own <see cref="UserFilter.IsActive"/> and
        /// <see cref="UserFilter.Action"/> — independent of the built-in
        /// <see cref="ActiveGameFilters"/> + <see cref="FilterActions"/> pair which
        /// continues to drive the Community Filters tab.
        /// </summary>
        [JsonProperty("UserFilters")]
        public List<UserFilter> UserFilters { get; set; } = new();
    }

    public class CustomFilter
    {
        [JsonProperty("Name")] public string Name { get; set; } = "";
        [JsonProperty("MinPort")] public ushort MinPort { get; set; }
        [JsonProperty("MaxPort")] public ushort MaxPort { get; set; }
        [JsonProperty("UdpOnly")] public bool UdpOnly { get; set; } = true;

        public override string ToString() => $"{Name} (UDP {MinPort}-{MaxPort})";
    }
}