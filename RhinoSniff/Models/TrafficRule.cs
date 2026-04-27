using System.Collections.Generic;
using Newtonsoft.Json;
using Newtonsoft.Json.Converters;

namespace RhinoSniff.Models
{
    // ── Enums ──────────────────────────────────────────────────────────────

    [JsonConverter(typeof(StringEnumConverter))]
    public enum TrafficTargetMode
    {
        AllTraffic,
        SpecificIPs,
        Filter
    }

    [JsonConverter(typeof(StringEnumConverter))]
    public enum TrafficAction
    {
        Drop,
        Lag,
        Throttle,
        Reorder,
        Duplicate
    }

    [JsonConverter(typeof(StringEnumConverter))]
    public enum TrafficProtocol
    {
        Any,
        TCP,
        UDP
    }

    [JsonConverter(typeof(StringEnumConverter))]
    public enum TrafficDirection
    {
        Both,
        Inbound,
        Outbound
    }

    // ── Port entry ─────────────────────────────────────────────────────────

    /// <summary>
    /// Represents a single port or a port range (e.g. 3074, or 80-999).
    /// When <see cref="MinPort"/> == <see cref="MaxPort"/> it's a single port.
    /// </summary>
    public class PortEntry
    {
        [JsonProperty("Min")] public ushort MinPort { get; set; }
        [JsonProperty("Max")] public ushort MaxPort { get; set; }

        public PortEntry() { }
        public PortEntry(ushort single) { MinPort = single; MaxPort = single; }
        public PortEntry(ushort min, ushort max) { MinPort = min; MaxPort = max; }

        public bool IsSingle => MinPort == MaxPort;

        public bool Contains(ushort port) => port >= MinPort && port <= MaxPort;

        public override string ToString() => IsSingle ? MinPort.ToString() : $"{MinPort}-{MaxPort}";

        /// <summary>
        /// Parse a string like "3074" or "80-999" into a <see cref="PortEntry"/>.
        /// Returns null on invalid input.
        /// </summary>
        public static PortEntry TryParse(string s)
        {
            if (string.IsNullOrWhiteSpace(s)) return null;
            s = s.Trim();
            var dash = s.IndexOf('-');
            if (dash < 0)
            {
                return ushort.TryParse(s, out var p) ? new PortEntry(p) : null;
            }
            var left = s.Substring(0, dash);
            var right = s.Substring(dash + 1);
            if (ushort.TryParse(left, out var lo) && ushort.TryParse(right, out var hi) && lo <= hi)
                return new PortEntry(lo, hi);
            return null;
        }
    }

    // ── Traffic Rule ───────────────────────────────────────────────────────

    /// <summary>
    /// A single Traffic Control rule — persisted in Settings.json.
    /// </summary>
    public class TrafficRule
    {
        // ── Identity ──────────────────────────────────────────────────────
        [JsonProperty("Name")]
        public string Name { get; set; } = "";

        [JsonProperty("Enabled")]
        public bool Enabled { get; set; } = true;

        // ── Target ────────────────────────────────────────────────────────
        [JsonProperty("TargetMode")]
        public TrafficTargetMode TargetMode { get; set; } = TrafficTargetMode.AllTraffic;

        /// <summary>One or more target IPs (only used when <see cref="TargetMode"/> is SpecificIPs).</summary>
        [JsonProperty("TargetIPs")]
        public List<string> TargetIPs { get; set; } = new();

        /// <summary>Filter preset (only used when <see cref="TargetMode"/> is Filter).</summary>
        [JsonProperty("FilterPreset")]
        public FilterPreset FilterPreset { get; set; } = FilterPreset.None;

        [JsonProperty("Protocol")]
        public TrafficProtocol Protocol { get; set; } = TrafficProtocol.Any;

        [JsonProperty("Direction")]
        public TrafficDirection Direction { get; set; } = TrafficDirection.Both;

        /// <summary>Port entries (single or range). Empty = all ports.</summary>
        [JsonProperty("Ports")]
        public List<PortEntry> Ports { get; set; } = new();

        // ── Action ────────────────────────────────────────────────────────
        [JsonProperty("Action")]
        public TrafficAction Action { get; set; } = TrafficAction.Drop;

        // ── Settings ──────────────────────────────────────────────────────
        /// <summary>Chance to apply action to each packet (0–100).</summary>
        [JsonProperty("Probability")]
        public int Probability { get; set; } = 100;

        /// <summary>Burst mode: apply action in ON/OFF cycles.</summary>
        [JsonProperty("BurstEnabled")]
        public bool BurstEnabled { get; set; }

        /// <summary>Burst ON duration in milliseconds.</summary>
        [JsonProperty("BurstOnMs")]
        public int BurstOnMs { get; set; } = 500;

        /// <summary>Burst OFF duration in milliseconds.</summary>
        [JsonProperty("BurstOffMs")]
        public int BurstOffMs { get; set; } = 2000;

        // ── Action-specific ───────────────────────────────────────────────
        /// <summary>Delay in ms (Lag action only).</summary>
        [JsonProperty("DelayMs")]
        public int DelayMs { get; set; } = 100;

        /// <summary>Jitter in ms — random ±variance added to Delay (Lag action only).</summary>
        [JsonProperty("JitterMs")]
        public int JitterMs { get; set; } = 0;

        /// <summary>Rate limit in kbps (Throttle action only).</summary>
        [JsonProperty("RateKbps")]
        public int RateKbps { get; set; } = 1000;

        /// <summary>Percentage of matched packets to reorder (Reorder action only, 0–100).</summary>
        [JsonProperty("ReorderPercent")]
        public int ReorderPercent { get; set; } = 50;

        /// <summary>Reorder buffer window in ms — how long to hold packets before shuffling and releasing (Reorder action only).</summary>
        [JsonProperty("ReorderWindowMs")]
        public int ReorderWindowMs { get; set; } = 100;

        /// <summary>Percentage of matched packets to duplicate (Duplicate action only, 0–100).</summary>
        [JsonProperty("DuplicatePercent")]
        public int DuplicatePercent { get; set; } = 50;

        /// <summary>Delay in ms before sending the duplicate packet (Duplicate action only). 0 = immediate.</summary>
        [JsonProperty("DuplicateDelayMs")]
        public int DuplicateDelayMs { get; set; } = 0;

        // ── Helpers ───────────────────────────────────────────────────────

        /// <summary>Human-readable target summary for the rule row display.</summary>
        [JsonIgnore]
        public string TargetDisplay
        {
            get
            {
                switch (TargetMode)
                {
                    case TrafficTargetMode.AllTraffic:
                        return "All IPs";
                    case TrafficTargetMode.SpecificIPs:
                        return TargetIPs.Count == 1 ? TargetIPs[0] : $"{TargetIPs.Count} IPs";
                    case TrafficTargetMode.Filter:
                        var meta = FilterRegistry.Get(FilterPreset);
                        return meta.DisplayName;
                    default:
                        return "Unknown";
                }
            }
        }

        /// <summary>Human-readable ports summary.</summary>
        [JsonIgnore]
        public string PortsDisplay =>
            Ports == null || Ports.Count == 0 ? "All" : string.Join(", ", Ports);

        /// <summary>Human-readable burst summary.</summary>
        [JsonIgnore]
        public string BurstDisplay =>
            BurstEnabled ? $"{BurstOnMs}ms ON / {BurstOffMs}ms OFF" : "Disabled";
    }
}
