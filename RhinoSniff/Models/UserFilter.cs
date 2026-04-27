using System;
using System.Collections.Generic;
using Newtonsoft.Json;

namespace RhinoSniff.Models
{
    /// <summary>
    /// Where a user-created filter "lives" — Step 1a of the create-filter wizard.
    /// Local = device-only, raw network rules (IP/CIDR, country, ISP).
    /// Cloud = game-focused, platform + title IDs + bytes pattern, optionally shareable.
    /// RhinoSniff has no cloud backend — Cloud filters are stored locally too, and
    /// <see cref="UserFilter.ShareWithCommunity"/> is persisted but currently no-op.
    /// </summary>
    public enum UserFilterSource
    {
        Local,
        Cloud
    }

    /// <summary>
    /// Cloud-filter metadata hint only. Does not affect packet matching.
    /// </summary>
    public enum UserFilterConnectionType
    {
        None,
        Matchmaking,
        Party,
        Session
    }

    /// <summary>
    /// A user-created filter. Rendered in the "My Filters" tab, activates
    /// alongside built-in <see cref="FilterPreset"/> entries, matched by
    /// MainWindow's packet loop after the built-in preset switch runs.
    /// </summary>
    public class UserFilter
    {
        [JsonProperty("Id")]
        public Guid Id { get; set; } = Guid.NewGuid();

        [JsonProperty("Source")]
        public UserFilterSource Source { get; set; } = UserFilterSource.Local;

        [JsonProperty("Name")]
        public string Name { get; set; } = "";

        [JsonProperty("Description")]
        public string Description { get; set; } = "";

        [JsonProperty("Author")]
        public string Author { get; set; } = "rhino241";

        [JsonProperty("Action")]
        public FilterAction Action { get; set; } = FilterAction.Highlight;

        [JsonProperty("Protocol")]
        public FilterProtocol Protocol { get; set; } = FilterProtocol.Udp;

        [JsonProperty("ConnectionType")]
        public UserFilterConnectionType ConnectionType { get; set; } = UserFilterConnectionType.None;

        /// <summary>Enabled state — equivalent of ActiveGameFilters for built-in presets.</summary>
        [JsonProperty("IsActive")]
        public bool IsActive { get; set; }

        // ── Local-filter fields (also usable by Cloud filters) ──────────────

        /// <summary>IPv4/IPv6 addresses or CIDR ranges. Match on source OR dest.</summary>
        [JsonProperty("IpCidrs")]
        public List<string> IpCidrs { get; set; } = new();

        /// <summary>2-letter country codes (e.g. "US", "DE"). Match via ip-api cache.</summary>
        [JsonProperty("Countries")]
        public List<string> Countries { get; set; } = new();

        /// <summary>ISP name substrings (case-insensitive partial match).</summary>
        [JsonProperty("Isps")]
        public List<string> Isps { get; set; } = new();

        /// <summary>
        /// Hex byte patterns (e.g. "FFFFFF", "FF00AB"). Payload must contain
        /// at least one of these byte sequences for the filter to match.
        /// Whitespace and commas between bytes are ignored at parse time.
        /// </summary>
        [JsonProperty("BytesPatternsHex")]
        public List<string> BytesPatternsHex { get; set; } = new();

        /// <summary>Inclusive port range. 0..65535 = match all ports.</summary>
        [JsonProperty("PortStart")]
        public int PortStart { get; set; } = 0;

        [JsonProperty("PortEnd")]
        public int PortEnd { get; set; } = 65535;

        /// <summary>Inclusive packet length range in bytes. 0..65535 = match all.</summary>
        [JsonProperty("LenMin")]
        public int LenMin { get; set; } = 0;

        [JsonProperty("LenMax")]
        public int LenMax { get; set; } = 65535;

        // ── Cloud-filter fields ──────────────────────────────────────────────

        /// <summary>Plain-text game name.</summary>
        [JsonProperty("GameName")]
        public string GameName { get; set; } = "";

        /// <summary>IGDB game id, stored for future API integration. Null = unset.</summary>
        [JsonProperty("IgdbId")]
        public int? IgdbId { get; set; }

        /// <summary>Cover art URL, stored for future IGDB integration. Empty = show controller placeholder.</summary>
        [JsonProperty("CoverUrl")]
        public string CoverUrl { get; set; } = "";

        /// <summary>Game/application title IDs (e.g. "CUSA00001"). Metadata only — not used for matching.</summary>
        [JsonProperty("TitleIds")]
        public List<string> TitleIds { get; set; } = new();

        /// <summary>Platform tags shown as pills on the card. Required for Cloud filters.</summary>
        [JsonProperty("Platforms")]
        public List<FilterPlatform> Platforms { get; set; } = new();

        /// <summary>
        /// Persisted from the wizard checkbox. No backend exists to receive the submission —
        /// this is stored for forward-compat when/if a community server is added.
        /// </summary>
        [JsonProperty("ShareWithCommunity")]
        public bool ShareWithCommunity { get; set; }

        /// <summary>When the filter was created (for sorting, display).</summary>
        [JsonProperty("CreatedAt")]
        public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    }
}
