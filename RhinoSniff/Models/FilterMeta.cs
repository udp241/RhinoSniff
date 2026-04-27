using System.Collections.Generic;

namespace RhinoSniff.Models
{
    public enum FilterProtocol { Both, Udp, Tcp }

    public class FilterMeta
    {
        public FilterPreset Preset { get; init; }
        public string DisplayName { get; init; } = "";
        public string Description { get; init; } = "";
        public string Author { get; init; } = "Rhino";
        public FilterCategory Category { get; init; } = FilterCategory.NA;
        public FilterProtocol Protocol { get; init; } = FilterProtocol.Udp;
        public List<FilterPlatform> Platforms { get; init; } = new();
        /// <summary>Short accent gradient hex (dark, light) used on the card header.</summary>
        public string AccentHexA { get; init; } = "#1F2937";
        public string AccentHexB { get; init; } = "#111827";
    }

    public static class FilterRegistry
    {
        private static readonly Dictionary<FilterPreset, FilterMeta> _map = BuildMap();

        public static FilterMeta Get(FilterPreset preset) =>
            _map.TryGetValue(preset, out var m) ? m : new FilterMeta
            {
                Preset = preset,
                DisplayName = preset.ToString(),
                Category = FilterCategory.NA,
                Platforms = { FilterPlatform.Universal }
            };

        public static IEnumerable<FilterMeta> All() => _map.Values;

        private static Dictionary<FilterPreset, FilterMeta> BuildMap()
        {
            var d = new Dictionary<FilterPreset, FilterMeta>();

            void Add(FilterPreset p, string name, string desc, FilterCategory cat,
                FilterProtocol proto, string a, string b, params FilterPlatform[] platforms)
            {
                d[p] = new FilterMeta
                {
                    Preset = p,
                    DisplayName = name,
                    Description = desc,
                    Category = cat,
                    Protocol = proto,
                    AccentHexA = a,
                    AccentHexB = b,
                    Platforms = new List<FilterPlatform>(platforms)
                };
            }

            // Console party (P2P)
            Add(FilterPreset.PSNParty, "PSN Party", "PlayStation party-chat peer-to-peer voice.",
                FilterCategory.P2P, FilterProtocol.Udp, "#1E3A8A", "#2563EB",
                FilterPlatform.PlayStation);
            Add(FilterPreset.XboxPartyBETA, "Xbox Party", "Xbox party-chat P2P (payload signature, beta).",
                FilterCategory.P2P, FilterProtocol.Udp, "#14532D", "#16A34A",
                FilterPlatform.Xbox);
            Add(FilterPreset.Discord, "Discord Voice", "Discord voice via Cloudflare TURN relays (UDP 3478-3480 STUN, 19000-19999 relay).",
                FilterCategory.Server, FilterProtocol.Udp, "#312E81", "#4F46E5",
                FilterPlatform.PC, FilterPlatform.Mobile);

            // Battle royale
            Add(FilterPreset.Fortnite, "Fortnite", "Epic game traffic (UDP 9000-9100).",
                FilterCategory.Server, FilterProtocol.Udp, "#3730A3", "#6366F1",
                FilterPlatform.Universal);
            Add(FilterPreset.ApexLegends, "Apex Legends", "EA server payload signature.",
                FilterCategory.Server, FilterProtocol.Udp, "#7F1D1D", "#DC2626",
                FilterPlatform.Universal);
            Add(FilterPreset.PUBG, "PUBG", "Krafton servers (UDP 7080-8000).",
                FilterCategory.Server, FilterProtocol.Udp, "#78350F", "#F59E0B",
                FilterPlatform.Universal);

            // COD
            Add(FilterPreset.CallOfDuty, "Call of Duty", "All COD titles (UDP 3074, 3478-3480, 4379-4380, 27000-27031, 28960).",
                FilterCategory.Server, FilterProtocol.Udp, "#1C1917", "#44403C",
                FilterPlatform.Universal);

            // Tactical / FPS
            Add(FilterPreset.Valorant, "Valorant", "Riot game servers (UDP 5000-5500, 7000-8000, 8180-8181).",
                FilterCategory.Server, FilterProtocol.Udp, "#991B1B", "#EF4444",
                FilterPlatform.PC);
            Add(FilterPreset.RainbowSixSiege, "Rainbow Six Siege X", "Ubisoft servers (UDP 3074, 3658, 6015, 6115, 6150, 10000-10099).",
                FilterCategory.Server, FilterProtocol.Udp, "#0C4A6E", "#0EA5E9",
                FilterPlatform.Universal);
            Add(FilterPreset.CSGO, "CS2 / CS:GO", "Valve game servers (UDP 27000-27036).",
                FilterCategory.Server, FilterProtocol.Udp, "#92400E", "#F59E0B",
                FilterPlatform.PC);
            Add(FilterPreset.Overwatch, "Overwatch 2", "Blizzard servers (UDP 26000-26600, 6250 voice).",
                FilterCategory.Server, FilterProtocol.Udp, "#9A3412", "#F97316",
                FilterPlatform.Universal);
            Add(FilterPreset.Battlefield, "Battlefield", "DICE/EA servers. BF6, BF2042. UDP 3659, 14000-14016, 18000, 21000-21999, 22990-24000, 25200-25300.",
                FilterCategory.Server, FilterProtocol.Udp, "#1E40AF", "#3B82F6",
                FilterPlatform.Universal);
            Add(FilterPreset.Halo, "Halo Infinite", "343i servers (UDP 3074 session, 3075 datacenter).",
                FilterCategory.Server, FilterProtocol.Udp, "#14532D", "#22C55E",
                FilterPlatform.Xbox, FilterPlatform.PC);
            Add(FilterPreset.Destiny, "Destiny 2", "Bungie servers (UDP 3074, 3097, 3480).",
                FilterCategory.Server, FilterProtocol.Udp, "#4C1D95", "#8B5CF6",
                FilterPlatform.Universal);

            // Open world
            Add(FilterPreset.GTAOnline, "GTA Online", "Rockstar session host (UDP 6672, 61455-61458).",
                FilterCategory.Server, FilterProtocol.Udp, "#064E3B", "#10B981",
                FilterPlatform.Universal);
            Add(FilterPreset.RDR2Online, "RDR2 Online", "Rockstar session host (UDP 6672, 61455-61458).",
                FilterCategory.Server, FilterProtocol.Udp, "#7C2D12", "#EA580C",
                FilterPlatform.Universal);
            Add(FilterPreset.Rust, "Rust", "Facepunch servers (UDP 28015-28016 game, 28083 companion).",
                FilterCategory.Server, FilterProtocol.Udp, "#57534E", "#A8A29E",
                FilterPlatform.PC);
            Add(FilterPreset.ARK, "ARK", "Studio Wildcard servers (UDP 7777-7778, 27015-27016).",
                FilterCategory.Server, FilterProtocol.Udp, "#365314", "#84CC16",
                FilterPlatform.Universal);
            Add(FilterPreset.DayZ, "DayZ", "Bohemia servers (UDP 2302-2305, 27016).",
                FilterCategory.Server, FilterProtocol.Udp, "#1F2937", "#4B5563",
                FilterPlatform.Universal);
            Add(FilterPreset.Minecraft, "Minecraft Bedrock", "Bedrock host (UDP 19132-19133). Java uses TCP 25565.",
                FilterCategory.Server, FilterProtocol.Udp, "#14532D", "#65A30D",
                FilterPlatform.Universal);

            // Sports/racing
            Add(FilterPreset.RocketLeague, "Rocket League", "Psyonix payload signature.",
                FilterCategory.Server, FilterProtocol.Udp, "#1E3A8A", "#F59E0B",
                FilterPlatform.Universal);
            Add(FilterPreset.FIFA, "EA FC / FIFA", "EA Sports servers (UDP 3659, 9000-9999, 14000-14016). EA FC 26.",
                FilterCategory.Server, FilterProtocol.Udp, "#0F766E", "#14B8A6",
                FilterPlatform.Universal);
            Add(FilterPreset.NBA2K, "NBA 2K", "2K servers (UDP 3074, 5000-5500, 3478-3480).",
                FilterCategory.Server, FilterProtocol.Udp, "#7C2D12", "#EF4444",
                FilterPlatform.Universal);

            // Co-op / Survival
            Add(FilterPreset.DeadByDaylight, "Dead by Daylight", "BHVR servers (UDP 27000-27200, 8010-8400).",
                FilterCategory.Server, FilterProtocol.Udp, "#450A0A", "#7F1D1D",
                FilterPlatform.Universal);
            Add(FilterPreset.SeaOfThieves, "Sea of Thieves", "Rare / Xbox servers (UDP 3074, 3478-3480).",
                FilterCategory.Server, FilterProtocol.Udp, "#0C4A6E", "#0284C7",
                FilterPlatform.Universal);
            Add(FilterPreset.RecRoom, "Rec Room", "RecRoom hub (UDP 5056).",
                FilterCategory.Server, FilterProtocol.Udp, "#4C1D95", "#A855F7",
                FilterPlatform.Universal);

            // Fighting
            Add(FilterPreset.Tekken, "Tekken 8", "Bandai Namco P2P (UDP 3074).",
                FilterCategory.P2P, FilterProtocol.Udp, "#7F1D1D", "#B91C1C",
                FilterPlatform.Universal);
            Add(FilterPreset.MortalKombat, "Mortal Kombat 1", "NetherRealm P2P (UDP 3074).",
                FilterCategory.P2P, FilterProtocol.Udp, "#713F12", "#CA8A04",
                FilterPlatform.Universal);

            // Torrent
            Add(FilterPreset.uTorrent, "uTorrent", "BitTorrent traffic signature.",
                FilterCategory.P2P, FilterProtocol.Udp, "#1E3A8A", "#2563EB",
                FilterPlatform.PC);
            Add(FilterPreset.GenericTorrentClient, "Torrent (Generic)", "Generic BT checksum match.",
                FilterCategory.P2P, FilterProtocol.Udp, "#1F2937", "#4B5563",
                FilterPlatform.PC);

            // Console specific
            Add(FilterPreset.GTAVConsole, "GTA V (Console)", "Console-only GTA V session (UDP 3074, 6672, 61455-61458).",
                FilterCategory.Server, FilterProtocol.Udp, "#064E3B", "#10B981",
                FilterPlatform.PlayStation, FilterPlatform.Xbox);

            // Generic
            Add(FilterPreset.TCP, "TCP Only", "Match any TCP traffic.",
                FilterCategory.Universal, FilterProtocol.Tcp, "#1E40AF", "#3B82F6",
                FilterPlatform.Universal);
            Add(FilterPreset.UDP, "UDP Only", "Match any UDP traffic.",
                FilterCategory.Universal, FilterProtocol.Udp, "#166534", "#22C55E",
                FilterPlatform.Universal);

            // Custom (port-range user filters)
            Add(FilterPreset.Custom, "Custom Ranges", "Your user-defined port-range rules.",
                FilterCategory.NA, FilterProtocol.Udp, "#312E81", "#6366F1",
                FilterPlatform.Universal);

            return d;
        }
    }
}
