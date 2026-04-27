namespace RhinoSniff.Models
{
    public enum FilterPreset
    {
        None,
        TCP,
        UDP,

        // --- Console Party ---
        PSNParty,
        XboxPartyBETA,
        Discord,

        // --- Battle Royale ---
        Fortnite,
        ApexLegends,
        PUBG,

        // --- Call of Duty (all titles use same ports) ---
        CallOfDuty,

        // --- Tactical / FPS ---
        Valorant,
        RainbowSixSiege,
        CSGO,
        Overwatch,
        Battlefield,
        Halo,
        Destiny,

        // --- Open World ---
        GTAOnline,
        RDR2Online,
        Rust,
        ARK,
        DayZ,
        Minecraft,

        // --- Sports / Racing ---
        RocketLeague,
        FIFA,
        NBA2K,
        
        // --- Co-op / Survival ---
        DeadByDaylight,
        SeaOfThieves,
        RecRoom,

        // --- Fighting ---
        Tekken,
        MortalKombat,

        // --- Torrent ---
        uTorrent,
        GenericTorrentClient,

        // --- Console specific ---
        GTAVConsole,

        // --- User-defined ---
        Custom
    }
}
