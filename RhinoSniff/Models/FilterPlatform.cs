namespace RhinoSniff.Models
{
    public enum FilterPlatform
    {
        Universal,
        PC,
        PlayStation,
        Xbox,
        Mobile,
        Android,
        iOS,
        Server,

        // ── Granular console generations (User-created Cloud filters) ──
        // Used by the Cloud filter wizard (PS3/PS4/PS5, Xbox 360/One/Series X).
        // Built-in FilterRegistry entries continue to use the broad PlayStation / Xbox values.
        // PlatformBrush falls these back to the PSN / Xbox brushes, PlatformLabel renders readable text.
        PS3,
        PS4,
        PS5,
        Xbox360,
        XboxOne,
        XboxSeriesX
    }

    /// <summary>
    /// Metadata taxonomy. Server = dedicated game server (matches server IP).
    /// P2P = peer-to-peer (console party, uTorrent, etc.). Universal = cross-platform.
    /// NA = no meaningful category (TCP/UDP/Custom).
    /// </summary>
    public enum FilterCategory
    {
        NA,
        Server,
        P2P,
        Universal
    }

    public enum IspFilterBehavior
    {
        /// <summary>Hide rows whose ISP does NOT match any entry.</summary>
        Hide,
        /// <summary>Keep rows visible but dim non-matching rows.</summary>
        Dim
    }
}
