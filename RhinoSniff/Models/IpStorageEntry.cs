using System;
using Newtonsoft.Json;

namespace RhinoSniff.Models
{
    /// <summary>
    /// Phase 5 — replaces <see cref="Label"/> as the canonical IP Storage record.
    /// Persisted in %APPDATA%\RhinoSniff\ip_storage.json.
    /// </summary>
    public class IpStorageEntry
    {
        [JsonProperty("ip")] public string Ip { get; set; } = "";

        /// <summary>
        /// Free-form note. Maps to the old Label.Name on migration.
        /// Displayed as the "COMMENT" column in the IP Storage page and as the
        /// in-grid Label column during capture.
        /// </summary>
        [JsonProperty("comment")] public string Comment { get; set; } = "";

        [JsonProperty("createdUtc")] public DateTime CreatedUtc { get; set; } = DateTime.UtcNow;
    }
}
