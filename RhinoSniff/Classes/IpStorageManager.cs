using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using Newtonsoft.Json;
using RhinoSniff.Models;

namespace RhinoSniff.Classes
{
    /// <summary>
    /// Phase 5 — canonical store for user-labeled IPs. Replaces the <see cref="Settings.Labels"/>
    /// list as the primary persistence point. Labels still exists as a shadow copy so legacy
    /// capture-path code (MainWindow line ~2549) keeps working without modification until
    /// Phase 6 Settings restructure.
    ///
    /// File layout: %APPDATA%\RhinoSniff\ip_storage.json (plain JSON, not encrypted — comments
    /// are user-authored notes, no secrets.)
    /// </summary>
    public static class IpStorageManager
    {
        private static readonly string StorageDir = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "RhinoSniff");

        private static readonly string StorageFile = Path.Combine(StorageDir, "ip_storage.json");

        private static readonly object Gate = new();

        private static List<IpStorageEntry> _entries = new();

        /// <summary>
        /// True once <see cref="LoadAsync"/> has run to completion.
        /// </summary>
        public static bool Loaded { get; private set; }

        /// <summary>
        /// Raised when the store changes (add / update / delete / clear / migration).
        /// IPStorage view subscribes to refresh its DataGrid.
        /// </summary>
        public static event Action Changed;

        public static IReadOnlyList<IpStorageEntry> Entries
        {
            get { lock (Gate) return _entries.ToList(); }
        }

        public static int Count
        {
            get { lock (Gate) return _entries.Count; }
        }

        /// <summary>
        /// Load from disk. On first run (no file), migrates existing Settings.Labels → ip_storage.json
        /// (one shot). Settings.Labels is kept populated on save so existing capture code keeps working.
        /// </summary>
        public static async Task LoadAsync()
        {
            try
            {
                if (!Directory.Exists(StorageDir))
                    Directory.CreateDirectory(StorageDir);

                if (!File.Exists(StorageFile))
                {
                    // First run — migrate from Settings.Labels if present
                    var migrated = new List<IpStorageEntry>();
                    if (Globals.Settings?.Labels != null)
                    {
                        foreach (var lbl in Globals.Settings.Labels)
                        {
                            if (string.IsNullOrWhiteSpace(lbl.IpAddress)) continue;
                            migrated.Add(new IpStorageEntry
                            {
                                Ip = lbl.IpAddress.Trim(),
                                Comment = lbl.Name ?? "",
                                CreatedUtc = DateTime.UtcNow
                            });
                        }
                    }
                    lock (Gate) _entries = migrated;
                    await SaveAsyncInternal();
                    Loaded = true;
                    Changed?.Invoke();
                    return;
                }

                var json = await File.ReadAllTextAsync(StorageFile);
                var list = JsonConvert.DeserializeObject<List<IpStorageEntry>>(json) ?? new List<IpStorageEntry>();
                lock (Gate) _entries = list;

                // Keep Settings.Labels shadow in sync so capture code still resolves labels
                SyncShadow();

                Loaded = true;
                Changed?.Invoke();
            }
            catch (Exception e)
            {
                await e.AutoDumpExceptionAsync();
                lock (Gate) _entries = new List<IpStorageEntry>();
                Loaded = true;
            }
        }

        public static async Task<bool> AddAsync(string ip, string comment)
        {
            if (string.IsNullOrWhiteSpace(ip)) return false;
            ip = ip.Trim();
            comment = (comment ?? "").Trim();

            lock (Gate)
            {
                // De-dupe by IP (case-insensitive for safety — IPs shouldn't differ in case
                // but some edge cases with hex / IPv6 later)
                var existing = _entries.FirstOrDefault(e =>
                    string.Equals(e.Ip, ip, StringComparison.OrdinalIgnoreCase));
                if (existing != null)
                {
                    existing.Comment = comment;
                }
                else
                {
                    _entries.Add(new IpStorageEntry
                    {
                        Ip = ip,
                        Comment = comment,
                        CreatedUtc = DateTime.UtcNow
                    });
                }
            }

            await SaveAsyncInternal();
            Changed?.Invoke();
            return true;
        }

        public static async Task<bool> UpdateAsync(string ip, string newComment)
        {
            if (string.IsNullOrWhiteSpace(ip)) return false;
            lock (Gate)
            {
                var existing = _entries.FirstOrDefault(e =>
                    string.Equals(e.Ip, ip, StringComparison.OrdinalIgnoreCase));
                if (existing == null) return false;
                existing.Comment = (newComment ?? "").Trim();
            }
            await SaveAsyncInternal();
            Changed?.Invoke();
            return true;
        }

        public static async Task<bool> DeleteAsync(string ip)
        {
            if (string.IsNullOrWhiteSpace(ip)) return false;
            bool removed;
            lock (Gate)
            {
                removed = _entries.RemoveAll(e =>
                    string.Equals(e.Ip, ip, StringComparison.OrdinalIgnoreCase)) > 0;
            }
            if (removed)
            {
                await SaveAsyncInternal();
                Changed?.Invoke();
            }
            return removed;
        }

        public static async Task ClearAsync()
        {
            lock (Gate) _entries.Clear();
            await SaveAsyncInternal();
            Changed?.Invoke();
        }

        /// <summary>
        /// O(n) lookup. Called per-packet from the capture path via the shadow Settings.Labels
        /// list so this isn't hot path — kept for the Add-to-Storage dialog.
        /// </summary>
        public static string LookupComment(string ip)
        {
            if (string.IsNullOrWhiteSpace(ip)) return null;
            lock (Gate)
            {
                var hit = _entries.FirstOrDefault(e =>
                    string.Equals(e.Ip, ip, StringComparison.OrdinalIgnoreCase));
                return hit?.Comment;
            }
        }

        private static async Task SaveAsyncInternal()
        {
            try
            {
                List<IpStorageEntry> snapshot;
                lock (Gate) snapshot = _entries.ToList();

                if (!Directory.Exists(StorageDir))
                    Directory.CreateDirectory(StorageDir);

                var json = JsonConvert.SerializeObject(snapshot, Formatting.Indented);
                await File.WriteAllTextAsync(StorageFile, json);

                // Keep Settings.Labels shadow in sync so the capture path (MainWindow ~2549)
                // and the Add-to-Labels menu item (~1046) see the same data without being
                // rewritten. Phase 6 will sever this link when Settings restructures.
                SyncShadow();
            }
            catch (Exception e)
            {
                await e.AutoDumpExceptionAsync();
            }
        }

        private static void SyncShadow()
        {
            if (Globals.Settings == null) return;
            List<IpStorageEntry> snapshot;
            lock (Gate) snapshot = _entries.ToList();
            Globals.Settings.Labels = snapshot
                .Select(e => new Label { IpAddress = e.Ip, Name = e.Comment })
                .ToList();
        }
    }
}
