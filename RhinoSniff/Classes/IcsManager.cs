using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Threading.Tasks;

namespace RhinoSniff.Classes
{
    /// <summary>
    /// Phase 5 — Windows Internet Connection Sharing (ICS) via the HNetCfg.HNetShare COM API.
    /// Not tested by Claude — Rhino please verify.
    ///
    /// ICS lets one NIC (the "public" one, with internet) share its connection with another
    /// ("private", typically a hosted hotspot or another ethernet port). The COM class
    /// <c>HNetCfg.HNetShare</c> exposes a per-interface <c>INetSharingConfiguration</c> with
    /// EnableSharing(role) / DisableSharing().
    ///
    /// Role constants (ICS_SHARING_TYPE):
    ///   ICSSHARINGTYPE_PUBLIC  = 0 — the internet-facing adapter
    ///   ICSSHARINGTYPE_PRIVATE = 1 — the LAN/client-facing adapter
    ///
    /// We dispatch via late-bound COM (<see cref="Type.GetTypeFromProgID(string)"/>) to avoid
    /// needing tlbimp-generated interop assemblies at build time.
    /// </summary>
    public static class IcsManager
    {
        private const int ICSSHARINGTYPE_PUBLIC = 0;
        private const int ICSSHARINGTYPE_PRIVATE = 1;

        public class AdapterInfo
        {
            public string Name { get; set; } = "";
            public string Guid { get; set; } = "";
            public string Description { get; set; } = "";
            public bool SharingEnabled { get; set; }
            public int? SharingRole { get; set; } // 0 public, 1 private, null none
            public bool IsActive { get; set; }
        }

        private static object CreateHNetShare()
        {
            var t = Type.GetTypeFromProgID("HNetCfg.HNetShare");
            if (t == null) throw new InvalidOperationException("HNetCfg.HNetShare COM class not found — is the Home Networking service available?");
            return Activator.CreateInstance(t);
        }

        public static Task<List<AdapterInfo>> ListAsync()
        {
            return Task.Run(() =>
            {
                var list = new List<AdapterInfo>();
                object hnet = null;
                try
                {
                    hnet = CreateHNetShare();
                    dynamic d = hnet;
                    dynamic connections = d.EnumEveryConnection;
                    foreach (dynamic conn in connections)
                    {
                        AdapterInfo info = null;
                        try
                        {
                            dynamic props = d.NetConnectionProps[conn];
                            var name = (string)props.Name;
                            var guid = (string)props.Guid;
                            var device = (string)props.DeviceName;
                            var status = (int)props.Status;

                            dynamic cfg = d.INetSharingConfigurationForINetConnection[conn];
                            bool enabled = (bool)cfg.SharingEnabled;
                            int? role = null;
                            if (enabled)
                            {
                                try { role = (int)cfg.SharingConnectionType; } catch { /* older Windows */ }
                            }

                            info = new AdapterInfo
                            {
                                Name = name ?? "",
                                Guid = guid ?? "",
                                Description = device ?? "",
                                SharingEnabled = enabled,
                                SharingRole = role,
                                IsActive = status == 2 // NCS_CONNECTED
                            };
                        }
                        catch { /* skip per-connection failures */ }
                        if (info != null) list.Add(info);
                    }
                }
                catch (Exception e)
                {
                    _ = e.AutoDumpExceptionAsync();
                }
                finally
                {
                    if (hnet != null) Marshal.ReleaseComObject(hnet);
                }
                return list;
            });
        }

        /// <summary>
        /// Enable ICS: publicGuid shares out, privateGuid receives.
        /// Both GUIDs must come from <see cref="ListAsync"/> (INetConnectionProps.Guid).
        /// Any existing sharing on other adapters is disabled first (ICS only allows one
        /// public + one private at a time).
        /// </summary>
        public static Task<(bool Ok, string Error)> EnableAsync(string publicGuid, string privateGuid)
        {
            return Task.Run<(bool, string)>(() =>
            {
                if (string.IsNullOrWhiteSpace(publicGuid) || string.IsNullOrWhiteSpace(privateGuid))
                    return (false, "Pick both a public and a private adapter.");
                if (string.Equals(publicGuid, privateGuid, StringComparison.OrdinalIgnoreCase))
                    return (false, "Public and private adapter must be different.");

                object hnet = null;
                try
                {
                    hnet = CreateHNetShare();
                    dynamic d = hnet;

                    // Disable existing sharing first (ICS = 1 public + 1 private system-wide)
                    foreach (dynamic conn in d.EnumEveryConnection)
                    {
                        try
                        {
                            dynamic cfg = d.INetSharingConfigurationForINetConnection[conn];
                            if ((bool)cfg.SharingEnabled) cfg.DisableSharing();
                        }
                        catch { /* keep going */ }
                    }

                    bool appliedPublic = false, appliedPrivate = false;
                    foreach (dynamic conn in d.EnumEveryConnection)
                    {
                        dynamic props = d.NetConnectionProps[conn];
                        var guid = (string)props.Guid;
                        dynamic cfg = d.INetSharingConfigurationForINetConnection[conn];

                        if (string.Equals(guid, publicGuid, StringComparison.OrdinalIgnoreCase))
                        {
                            cfg.EnableSharing(ICSSHARINGTYPE_PUBLIC);
                            appliedPublic = true;
                        }
                        else if (string.Equals(guid, privateGuid, StringComparison.OrdinalIgnoreCase))
                        {
                            cfg.EnableSharing(ICSSHARINGTYPE_PRIVATE);
                            appliedPrivate = true;
                        }
                    }

                    if (!appliedPublic) return (false, "Public adapter not found.");
                    if (!appliedPrivate) return (false, "Private adapter not found.");
                    return (true, null);
                }
                catch (Exception e)
                {
                    _ = e.AutoDumpExceptionAsync();
                    return (false, e.Message);
                }
                finally
                {
                    if (hnet != null) Marshal.ReleaseComObject(hnet);
                }
            });
        }

        /// <summary>
        /// Disable ICS everywhere.
        /// </summary>
        public static Task<(bool Ok, string Error)> DisableAllAsync()
        {
            return Task.Run<(bool, string)>(() =>
            {
                object hnet = null;
                try
                {
                    hnet = CreateHNetShare();
                    dynamic d = hnet;
                    foreach (dynamic conn in d.EnumEveryConnection)
                    {
                        try
                        {
                            dynamic cfg = d.INetSharingConfigurationForINetConnection[conn];
                            if ((bool)cfg.SharingEnabled) cfg.DisableSharing();
                        }
                        catch { /* keep going */ }
                    }
                    return (true, null);
                }
                catch (Exception e)
                {
                    _ = e.AutoDumpExceptionAsync();
                    return (false, e.Message);
                }
                finally
                {
                    if (hnet != null) Marshal.ReleaseComObject(hnet);
                }
            });
        }
    }
}
