using System;
using System.Diagnostics;
using System.ServiceProcess;
using Microsoft.Win32;

namespace RhinoSniff.Classes
{
    /// <summary>
    /// Toggles Windows kernel IP forwarding so ARP-MITM'd packets actually get routed to the
    /// real gateway instead of dropped at the Windows IP layer. Without this, starting ARP
    /// spoofing black-holes the target's traffic — exactly the symptom where the target loses
    /// internet / gets kicked from online games mid-session.
    ///
    /// Two things have to happen:
    ///   1. HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\IPEnableRouter = 1
    ///   2. The RemoteAccess service has to be running (Windows routing stack is gated behind it).
    ///
    /// We capture the previous state on Enable() and restore on Disable() so we don't permanently
    /// turn the user's PC into a router.
    /// </summary>
    public static class IpForwarding
    {
        private const string TcpipParamsKey = @"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters";
        private const string IPEnableRouter = "IPEnableRouter";
        private const string RemoteAccessService = "RemoteAccess";

        // Previous state — captured at Enable(), used by Disable().
        private static int? _prevIpEnableRouter = null;
        private static ServiceStartMode? _prevRemoteAccessStart = null;
        private static bool _prevRemoteAccessRunning = false;
        private static string _interfaceName = null;   // Which NIC we enabled per-interface fwd on.
        private static bool _enabled = false;

        /// <summary>
        /// Enable kernel IP forwarding on the given interface. Returns true if successful.
        /// interfaceName is the Windows adapter friendly name (e.g. "Wi-Fi", "Ethernet").
        /// Required because on modern Windows (10/11) the global IPEnableRouter flag alone is
        /// NOT sufficient — per-interface forwarding must also be enabled via netsh.
        /// </summary>
        public static bool Enable(string interfaceName)
        {
            if (_enabled) return true;
            try
            {
                // 1. Registry: set IPEnableRouter = 1 (capture previous value first).
                using (var key = Registry.LocalMachine.OpenSubKey(TcpipParamsKey, writable: true))
                {
                    if (key == null) return false;
                    var prev = key.GetValue(IPEnableRouter);
                    _prevIpEnableRouter = prev is int i ? i : 0;
                    key.SetValue(IPEnableRouter, 1, RegistryValueKind.DWord);
                }

                // 2. Per-interface forwarding via netsh. On Windows 10/11 the global registry flag
                //    alone does NOT enable forwarding — each interface's forwarding property must
                //    also be set. Without this, ARP-redirected packets arrive at the NIC but get
                //    dropped at the IP layer (one-way forwarding bug — target sees downstream but
                //    can't send upstream, game sessions freeze/kick).
                if (!string.IsNullOrWhiteSpace(interfaceName))
                {
                    _interfaceName = interfaceName;
                    RunNetsh($"interface ipv4 set interface \"{interfaceName}\" forwarding=enabled");
                    RunNetsh($"interface ipv6 set interface \"{interfaceName}\" forwarding=enabled");
                }

                // 3. RemoteAccess service: set to Manual (if Disabled, can't be started) + start it.
                try
                {
                    using var sc = new ServiceController(RemoteAccessService);
                    _prevRemoteAccessStart = GetServiceStartMode(RemoteAccessService);
                    _prevRemoteAccessRunning = sc.Status == ServiceControllerStatus.Running;

                    if (_prevRemoteAccessStart == ServiceStartMode.Disabled)
                        SetServiceStartMode(RemoteAccessService, ServiceStartMode.Manual);

                    if (sc.Status != ServiceControllerStatus.Running)
                    {
                        sc.Start();
                        sc.WaitForStatus(ServiceControllerStatus.Running, TimeSpan.FromSeconds(10));
                    }
                }
                catch
                {
                    // RemoteAccess service is best-effort. Some stripped Windows SKUs don't have it
                    // but forwarding can still work with just the registry flag + netsh + a reboot.
                    // We don't force a reboot — flag it and move on.
                }

                _enabled = true;
                return true;
            }
            catch (Exception e)
            {
                _ = e.AutoDumpExceptionAsync();
                return false;
            }
        }

        /// <summary>
        /// Restore the previous state captured at Enable(). Call when ARP poisoning stops so the
        /// user's PC doesn't keep routing traffic after we're done. Safe no-op if never enabled.
        /// </summary>
        public static void Disable()
        {
            if (!_enabled) return;
            try
            {
                // 1. Per-interface forwarding: reset to disabled (default state for home PCs).
                if (!string.IsNullOrWhiteSpace(_interfaceName))
                {
                    try
                    {
                        RunNetsh($"interface ipv4 set interface \"{_interfaceName}\" forwarding=disabled");
                        RunNetsh($"interface ipv6 set interface \"{_interfaceName}\" forwarding=disabled");
                    }
                    catch { }
                }

                // 2. Registry: restore previous IPEnableRouter value.
                if (_prevIpEnableRouter.HasValue)
                {
                    try
                    {
                        using var key = Registry.LocalMachine.OpenSubKey(TcpipParamsKey, writable: true);
                        key?.SetValue(IPEnableRouter, _prevIpEnableRouter.Value, RegistryValueKind.DWord);
                    }
                    catch { }
                }

                // 3. RemoteAccess: stop if we started it + restore original start mode.
                if (_prevRemoteAccessStart.HasValue)
                {
                    try
                    {
                        using var sc = new ServiceController(RemoteAccessService);
                        if (!_prevRemoteAccessRunning && sc.Status == ServiceControllerStatus.Running)
                        {
                            sc.Stop();
                            try { sc.WaitForStatus(ServiceControllerStatus.Stopped, TimeSpan.FromSeconds(10)); }
                            catch { }
                        }
                        if (GetServiceStartMode(RemoteAccessService) != _prevRemoteAccessStart.Value)
                            SetServiceStartMode(RemoteAccessService, _prevRemoteAccessStart.Value);
                    }
                    catch { }
                }
            }
            catch (Exception e)
            {
                _ = e.AutoDumpExceptionAsync();
            }
            finally
            {
                _prevIpEnableRouter = null;
                _prevRemoteAccessStart = null;
                _prevRemoteAccessRunning = false;
                _interfaceName = null;
                _enabled = false;
            }
        }

        private static void RunNetsh(string args)
        {
            var psi = new ProcessStartInfo("netsh.exe", args)
            {
                CreateNoWindow = true,
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true
            };
            using var p = Process.Start(psi);
            p?.WaitForExit(5000);
        }

        private static ServiceStartMode GetServiceStartMode(string serviceName)
        {
            using var sc = new ServiceController(serviceName);
            return sc.StartType;
        }

        private static void SetServiceStartMode(string serviceName, ServiceStartMode mode)
        {
            // Use sc.exe — the managed ServiceController API has no StartType setter on .NET 6.
            var startArg = mode switch
            {
                ServiceStartMode.Automatic => "auto",
                ServiceStartMode.Manual    => "demand",
                ServiceStartMode.Disabled  => "disabled",
                ServiceStartMode.Boot      => "boot",
                ServiceStartMode.System    => "system",
                _ => "demand"
            };
            var psi = new ProcessStartInfo("sc.exe", $"config {serviceName} start= {startArg}")
            {
                CreateNoWindow = true,
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true
            };
            using var p = Process.Start(psi);
            p?.WaitForExit(5000);
        }
    }
}
