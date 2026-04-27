using System.Linq;
using System.Threading.Tasks;
using RhinoSniff.Interfaces;
using RhinoSniff.Models;
using PacketDotNet;

namespace RhinoSniff.Classes
{
    public class PacketFilter : IPacketFilter
    {
        public Task<bool> FilterPacketAsync(PacketWrapper packetWrapper)
        {
            var packet = packetWrapper.Packet.Extract<IPPacket>();
            return Task.FromResult(packet is not null);
        }
    }
}