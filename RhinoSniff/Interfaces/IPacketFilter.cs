using RhinoSniff.Models;
using System.Threading.Tasks;

namespace RhinoSniff.Interfaces
{
    internal interface IPacketFilter
    {
        public Task<bool> FilterPacketAsync(PacketWrapper wrapper);
    }
}