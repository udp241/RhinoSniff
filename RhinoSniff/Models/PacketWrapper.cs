using PacketDotNet;
using SharpPcap;

namespace RhinoSniff.Models
{
    public class PacketWrapper
    {
        public RawCapture p;

        private Packet _cachedPacket;
        private bool _parsed;
        private ProtocolType _cachedProtocol;

        public PacketWrapper(int count, RawCapture p)
        {
            Count = count;
            this.p = p;
            _cachedPacket = null;
            _parsed = false;
            _cachedProtocol = ProtocolType.Reserved254;
        }

        public int Count { get; }

        public LinkLayers LinkLayerType => p.LinkLayerType;

        public Packet Packet
        {
            get
            {
                if (!_parsed)
                {
                    _cachedPacket = Packet.ParsePacket(p.LinkLayerType, p.Data);
                    _parsed = true;
                    var ipPacket = _cachedPacket?.Extract<IPPacket>();
                    _cachedProtocol = ipPacket?.Protocol ?? ProtocolType.Reserved254;
                }
                return _cachedPacket;
            }
        }

        public ProtocolType Protocol
        {
            get
            {
                if (!_parsed)
                    _ = Packet;
                return _cachedProtocol;
            }
        }

        public PosixTimeval TimeValue => p.Timeval;
    }
}
