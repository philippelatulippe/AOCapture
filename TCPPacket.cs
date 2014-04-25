using System.IO;

namespace AOCapture
{
    /**
     * This is only used to store out-of-order packets
     */
    class TCPPacket
    {
        public uint dataLength;
        public Stream packet;

        public TCPPacket(uint dataLength, Stream packet) {
            this.dataLength = dataLength;
            this.packet = packet;
        }

    }
}
