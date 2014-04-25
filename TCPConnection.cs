using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.IO;
using ComponentAce.Compression.Libs.zlib;

namespace AOCapture
{
    class TCPConnection
    {
        public int localPort;
        public int remotePort;
        public SortedList<uint /*seqNo*/, TCPPacket> outOfOrderPackets;
        public Object dataParser;
        public ZInputStream decompressor;

        private UInt32 _receivingSequenceNumber;
        public UInt32 receivingSequenceNumber
        {
            get { return _receivingSequenceNumber; }
            set
            {
                receivingStreamOpen = true;
                _receivingSequenceNumber = value;
            }
        }

        //TODO: remove, right now each side of the connection gets its own TCPConnection
        private UInt32 _sendingSequenceNumber;
        public UInt32 sendingSequenceNumber
        {
            get { return _sendingSequenceNumber; }
            set
            {
                sendingStreamOpen = true;
                _sendingSequenceNumber = value;
            }
        }

        public bool receivingStreamOpen = false;
        public bool sendingStreamOpen = false;


        public TCPConnection(int localPort, int remotePort)
        {
            this.localPort = localPort;
            this.remotePort = remotePort;
            this.outOfOrderPackets = new SortedList<uint, TCPPacket>();
        }
    }
}
