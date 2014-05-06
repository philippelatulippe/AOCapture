using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using SmokeLounge.AOtomation.Messaging.Messages;
using SmokeLounge.AOtomation.Messaging.Serialization;
using PcapngFile;
using System.IO;
using System.Net;
using ComponentAce.Compression.Libs.zlib;

using SmokeLounge.AOtomation.Messaging.Messages.N3Messages;
namespace AOCapture
{
    class Program
    {
        static void Main(string[] args)
        {
            var streams = new Dictionary<int,TCPConnection>();

            if (args.Count() < 1){
                Console.WriteLine("Give me a .pcapng file captured while playing Anarchy Online.");
                Console.WriteLine("I'll try to extract data important for historical preservation of AO, like NPC");
                Console.WriteLine("dialog.");
                //TODO link to site
                return;
            }

            var reader = new Reader(args[0]);

            foreach (var block in reader.AllBlocks)
            {
                byte[] data = null;
                if(block is SimplePacketBlock){
                    data = ((SimplePacketBlock)block).Data;
                }else if (block is EnhancedPacketBlock){
                    data = ((EnhancedPacketBlock)block).Data;
                }

                if (data != null && data.Length > 0){
                    //Dirty Ethernet+IP+TCP parser

                    //Assumes that data is Ethernet.  If this is a problem, see LinkType: http://www.winpcap.org/ntar/draft/PCAP-DumpFileFormat.html#sectionidb

                    var stream = new MemoryStream(data);
                    var breader = new BinaryReader(stream);

                    try
                    {
                        //skip mac addresses
                        breader.BaseStream.Seek(12, SeekOrigin.Current);

                        int etherType = breader.ReadInt16();

                        if (etherType != 0x0008) {//Check if IPv4
                            continue;
                        }

                        int ipVersionThenLength = breader.ReadByte();

                        if ((ipVersionThenLength >> 4) != 0x04){//IPv4?
                            continue;
                        }

                        int ipHeaderLength = (ipVersionThenLength & 0x0F) * 4;

                        int dscp = breader.ReadByte();

                        UInt16 ipTotalLength = (UInt16)IPAddress.NetworkToHostOrder((short)breader.ReadInt16());

                        int offsetBetweenLengthAndProtoField = 5;

                        breader.BaseStream.Seek(offsetBetweenLengthAndProtoField, SeekOrigin.Current);
                        int dataProto = breader.ReadByte();

                        if (dataProto != 0x06) {
                            continue;
                        }

                        //Skip rest of IP header
                        breader.BaseStream.Seek(ipHeaderLength - offsetBetweenLengthAndProtoField - 1 - 1 - 3, SeekOrigin.Current); //-1: length field, already read.
                        //We assume port pairs will be enough to identify connections and their direction (i.e. only one interface per trace, no locally hosted AO server)


                        UInt16 srcPort = (UInt16)IPAddress.NetworkToHostOrder((short)breader.ReadUInt16());
                        UInt16 dstPort = (UInt16)IPAddress.NetworkToHostOrder((short)breader.ReadUInt16());
                        UInt32 seqNo = (UInt32)IPAddress.NetworkToHostOrder((Int32)breader.ReadUInt32());
                        UInt32 ackNo = (UInt32)IPAddress.NetworkToHostOrder((Int32)breader.ReadUInt32());
                        int tcpHeaderLength = 4 * (breader.ReadByte() >> 4);
                        int flags = breader.ReadByte();
                        int windowSize = (UInt16)IPAddress.NetworkToHostOrder((short)breader.ReadInt16());
                        int checksum = (UInt16)IPAddress.NetworkToHostOrder((short)breader.ReadInt16());
                        int urgentPointerLol = (UInt16)IPAddress.NetworkToHostOrder((short)breader.ReadInt16());

                        bool ack = (flags & (1 << 4)) != 0;
                        bool psh = (flags & (1 << 3)) != 0;
                        bool rst = (flags & (1 << 2)) != 0;
                        bool syn = (flags & (1 << 1)) != 0;
                        bool fin = (flags & (1 << 0)) != 0;


                        breader.BaseStream.Seek(tcpHeaderLength - 20, SeekOrigin.Current);

                        int localPort;
                        TCPConnection tcpStream;

                        if (srcPort == 7511 || dstPort == 7511){
                            bool gotStream = streams.TryGetValue(dstPort, out tcpStream);

                            uint tcpDataLength = (uint)(ipTotalLength-ipHeaderLength-tcpHeaderLength);

                            if (ipTotalLength-ipHeaderLength-tcpHeaderLength > 0) {
                                if (!gotStream){
                                    tcpStream = new TCPConnection(dstPort, srcPort);
                                    streams.Add(dstPort, tcpStream);
                                }

                                if (!tcpStream.receivingStreamOpen){
                                    //first packet we've seen
                                    tcpStream.receivingSequenceNumber = seqNo;
                                    tcpStream.dataParser = new MessageSerializer();
                                }

                                if (tcpStream.receivingSequenceNumber == seqNo) {
                                    Stream finalPDU;
                                    SubStream tcpPDU = new SubStream(stream, tcpDataLength);

                                    if (tcpStream.decompressor != null) {
                                        tcpStream.decompressor.BaseStream.Position = 0;
                                        tcpStream.decompressor.BaseStream.SetLength(0);
                                        tcpPDU.CopyTo(tcpStream.decompressor.BaseStream);
                                        tcpStream.decompressor.BaseStream.Position = 0;
                                        tcpStream.decompressor.nomoreinput = false;

                                        finalPDU = new MemoryStream(4096);
                                        byte[] buffer = new byte[2048];
                                        int decompressedBytesRead = 0;
                                        while ((decompressedBytesRead = tcpStream.decompressor.read(buffer, 0, 2048)) > 0) { //don't call capital R Read!
                                            finalPDU.Write(buffer, 0, decompressedBytesRead);
                                            //Use this instead to help debug end of stream exceptions: finalPDU.Write(buffer, 0, 2048);
                                        }

                                    } else {
                                        finalPDU = tcpPDU;
                                    }

                                    Message message = null;
                                    bool exception = false;
                                    try {
                                        message = ((MessageSerializer)tcpStream.dataParser).Deserialize(finalPDU);
                                    } catch (Exception e) {
                                        Console.Write(srcPort + " EXCEPTION");
                                        if (e.Data.Contains("aoPacketType")) {
                                            Console.Write(", packet type: " + e.Data["aoPacketType"]);
                                        }
                                        Console.WriteLine();
                                    }

                                    if(!exception){
                                        savePacket(srcPort, message, finalPDU);
                                    }

                                    if (message!=null && message.Body is SmokeLounge.AOtomation.Messaging.Messages.InitiateCompressionMessage) {
                                        if (message.Header.Sender == 0x01000000) {
                                            Console.WriteLine("Server wants compression!"); //the AOCell code says that 03 is compression, but I think it's the other way around
                                            tcpStream.decompressor = new ZInputStream(new MemoryStream(1450));
                                            tcpStream.decompressor.FlushMode = zlibConst.Z_NO_FLUSH;
                                            //I should let the TCPConnection handle the decompression, and give it lambda that hands back data
                                            //Also, it would be good to have a zlib library that doesn't expect a single stream when decompressing
                                        }
                                    }
                                    tcpStream.receivingSequenceNumber += tcpDataLength;

                                    //See if the next packet has already arrived
                                    while(tcpStream.outOfOrderPackets.Count > 0  && tcpStream.outOfOrderPackets.First().Key == seqNo){
                                        TCPPacket outOfOrderPacket = tcpStream.outOfOrderPackets.First().Value;
                                        SubStream tcpPDU2 = new SubStream(outOfOrderPacket.packet, outOfOrderPacket.dataLength);
                                        Message message2 = ((MessageSerializer)tcpStream.dataParser).Deserialize(tcpPDU2);
                                        savePacket(srcPort, message2, tcpPDU2);
                                        tcpStream.receivingSequenceNumber += outOfOrderPacket.dataLength;
                                    }
                                } else if(tcpStream.receivingSequenceNumber < seqNo){
                                    //This packet arrived before its predecessor
                                    tcpStream.outOfOrderPackets.Add(seqNo, new TCPPacket(tcpDataLength, breader.BaseStream));  //UM, CAN A TCP STACK DECIDE TO RESEND A DIFFIRENT PORTION OF THE STREAM?  probably not, since the ack could have been lost and the packet read by the other end.  Then the other would have to start splitting packet, I doubt they made the protocol that complicate for no reason.
                                    if (tcpStream.outOfOrderPackets.Count() == 15) {
                                        Console.WriteLine("Out-of-order-packet queue is getting big!  Is this capture missing a packet?");
                                        //To find out, we'd need to analyze ACKs.
                                    }else if(tcpStream.outOfOrderPackets.Count() > 25){
                                        Console.WriteLine("This capture is probably missing a packet.  Aborting.");
                                        return;
                                    }
                                }
                            }
                        }


                    }
                    /*catch (Exception e)
                    {
                        Console.WriteLine("Weird packet?");
                    }*/
                    finally
                    {
                        stream.Close();
                    }


                }
            }
        }

        static void savePacket(int srcPort, Message message, Stream data){
            if (message != null) {
                Console.WriteLine(srcPort+" "+message.Body.GetType().Name+" size="+message.Header.Size);

                //What packet do you get when you literally walk away from a conversation?  Change playfield?
                //Can you have multiple conversations simultaneously?
                //You still need to fix your TCP parser to reassemble packets (erp)
                //What about timing information (for animations and reponses)? (probably also requires refactoring)

                if (message.Body is KnuBotOpenChatWindowMessage){
                    KnuBotOpenChatWindowMessage body = (KnuBotOpenChatWindowMessage)message.Body;
                    string conversationIdentity =  body.Identity.Instance.ToString();
                    Console.WriteLine("    Begin conversation with " +conversationIdentity);
                }else if(message.Body is  KnuBotAnswerListMessage) {
                    KnuBotAnswerListMessage body = (KnuBotAnswerListMessage)message.Body;
                    Console.WriteLine("    Dialog Options: ");
                    foreach(var option in body.DialogOptions){
                        Console.WriteLine("    - "+option.Text);
                    }
                }else if(message.Body is KnuBotAnswerMessage){
                    KnuBotAnswerMessage body = (KnuBotAnswerMessage)message.Body;
                    string conversationIdentity = body.Identity.Instance.ToString();
                    Console.WriteLine("Answered with option: " + body.Answer);
                    Console.WriteLine("ok?");
                }else if(message.Body is KnuBotAppendTextMessage){
                    KnuBotAppendTextMessage body = (KnuBotAppendTextMessage)message.Body;
                    string conversationIdentity = body.Identity.Instance.ToString();
                    Console.WriteLine(conversationIdentity + " says: " + body.Text);
                    Console.WriteLine("ok?");
                }else if(message.Body is CharacterActionMessage){
                    CharacterActionMessage body = (CharacterActionMessage)message.Body;
                    string identity = body.Identity.Instance.ToString();
                    Console.WriteLine("    Character " + identity + " performs action "+body.Action.ToString());
                }
            } else {
                data.Position = 0;
                byte[] buffer = new byte[20];
                int countRead = data.Read(buffer, 0, buffer.Length);

                bool allZero = true;
                foreach (byte b in buffer) {
                    if (b != 0) {
                        allZero = false;
                        break;
                    }
                }

                if (countRead <= 0) {
                    Console.WriteLine(srcPort + " Could not deserialize: EMPTY PACKET");
                } else if (allZero) {
                    Console.WriteLine(srcPort + " Could not deserialize: ZEROES EVERYWHERE");
                } else if (countRead > 0) {
                    Console.WriteLine(srcPort + " Could not deserialize, unknown packet: " + BitConverter.ToString(buffer));
                } else {
                    Console.WriteLine(srcPort + " Could not deserialize, empty packet");
                }
            }
        }
    }
}
