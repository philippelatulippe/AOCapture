using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.IO;

namespace AOCapture
{

    /**
     * Takes a stream and only exposes a specified subsection of the stream.
     */
    public class SubStream : Stream
    {
        private Stream stream;
        private long startPosition;
        private long endPosition;

        /**
         * Creates a stream that starts at the current position of the stream in the argument.
         */
        public SubStream(Stream stream)
        {
            this.stream = stream;
            this.startPosition = stream.Position;
        }

        /**
         * Creates a stream that starts at the current position of the stream in the argument,
         * and ends after length bytes.
         */
        public SubStream(Stream stream, long length)
            : this(stream)
        {
            this.endPosition = this.startPosition + length;
        }

        public override bool CanRead { get {return stream.CanRead;} }
        public override bool CanSeek { get { return stream.CanSeek; } }
        public override bool CanTimeout { get { return stream.CanTimeout; } }
        public override bool CanWrite { get { return stream.CanWrite; } }
        public override long Length { get { return this.endPosition - this.startPosition; } }
        public override int ReadTimeout { get { return stream.ReadTimeout; } }
        public override int WriteTimeout { get { return stream.WriteTimeout; } }

        public override void Close() { stream.Close(); }
        //HEY! Do I really want to dispose the underlying stream?
        public new void Dispose() { stream.Dispose(); }
        public override void Flush() { stream.Flush(); }

        public override long Position {
            set { this.Seek(value, SeekOrigin.Begin); } 
            get {
                return this.stream.Position - this.startPosition;
            }
        }

        public override int Read(byte[] buffer, int offset, int count)
        {
            if(this.stream.Position + count == this.endPosition + 1){
                return 0;
            }else if (this.stream.Position + count > this.endPosition) {
                //HEY! Does my little equation still work if Position > endPosition? Just in case there's a bug
                return this.stream.Read(buffer, offset, (int)(this.endPosition - this.stream.Position));
            }else{
                return this.stream.Read(buffer, offset, count);
            }
        }

        public override int ReadByte()
        {
            if (this.stream.Position == this.endPosition) {
                return -1;
            } else {
                return this.stream.ReadByte();
            }
        }

        //Note: seeking beyond the length of the stream is *not* supported
        public override long Seek(long offset, SeekOrigin origin)
        {
            //TODO: double-check the fenceposts
            switch(origin){
                case SeekOrigin.Begin:
                    if (this.startPosition + offset > this.endPosition || this.startPosition + offset < this.startPosition) {
                        throw new ArgumentException();
                    };
                    return this.stream.Seek(this.startPosition + offset, origin) - this.startPosition;
                case SeekOrigin.Current:
                    if (this.stream.Position + offset > this.endPosition || this.stream.Position + offset < this.startPosition) {
                        throw new ArgumentException();
                    };
                    return this.stream.Seek(offset, origin) - this.startPosition;
                case SeekOrigin.End:
                    if (this.endPosition + offset > this.endPosition || this.endPosition + offset < this.startPosition) {
                        throw new ArgumentException();
                    };
                    return this.stream.Seek(offset, origin) - this.startPosition;
                default:
                    throw new ArgumentException();
            }
        }

        public override void SetLength(long value)
        {
            //NOT IMPLEMENTED
        }

        public override void Write(byte[] buffer, int offset, int count)
        { 
            //not implemented
        }


        static void Main(string[] args)
        {
            MemoryStream ms = new MemoryStream(Encoding.UTF8.GetBytes("0123456789"));
            SubStream ss1 = new SubStream(ms,5);

            StreamReader sr1 = new StreamReader(ss1);
            Console.Write("From 0 to 4: ");
            while (sr1.Peek() >= 0) {
                char[] c = new char[1];
                sr1.Read(c,0,1);
                Console.Write(c[0]+" ");
            }
            Console.WriteLine();

            ss1.Position = 0;
            ss1 = new SubStream(ms, 6);
            sr1 = new StreamReader(ss1);
            Console.Write("From 0 to 5: ");
            while (sr1.Peek() >= 0) {
                char[] c = new char[1];
                sr1.Read(c, 0, 1);
                Console.Write(c[0] + " ");
            }

            Console.WriteLine();
            ms.Position = 3;
            ss1 = new SubStream(ms, 3);
            sr1 = new StreamReader(ss1);
            Console.Write("From 3 to 5: ");
            while (sr1.Peek() >= 0) {
                char[] c = new char[1];
                sr1.Read(c, 0, 1);
                Console.Write(c[0] + " ");
            }
            Console.WriteLine();


            Console.WriteLine();
            ms.Position = 1;
            ss1 = new SubStream(ms, 5);
            ss1.Seek(2,SeekOrigin.Begin);
            sr1 = new StreamReader(ss1);
            Console.Write("From 3 to 5 (seek from 'Begin'): ");
            while (sr1.Peek() >= 0) {
                char[] c = new char[1];
                sr1.Read(c, 0, 1);
                Console.Write(c[0] + " ");
            }
            Console.WriteLine();

            Console.WriteLine();
            var binaryReader = new BinaryReader(ss1);
            ss1.Position = 0;
            int reddByte = binaryReader.ReadByte();
            Console.Write("ReadByte: "+reddByte);
            Console.WriteLine();


            Console.WriteLine();
        }
    }
}
