using System;
using System.Collections.Generic;
using System.Text;

namespace Trillian
{
    public enum LogRootVersion : UInt16 { V1 = 1 }

    public class LogRootV1
    {
        public UInt64 TreeSize;
        public byte[] RootHash;
        public UInt64 TimestampNanos;
        public UInt64 Revision;
        public byte[] Metadata;
    }

    public class LogRoot
    {
        public LogRootVersion Version;
        public LogRootV1 LogRootV1;
    }
}
