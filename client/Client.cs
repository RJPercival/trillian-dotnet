using System;
using System.IO;
using System.Threading.Tasks;

namespace Trillian
{
    public class Client
    {
        public Client(TrillianLog.TrillianLogClient client)
        {
            this.client = client;
        }

        public async Task<LogRoot> GetLatestLogRoot(long logId)
        {
            var resp = await client.GetLatestSignedLogRootAsync(new GetLatestSignedLogRootRequest
            {
                LogId = logId,
            });

            // TODO: Verify signature

            using var reader = new BinaryReader(new MemoryStream(resp.SignedLogRoot.LogRoot.ToByteArray()));
            return ParseLogRoot(reader);
        }

        public async Task<bool> CheckConsistency(long logId, LogRootV1 first, LogRootV1 second)
        {
            var resp = await client.GetConsistencyProofAsync(new GetConsistencyProofRequest
            {
                LogId = logId,
                FirstTreeSize = (Int64)first.TreeSize,
                SecondTreeSize = (Int64)second.TreeSize,
            });

            return Verifier.VerifyConsistencyProof(first, second, resp.Proof);
        }

        private LogRoot ParseLogRoot(BinaryReader reader)
        {
            LogRoot logRoot = new LogRoot();
            logRoot.Version = (LogRootVersion)reader.ReadUInt16();
            switch (logRoot.Version)
            {
                case LogRootVersion.V1:
                    logRoot.LogRootV1 = ParseLogRootV1(reader);
                    break;
                default:
                    throw new ArgumentOutOfRangeException("LogRoot.Version", logRoot.Version, "not supported");
            }

            return logRoot;
        }

        private LogRootV1 ParseLogRootV1(BinaryReader reader)
        {
            LogRootV1 logRoot = new LogRootV1();
            logRoot.TreeSize = reader.ReadUInt64();
            int rootHashLen = reader.ReadByte();
            logRoot.RootHash = reader.ReadBytes(rootHashLen);
            logRoot.TimestampNanos = reader.ReadUInt64();
            logRoot.Revision = reader.ReadUInt64();
            int metadataLen = reader.ReadUInt16();
            logRoot.Metadata = reader.ReadBytes(metadataLen);
            return logRoot;
        }

        private readonly TrillianLog.TrillianLogClient client;
    }
}
