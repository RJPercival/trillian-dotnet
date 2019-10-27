using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace Trillian
{
    public class Verifier
    {
        public static bool VerifyConsistencyProof(LogRootV1 first, LogRootV1 second, Trillian.Proof proof)
        {
            if (first.TreeSize == second.TreeSize)
            {
                if (proof.Hashes.Count > 0)
                    throw new ArgumentException("first.TreeSize == second.TreeSize but proof.Hashes.Count > 0");
                return first.RootHash.Equals(second.RootHash);
            }
            if (first.TreeSize < second.TreeSize)
                throw new ArgumentException("first.TreeSize < second.TreeSize");

            using SHA256 hasher = SHA256.Create();

            // 1.  If "first" is an exact power of 2, then prepend "first_hash" to
            //     the "consistency_path" array.
            if (IsPowerOf2(first.TreeSize)) {
                proof.Hashes.Insert(0, Google.Protobuf.ByteString.CopyFrom(first.RootHash));
            }

            // 2.  Set "fn" to "first - 1" and "sn" to "second - 1".
            UInt64 fn = first.TreeSize - 1;
            UInt64 sn = second.TreeSize - 1;

            // 3.  If "LSB(fn)" is set, then right-shift both "fn" and "sn" equally
            //     until "LSB(fn)" is not set.
            while ((fn & 1) == 1)
            {
                fn >>= 1;
                sn >>= 1;
            }

            // 4.  Set both "fr" and "sr" to the first value in the
            //     "consistency_path" array.
            var fr = proof.Hashes[0].ToByteArray();
            var sr = proof.Hashes[0].ToByteArray();

            // 5.  For each subsequent value "c" in the "consistency_path" array:
            foreach (var c in proof.Hashes)
            {
                // If "sn" is 0, stop the iteration and fail the proof verification.
                if (sn == 0)
                    return false;
                // If "LSB(fn)" is set, or if "fn" is equal to "sn", then:
                if ((fn & 1) == 1 || fn == sn)
                {
                    // 1.  Set "fr" to "HASH(0x01 || c || fr)"
                    //     Set "sr" to "HASH(0x01 || c || sr)"
                    MemoryStream memStream = new MemoryStream(1 + c.Length + fr.Length);
                    memStream.WriteByte(0x01);
                    memStream.Write(c.Span);
                    memStream.Write(fr);
                    memStream.Seek(0, SeekOrigin.Begin);
                    fr = hasher.ComputeHash(memStream);

                    memStream.Seek(1 + c.Length, SeekOrigin.Begin);
                    memStream.Write(sr);
                    memStream.Seek(0, SeekOrigin.Begin);
                    sr = hasher.ComputeHash(memStream);

                    // 2. If "LSB(fn)" is not set, then right-shift both "fn" and "sn"
                    //    equally until either "LSB(fn)" is set or "fn" is "0".
                    while ((fn & 1) == 0)
                    {
                        fn >>= 1;
                        sn >>= 1;
                        if (fn == 0)
                            break;
                    }
                }
                else
                {
                    // Otherwise:
                    // 1.Set "sr" to "HASH(0x01 || sr || c)"
                    MemoryStream memStream = new MemoryStream(1 + c.Length + fr.Length);
                    memStream.WriteByte(0x01);
                    memStream.Write(sr);
                    memStream.Write(c.Span);
                    memStream.Seek(0, SeekOrigin.Begin);
                    sr = hasher.ComputeHash(memStream);
                }
                // Finally, right - shift both "fn" and "sn" one time.
                fn >>= 1;
                sn >>= 1;
            }
            // 6.  After completing iterating through the "consistency_path" array
            //     as described above, verify that the "fr" calculated is equal to
            //     the "first_hash" supplied, that the "sr" calculated is equal to
            //     the "second_hash" supplied and that "sn" is 0.
            return fr.Equals(first.RootHash) && sr.Equals(second.RootHash) && sn == 0;
        }

        private static bool IsPowerOf2(UInt64 x)
        {
            return x != 0 && (x & (x - 1)) == 0;
        }
    }
}
