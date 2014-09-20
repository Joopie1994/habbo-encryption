using HabboEncryption.Crypto.KeyExchange;
using HabboEncryption.Hurlant.Crypto.Rsa;
using HabboEncryption.Keys;
using HabboEncryption.Utils;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Numerics;
using System.Globalization;

namespace HabboEncryption
{
    public class HabboEncryptionHandlerV2
    {
        public static RsaKey Rsa;
        public static DiffieHellman DiffieHellman;

        public static void Initialize(RsaKeyHolder rsaKeys, DiffieHellmanKeyHolder dhKeys)
        {
            Rsa = RsaKey.ParsePrivateKey(rsaKeys.N, rsaKeys.E, rsaKeys.D);
            DiffieHellman = DiffieHellman.ParsePublicKey(dhKeys.Prime, dhKeys.Generator);
        }

        private static string GetRsaStringEncrypted(string message)
        {
            try
            {
                byte[] m = Encoding.Default.GetBytes(message);
                byte[] c = Rsa.Sign(m);

                return Converter.BytesToHexString(c);
            }
            catch
            {
                return "0";
            }
        }

        public static string GetRsaDiffieHellmanPrimeKey()
        {
            string key = DiffieHellman.Prime.ToString("D");
            return GetRsaStringEncrypted(key);
        }

        public static string GetRsaDiffieHellmanGeneratorKey()
        {
            string key = DiffieHellman.Generator.ToString("D");
            return GetRsaStringEncrypted(key);
        }

        public static string GetRsaDiffieHellmanPublicKey()
        {
            string key = DiffieHellman.PublicKey.ToString("D");
            return GetRsaStringEncrypted(key);
        }

        public static BigInteger CalculateDiffieHellmanSharedKey(string publicKey)
        {
            try
            {
                byte[] cbytes = Converter.HexStringToBytes(publicKey);
                byte[] publicKeyBytes = Rsa.Verify(cbytes);
                string publicKeyString = Encoding.Default.GetString(publicKeyBytes);
                return DiffieHellman.CalculateSharedKey(BigInteger.Parse(publicKeyString));
            }
            catch
            {
                return 0;
            }
        }
    }
}
