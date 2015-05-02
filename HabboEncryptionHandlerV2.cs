using HabboEncryption.CodeProject.Utils;
using HabboEncryption.Crypto.KeyExchange;
using HabboEncryption.Hurlant.Crypto.Rsa;
using HabboEncryption.Keys;
using HabboEncryption.Utils;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace HabboEncryption
{
    public class HabboEncryptionHandlerV2
    {
        public static RsaKey Rsa;
        public static DiffieHellman DiffieHellman;

        public static void Initialize(RsaKeyHolder keys)
        {
            Rsa = RsaKey.ParsePrivateKey(keys.N, keys.E, keys.D);
            DiffieHellman = new DiffieHellman();
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
            string key = DiffieHellman.Prime.ToString(10);
            return GetRsaStringEncrypted(key);
        }

        public static string GetRsaDiffieHellmanGeneratorKey()
        {
            string key = DiffieHellman.Generator.ToString(10);
            return GetRsaStringEncrypted(key);
        }

        public static string GetRsaDiffieHellmanPublicKey()
        {
            string key = DiffieHellman.PublicKey.ToString(10);
            return GetRsaStringEncrypted(key);
        }

        public static BigInteger CalculateDiffieHellmanSharedKey(string publicKey)
        {
            try
            {
                byte[] cbytes = Converter.HexStringToBytes(publicKey);
                byte[] publicKeyBytes = Rsa.Decrypt(cbytes);
                string publicKeyString = Encoding.Default.GetString(publicKeyBytes);
                return DiffieHellman.CalculateSharedKey(new BigInteger(publicKeyString, 10));
            }
            catch
            {
                return 0;
            }
        }
    }
}
