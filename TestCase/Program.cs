using System;
using System.Linq;
using System.Text;
using System.Numerics;
using System.Security.Cryptography;
using HabboEncryption.Security.Cryptography;
using HabboEncryption.Utils;

namespace TestCase
{
    class Program
    {
        public static bool CONSOLE_OUTPUT = true;
        public static int AMOUNT_TESTS = 1000;
        public static int DH_BIT_LENGTH = 128;
        public static int RSA_BIT_LENGTH = 1024;

        private static BigInteger _modules = BigInteger.Parse("0086851DD364D5C5CECE3C883171CC6DDC5760779B992482BD1E20DD296888DF91B33B936A7B93F06D29E8870F703A216257DEC7C81DE0058FEA4CC5116F75E6EFC4E9113513E45357DC3FD43D4EFAB5963EF178B78BD61E81A14C603B24C8BCCE0A12230B320045498EDC29282FF0603BC7B7DAE8FC1B05B52B2F301A9DC783B7", System.Globalization.NumberStyles.HexNumber);

        private static BigInteger _d = BigInteger.Parse("0059AE13E243392E89DED305764BDD9E92E4EAFA67BB6DAC7E1415E8C645B0950BCCD26246FD0D4AF37145AF5FA026C0EC3A94853013EAAE5FF1888360F4F9449EE023762EC195DFF3F30CA0B08B8C947E3859877B5D7DCED5C8715C58B53740B84E11FBC71349A27C31745FCEFEEEA57CFF291099205E230E0C7C27E8E1C0512B", System.Globalization.NumberStyles.HexNumber);

        private static BigInteger _exponent = 3;

        public static void Main(string[] args)
        {
            RSACParameters rsaParameters = new RSACParameters(_d, _modules, _exponent);
            rsaParameters.ToXmlFile(@"rsa.keys");

            for (int i = 0; i < AMOUNT_TESTS; i++)
            {
                Console.WriteLine("Performing test: {0}", i);

                TestHabboEncryption(CONSOLE_OUTPUT, DH_BIT_LENGTH, RSA_BIT_LENGTH);
            }

            Console.WriteLine("Test case finished!");
            Console.ReadLine();
        }

        private static void TestHabboEncryption(bool consoleOutput, int dhBitLength, int rsaBitLength)
        {
            RSACrypto serverRsa = new RSACrypto(RSACParameters.FromXmlFile(@"rsa.keys"));
            DiffieHellman serverDh = DiffieHellman.CreateInstance(dhBitLength);

            string serverDhPrimeRsa = signDiffieHellmanKeys(serverDh.P, serverRsa);
            string serverDhGenRsa = signDiffieHellmanKeys(serverDh.G, serverRsa);

            RSACrypto clientRsa = new RSACrypto(new RSACParameters(_modules, _exponent));

            BigInteger clientDhPrime = verifyDiffieHellmanKeys(serverDhPrimeRsa, clientRsa);
            BigInteger clientDhGen = verifyDiffieHellmanKeys(serverDhGenRsa, clientRsa);

            DiffieHellman clientDh = new DiffieHellman(dhBitLength, clientDhPrime, clientDhGen);

            if (!clientDh.P.Equals(serverDh.P))
            {
                throw new Exception("HabboEncryption test FAILED, P keys are not equal!");
            }

            if (!clientDh.G.Equals(serverDh.G))
            {
                throw new Exception("HabboEncryption test FAILED, G keys are not equal!");
            }

            string serverDhPublicRsa = signDiffieHellmanKeys(serverDh.PublicKey, serverRsa);
            string clientDhPublicRsa = encryptDiffieHellmanKeys(clientDh.PublicKey, clientRsa);

            BigInteger serverDhClientPublic = decryptDiffieHellmanKeys(clientDhPublicRsa, serverRsa);
            BigInteger clientDhServerPublic = verifyDiffieHellmanKeys(serverDhPublicRsa, clientRsa);

            if (!clientDhServerPublic.Equals(serverDh.PublicKey))
            {
                throw new Exception("HabboEncryption test FAILED, server -> client public keys are not equal!");
            }

            if (!serverDhClientPublic.Equals(clientDh.PublicKey))
            {
                throw new Exception("HabboEncryption test FAILED, server <- client public keys are not equal!");
            }

            BigInteger serverDhShared = serverDh.CalculateSharedKey(serverDhClientPublic);
            BigInteger clientDhShared = clientDh.CalculateSharedKey(clientDhServerPublic);

            if (!serverDhShared.Equals(clientDhShared))
            {
                throw new Exception("HabboEncryption test FAILED, shared keys are not equal!");
            }
        }

        private static byte[] convertKeyToBytes(BigInteger key)
        {
            string sKey = key.ToString();
            byte[] bKey = Encoding.Default.GetBytes(sKey);

            return bKey;
        }

        private static BigInteger convertBytesToKey(byte[] bKey)
        {
            string sKey = Encoding.Default.GetString(bKey);
            BigInteger key = BigInteger.Parse(sKey);

            return key;
        }

        private static string signDiffieHellmanKeys(BigInteger key, RSACrypto rsa)
        {
            byte[] sKeyBytes = convertKeyToBytes(key);
            byte[] sKeyRsaBytes = rsa.Encrypt(sKeyBytes, true);
            string sKeyRsa = Converter.BytesToHexString(sKeyRsaBytes);

            return sKeyRsa;
        }

        private static string encryptDiffieHellmanKeys(BigInteger key, RSACrypto rsa)
        {
            byte[] sKeyBytes = convertKeyToBytes(key);
            byte[] sKeyRsaBytes = rsa.Encrypt(sKeyBytes);
            string sKeyRsa = Converter.BytesToHexString(sKeyRsaBytes);

            return sKeyRsa;
        }

        private static BigInteger verifyDiffieHellmanKeys(string cKeyRsa, RSACrypto rsa)
        {
            byte[] cKeyRsaBytes = Converter.HexStringToBytes(cKeyRsa);
            byte[] cKeyBytes = rsa.Decrypt(cKeyRsaBytes);
            BigInteger key = convertBytesToKey(cKeyBytes);

            return key;
        }

        private static BigInteger decryptDiffieHellmanKeys(string cKeyRsa, RSACrypto rsa)
        {
            byte[] cKeyRsaBytes = Converter.HexStringToBytes(cKeyRsa);
            byte[] cKeyBytes = rsa.Decrypt(cKeyRsaBytes, true);
            BigInteger key = convertBytesToKey(cKeyBytes);

            return key;
        }
    }
}
