using HabboEncryption.CodeProject.Utils;
using HabboEncryption.Crypto.KeyExchange;
using HabboEncryption.Hurlant.Crypto.Prng;
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
    public class HabboEncryptionHandlerV1
    {
        private DiffieHellman DiffieHellman;

        private RsaKey Rsa;

        private ARC4 Rc4;

        public Boolean Initialized { get; private set; }

        public BigInteger GetPrime
        {
            get
            {
                return this.DiffieHellman.Prime;
            }
        }

        public BigInteger GetGenerator
        {
            get
            {
                return this.DiffieHellman.Generator;
            }
        }

        public BigInteger GetPublicKey
        {
            get
            {
                return this.DiffieHellman.PublicKey;
            }
        }

        public HabboEncryptionHandlerV1(RsaKeyHolder keys)
        {
            this.DiffieHellman = new DiffieHellman();

            this.Rsa = RsaKey.ParsePrivateKey(keys.N, keys.E, keys.D);

            this.Rc4 = new ARC4();

            this.Initialized = false;
        }

        public Boolean InitializeRC4(string ctext)
        {
            try
            {
                byte[] cbytes = Converter.HexStringToBytes(ctext);
                byte[] publicKeyBytes = this.Rsa.Verify(cbytes);
                string publicKeyString = Encoding.Default.GetString(publicKeyBytes);

                BigInteger sharedKey = this.DiffieHellman.CalculateSharedKey(new BigInteger(publicKeyString, 10));

                this.Rc4.Initialize(sharedKey.getBytes());

                this.Initialized = true;

                return true;
            }
            catch
            {
                return false;
            }
        }

        public void Parse(ref byte[] toparse)
        {
            this.Rc4.Decrypt(ref toparse);
        }
    }
}
