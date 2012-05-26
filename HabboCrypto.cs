using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

using JCryptology.Utils;
using JCryptology.Utils.Encryption;

namespace JCryptology
{
    public class HabboCrypto
    {
        private DiffieHellman DH;

        private RSA RSA;

        private RC4 RC4;

        public Boolean Initialized { get; private set; }

        public BigInteger GetPrime
        {
            get
            {
                return this.DH.Prime;
            }
        }

        public BigInteger GetGenerator
        {
            get
            {
                return this.DH.Generator;
            }
        }

        public BigInteger GetPublicKey
        {
            get
            {
                return this.DH.PublicKey;
            }
        }

        public HabboCrypto(BigInteger n, BigInteger e, BigInteger d)
        {
            this.DH = new DiffieHellman(200);

            this.RSA = new RSA(n, e, d, 0, 0, 0, 0, 0);

            this.RC4 = new RC4();

            this.Initialized = false;
        }

        public Boolean InitializeRC4(string ctext)
        {
            try
            {
                string publickey = this.RSA.Decrypt(ctext);

                this.DH.GenerateSharedKey(publickey.Replace(((char)0).ToString(), ""));

                this.RC4.Init(this.DH.SharedKey.getBytes());

                this.Initialized = true;

                return true;
            }
            catch
            {
                return false;
            }
        }

        public byte[] Parse(byte[] toparse)
        {
            return this.RC4.Parse(toparse);
        }
    }
}
