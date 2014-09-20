using HabboEncryption.Utils;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Numerics;
using System.Globalization;

namespace HabboEncryption.Crypto.KeyExchange
{
    public class DiffieHellman
    {
        public readonly int BITLENGTH = 32;

        public BigInteger Prime { get; private set; }
        public BigInteger Generator { get; private set; }

        private BigInteger PrivateKey;
        public BigInteger PublicKey { get; private set; }

        public DiffieHellman(BigInteger prime, BigInteger generator)
        {
            this.Prime = prime;
            this.Generator = generator;
            this.BITLENGTH = this.Prime.GetBitCount();

            this.Initialize();
        }

        private void Initialize()
        {
            this.PublicKey = 0;

            byte[] bytes = new byte[this.BITLENGTH / 8];
            Randomizer.NextBytes(bytes);
            this.PrivateKey = new BigInteger(bytes);

            if (this.Generator > this.Prime)
            {
                BigInteger temp = this.Prime;
                this.Prime = this.Generator;
                this.Generator = temp;
            }

            this.PublicKey = BigInteger.ModPow(this.Generator, this.PrivateKey, this.Prime);
        }

        public static DiffieHellman ParsePublicKey(string prime, string generator)
        {
            return new DiffieHellman(BigInteger.Parse(prime, NumberStyles.AllowHexSpecifier), BigInteger.Parse(generator, NumberStyles.AllowHexSpecifier));
        }

        public BigInteger CalculateSharedKey(BigInteger m)
        {
            return BigInteger.ModPow(m, this.PrivateKey, this.Prime);
        }
    }
}
