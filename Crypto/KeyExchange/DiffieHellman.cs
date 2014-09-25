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
        public int Bits { get; private set; }

        public BigInteger Prime { get; private set; }
        public BigInteger Generator { get; private set; }

        private BigInteger PrivateKey;
        public BigInteger PublicKey { get; private set; }

        public DiffieHellman(BigInteger prime, BigInteger generator)
        {
            this.Bits = 32;
            this.Prime = prime;
            this.Generator = generator;

            this.Initialize();
        }

        public DiffieHellman(int bits, BigInteger prime, BigInteger generator)
        {
            this.Bits = bits;
            this.Prime = prime;
            this.Generator = generator;

            this.Initialize();
        }

        private void Initialize()
        {
            this.PublicKey = 0;

            byte[] bytes = new byte[this.Bits / 8];
            Randomizer.NextBytes(bytes);
            this.PrivateKey = BigInteger.Abs(new BigInteger(bytes));

            this.PublicKey = BigInteger.ModPow(this.Generator, this.PrivateKey, this.Prime);
        }

        public static DiffieHellman ParsePublicKey(string prime, string generator)
        {
            return new DiffieHellman(BigInteger.Parse(prime), BigInteger.Parse(generator));
        }

        public static DiffieHellman ParsePublicKey(int bits, string prime, string generator)
        {
            return new DiffieHellman(bits, BigInteger.Parse(prime), BigInteger.Parse(generator));
        }

        public BigInteger CalculateSharedKey(BigInteger m)
        {
            return BigInteger.ModPow(m, this.PrivateKey, this.Prime);
        }
    }
}