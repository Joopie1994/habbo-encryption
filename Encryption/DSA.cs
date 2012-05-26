using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Security.Cryptography;

using JCryptology.Utils;

namespace JCryptology.Encryption
{
    public class DSA
    {
        public readonly int BITLENGTH = 64;
        private static SHA256Managed SHA256 = new SHA256Managed();

        public enum KeyLengthPairs
        {
            Small,
            Normal,
            Medium,
            High
        }

        public KeyLengthPairs KeyLengthPair { get; private set; }

        //public keys
        public BigInteger q { get; private set; } //public
        public BigInteger p { get; private set; } //public
        public BigInteger g { get; private set; } //public

        //per-user keys
        public BigInteger x { get; private set; }
        public BigInteger y { get; private set; } //public

        public DSA(KeyLengthPairs t)
        {
            this.KeyLengthPair = t;

            int[] KeyLengthPairs = GetKeyLengthPairs(this.KeyLengthPair);

            this.q = BigInteger.genPseudoPrime(KeyLengthPairs[1], 10, Randomize.GetRandom);
            this.p = BigInteger.genPseudoPrime(KeyLengthPairs[0], 10, Randomize.GetRandom);
            this.g = new BigInteger(2).modPow((this.p - 1) / this.q, this.p);

            this.GenerateUserKeys();
        }

        public DSA(KeyLengthPairs t, BigInteger q, BigInteger p, BigInteger g)
        {
            this.KeyLengthPair = t;
            
            this.q = q;
            this.p = p;
            this.g = g;

            this.GenerateUserKeys();
        }

        private void GenerateUserKeys()
        {
            this.x = BigInteger.genPseudoPrime(BITLENGTH, 10, Randomize.GetRandom);
            this.y = this.g.modPow(this.x, this.p);
        }

        public void Signing(int m)
        {
            BigInteger k = new BigInteger(GenerateRandomHexString(Randomize.Next(1, BITLENGTH)), 16);
            
            BigInteger r = 0;
            while (r == 0)
            {
                r = this.g.modPow(k, this.p) % this.q;
            }

            BigInteger s = 0;
            while (s == 0)
            {
                BigInteger sum = k;
            }

        }


        public static int[] GetKeyLengthPairs(KeyLengthPairs t)
        {
            if (t != KeyLengthPairs.Small)
            {
                Console.WriteLine("Warning: Key pairs takes more time to generate, recommened to choose `Small`!");
                
                Console.WriteLine("\r\nPress any key to continue...");
                Console.ReadKey();
            }

            switch (t)
            {
                default:
                case KeyLengthPairs.Small: return new int[2] { 1024, 160 };
                case KeyLengthPairs.Normal: return new int[2] { 2048, 224 };
                case KeyLengthPairs.Medium: return new int[2] { 2048, 256 };
                case KeyLengthPairs.High: return new int[2] { 3072, 256 };
            }
        }

        private static string GetSHA256Hash(string input)
        {
            byte[] inputbytes = Encoding.Default.GetBytes(input);
            byte[] hash = SHA256.ComputeHash(inputbytes);

            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < hash.Length; i++)
            {
                sb.Append(hash[i].ToString("X2"));
            }

            return sb.ToString();
        }

        #region RandomHexString
        public static string GenerateRandomHexString(int len)
        {
            byte[] bytes = new byte[len / 2];
            Randomize.NextBytes(bytes);

            BigInteger Result = new BigInteger(bytes);

            if (Result < 0)
            {
                Result *= -1;
            }

            return Result.ToString(16);
        }
        #endregion
    }
}
