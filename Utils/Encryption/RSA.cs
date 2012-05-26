using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

using JCryptology.Utils;

namespace JCryptology.Utils.Encryption
{
    public class RSA
    {
        #region Variables
        public BigInteger n { get; private set; }
        public BigInteger e { get; private set; }
        public BigInteger d { get; private set; }
        public BigInteger p { get; private set; }
        public BigInteger q { get; private set; }
        public BigInteger dmp1 { get; private set; }
        public BigInteger dmq1 { get; private set; }
        public BigInteger coeff { get; private set; }

        protected Boolean canDecrypt { get; private set; }
        protected Boolean canEncrypt { get; private set; }
        #endregion

        #region Constructor
        public RSA(BigInteger n, BigInteger e, BigInteger d, BigInteger p, BigInteger q, BigInteger dmp1, BigInteger dmq1, BigInteger coeff)
        {
            this.n = n;
            this.e = e;
            this.d = d;
            this.p = p;
            this.q = q;
            this.dmp1 = dmp1;
            this.dmq1 = dmq1;
            this.coeff = coeff;

            this.canEncrypt = this.n != 0 && this.e != 0;
            this.canDecrypt = this.canEncrypt && this.d != 0;
        }

        public RSA(int b, BigInteger e)
        {
            this.e = e;

            int qs = b >> 1;
            
            while (true)
            {
                while (true)
                {
                    this.p = BigInteger.genPseudoPrime(b - qs, 1, Randomize.GetRandom);

                    if ((this.p - 1).gcd(this.e) == 1 && this.p.isProbablePrime(10))
                    {
                        break;
                    }
                }

                while (true)
                {
                    this.q = BigInteger.genPseudoPrime(qs, 1, Randomize.GetRandom);

                    if ((this.q - 1).gcd(this.e) == 1 && this.p.isProbablePrime(10))
                    {
                        break;
                    }
                }

                if (this.p < this.q)
                {
                    BigInteger t = this.p;
                    this.p = this.q;
                    this.q = t;
                }

                BigInteger phi = (this.p - 1) * (this.q - 1);
                if (phi.gcd(this.e) == 1)
                {
                    this.n = this.p * this.q;
                    this.d = this.e.modInverse(phi);
                    this.dmp1 = this.d % (this.p - 1);
                    this.dmq1 = this.d % (this.q - 1);
                    this.coeff = this.q.modInverse(this.p);
                    break;
                }
            }

            this.canEncrypt = this.n != 0 && this.e != 0;
            this.canDecrypt = this.canEncrypt && this.d != 0;
        }

        public RSA(BigInteger e, BigInteger p, BigInteger q)
        {
            this.e = e;
            this.p = p;
            this.q = q;

            BigInteger phi = (this.p - 1) * (this.q - 1);
            if (phi.gcd(this.e) == 1)
            {
                this.n = this.p * this.q;
                this.d = this.e.modInverse(phi);
                this.dmp1 = this.d % (this.p - 1);
                this.dmq1 = this.d % (this.q - 1);
                this.coeff = this.q.modInverse(this.p);
            }

            this.canEncrypt = this.n != 0 && this.e != 0;
            this.canDecrypt = this.canEncrypt && this.d != 0;
        }
        #endregion

        private int GetBlockSize()
        {
            return (this.n.bitCount() + 7) / 8;
        }

        public BigInteger DoPublic(BigInteger x)
        {
            if (this.canEncrypt)
            {
                return x.modPow(this.e, this.n);
            }

            return 0;
        }

        public string Encrypt(string text)
        {
            if (text.Length > this.GetBlockSize() - 11)
            {
                Console.WriteLine("RSA Encrypt: Message is to big!");
            }

            BigInteger m = new BigInteger(this.pkcs1pad2(Encoding.GetEncoding("iso-8859-1").GetBytes(text), this.GetBlockSize()));
            if (m == 0)
            {
                return null;
            }

            BigInteger c = this.DoPublic(m);
            if (c == 0)
            {
                return null;
            }

            string result = c.ToString(16);
            if ((result.Length & 1) == 0)
            {
                return result;
            }

            return "0" + result;
        }

        private byte[] pkcs1pad2(byte[] data, int n)
        {
            byte[] bytes = new byte[n];
            int i = data.Length - 1;
            while (i >= 0 && n > 11)
            {
                bytes[--n] = data[i--];
            }
            bytes[--n] = 0;

            while (n > 2)
            {
                bytes[--n] = 0x01;
            }

            bytes[--n] = 0x2;
            bytes[--n] = 0;

            return bytes;
        }

        public BigInteger DoPrivate(BigInteger x)
        {
            if (this.canDecrypt)
            {
                return x.modPow(this.d, this.n);
            }

            return 0;
        }

        public string Decrypt(string ctext)
        {
            BigInteger c = new BigInteger(ctext, 16);
            BigInteger m = this.DoPrivate(c);
            if (m == 0)
            {
                return null;
            }

            byte[] bytes = this.pkcs1unpad2(m, this.GetBlockSize());

            if (bytes == null)
            {
                return null;
            }

            return Encoding.GetEncoding("iso-8859-1").GetString(bytes);
        }

        private byte[] pkcs1unpad2(BigInteger m, int b)
        {
            byte[] bytes = m.getBytes();

            int i = 0;
            while (i < bytes.Length && bytes[i] == 0) ++i;

            if (bytes.Length - i != (b - 1) || bytes[i] != 0x2)
            {
                return null;
            }

            while (bytes[i] != 0)
            {
                if (++i >= bytes.Length)
                {
                    return null;
                }
            }

            byte[] result = new byte[bytes.Length - i + 1];
            int p = 0;
            while (++i < bytes.Length)
            {
                result[p++] = bytes[i];
            }

            return result;
        }
    }
}
