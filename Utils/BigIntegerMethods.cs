using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Numerics;

namespace HabboEncryption.Utils
{
    public static class BigIntegerMethods
    {
        public static int GetBitCount(this BigInteger number)
        {
            byte[] data = number.ToByteArray();
            uint value = data[data.Length - 1];
            uint mask = 0x80000000;
            int bits = 32;

            while (bits > 0 && (value & mask) == 0)
            {
                bits--;
                mask >>= 1;
            }
            bits += ((data.Length - 1) << 5);

            return bits;
        }
    }
}
