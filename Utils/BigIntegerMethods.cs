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
            return (int)BigInteger.Log(number, 2) + 1;
        }
    }
}
