using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace HabboEncryption.Utils
{
    public class Randomize
    {
        private static Random rand = new Random();

        public static Random GetRandom
        {
            get
            {
                return rand;
            }
        }

        public static int Next()
        {
            return rand.Next();
        }

        public static int Next(int max)
        {
            return rand.Next(max);
        }

        public static int Next(int min, int max)
        {
            return rand.Next(min, max);
        }

        public static double NextDouble()
        {
            return rand.NextDouble();
        }

        public static void NextBytes(byte[] toparse)
        {
            rand.NextBytes(toparse);
        }
    }
}
