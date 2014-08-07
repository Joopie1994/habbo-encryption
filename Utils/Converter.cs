using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace HabboEncryption.Utils
{
    public class Converter
    {
        public static string BytesToHexString(byte[] bytes)
        {
            string hexstring = BitConverter.ToString(bytes);
            return hexstring.Replace("-", "");
        }

        public static byte[] HexStringToBytes(string hexstring)
        {
            int NumberChars = hexstring.Length;
            byte[] bytes = new byte[NumberChars / 2];
            for (int i = 0; i < NumberChars; i += 2)
            {
                bytes[i / 2] = Convert.ToByte(hexstring.Substring(i, 2), 16);
            }
            return bytes;
        }
    }
}
