using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace JCryptology.JEncryption
{
    public class Elec2WayEnc
    {
        public static string[] Encrypt(int[] array)
        {
            List<string> result = new List<string>();

            for (int j = 0; j < array.Length; j += 2)
            {
                int b = j + 1;

                int u = array[j];
                int i = (array.Length > b) ? array[b] : 1;

                int p = u * i;
                double r = (double)u / (double)i;

                result.Add(string.Format("{0}:{1}", r, p));
            }

            return result.ToArray();
        }

        public static string EncryptToString(int[] array)
        {
            string result = "";

            string[] temparray = Encrypt(array);
            foreach (string num in temparray)
            {
                int len = num.Length;
                int len1 = len.ToString().Length;

                result += string.Format("{0}{1}{2}", len1, len, num);
            }

            return result;
        }

        public static string EncryptFromString(string str)
        {
            List<int> result = new List<int>();

            foreach (char chr in str)
            {
                result.Add(chr);
            }

            return EncryptToString(result.ToArray());
        }

        public static int[] Decrypt(string[] array)
        {
            List<int> result = new List<int>();

            foreach (string num in array)
            {
                double r = double.Parse(num.Split(':')[0]);
                int p = int.Parse(num.Split(':')[1]);

                int u = int.Parse(Math.Sqrt(p * r).ToString());
                int i = int.Parse((u / r).ToString());

                result.Add(u);

                if (i == 1)
                {
                    continue;
                }

                result.Add(i);
            }

            return result.ToArray();
        }

        public static int[] DecryptFromString(string str)
        {
            List<string> result = new List<string>();

            int i = 0;
            while (i < str.Length)
            {
                int len1 = int.Parse(str[i++].ToString());
                int len = int.Parse(str.Substring(i, len1));
                i += len1;

                string num = str.Substring(i, len);
                i += len;

                result.Add(num);
            }

            return Decrypt(result.ToArray());
        }

        public static string DecryptToString(string str)
        {
            string result = "";

            int[] array = DecryptFromString(str);
            foreach (int chr in array)
            {
                result += (char)chr;
            }

            return result;
        }
    }
}
