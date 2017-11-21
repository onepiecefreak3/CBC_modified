using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace CBC
{
    public class Program
    {
        static Dictionary<byte, char> encoding = new Dictionary<byte, char>
        {
            [0] = 'a',
            [1] = 'b',
            [2] = 'c',
            [3] = 'd',
            [4] = 'e',
            [5] = 'f',
            [6] = 'g',
            [7] = 'h',
            [8] = 'i',
            [9] = 'j',
            [10] = 'k',
            [11] = 'l',
            [12] = 'm',
            [13] = 'n',
            [14] = 'o',
            [15] = 'p',
            [16] = 'q',
            [17] = 'r',
            [18] = 's',
            [19] = 't',
            [20] = 'u',
            [21] = 'v',
            [22] = 'w',
            [23] = 'x',
            [24] = 'y',
            [25] = 'z',
            [26] = 'A',
            [27] = 'B',
            [28] = 'C',
            [29] = 'D',
            [30] = 'E',
            [31] = 'F',
            [32] = 'G',
            [33] = 'H',
            [34] = 'I',
            [35] = 'J',
            [36] = 'K',
            [37] = 'L',
            [38] = 'M',
            [39] = 'N',
            [40] = 'O',
            [41] = 'P',
            [42] = 'Q',
            [43] = 'R',
            [44] = 'S',
            [45] = 'T',
            [46] = 'U',
            [47] = 'V',
            [48] = 'W',
            [49] = 'X',
            [50] = 'Y',
            [51] = 'Z',
            [52] = '0',
            [53] = '1',
            [54] = '2',
            [55] = '3',
            [56] = '4',
            [57] = '5',
            [58] = '6',
            [59] = '7',
            [60] = '8',
            [61] = '9',
            [62] = ' ',
            [63] = '.'
        };

        static void Main(string[] args)
        {
            byte[] iv = new byte[] { 22 };
            byte[] key = new byte[] { 42 };
            string textToEncode = "Pinguine sind knuffige Tiere.";

            Console.WriteLine(textToEncode);

            var enc = Encrypt(textToEncode, iv, key);
            Console.WriteLine(enc);

            var dec = Decrypt(enc, iv, key);
            Console.WriteLine(dec);
        }

        static string Encrypt(string textToEncode, byte[] iv, byte[] key)
        {
            byte[] GetBytes(string s) => s.Select(c => encoding.Where(e => e.Value == c).ToArray()[0].Key).ToArray();
            string GetString(byte[] ba) => ba.Aggregate("", (s, b) => s + encoding[b]);
            byte[] MakeRange(byte[] ba) => ba.Select(b => (byte)(b % encoding.Count())).ToArray();

            byte[] textInByte = GetBytes(textToEncode);
            List<byte> result = new List<byte>();

            //loop through input text until end, block is key.Length big
            for (int i = 0; i < textInByte.Length; i += key.Length)
            {
                //Get Block of bytes with length of key
                byte[] block = new byte[key.Length];
                Array.Copy(textInByte, i, block, 0, key.Length);

                //XOR block
                var ciphered = MakeRange(block.Select((b, index) => (byte)(b ^ iv[index] ^ key[index])).ToArray());

                //set ciphered block as new iv
                iv = ciphered;

                //add ciphered block to result
                result.AddRange(ciphered);
            }

            //cut maybe overflowing stuff in result
            byte[] cutRes = new byte[textToEncode.Length];
            Array.Copy(result.ToArray(), 0, cutRes, 0, textToEncode.Length);

            //convert encrypted byte[] to string
            string resultInText = GetString(cutRes.ToArray());

            return resultInText;
        }

        static string Decrypt(string textToDecode, byte[] iv, byte[] key)
        {
            byte[] GetBytes(string s) => s.Select(c => encoding.Where(e => e.Value == c).ToArray()[0].Key).ToArray();
            string GetString(byte[] ba) => ba.Aggregate("", (s, b) => s + encoding[b]);
            byte[] MakeRange(byte[] ba) => ba.Select(b => (byte)(b % encoding.Count())).ToArray();

            byte[] textInByte = GetBytes(textToDecode);
            byte[] lastUseIV = iv;
            List<byte> result = new List<byte>();

            //loop through input text until end, block is key.Length big
            for (int i = textInByte.Length - 1; i >= 0; i--)
            {
                //Set IV to use
                iv = (i != 0) ? new byte[] { textInByte[i - 1] } : lastUseIV;

                //XOR block
                var deciphered = MakeRange(new byte[] { (byte)(textInByte[i] ^ key[0] ^ iv[0]) });

                //set ciphered block as new iv
                iv = deciphered;

                //add ciphered block to result
                result.AddRange(deciphered);
            }

            //cut maybe overflowing stuff in result
            byte[] cutRes = new byte[textToDecode.Length];
            Array.Copy(result.ToArray(), 0, cutRes, 0, textToDecode.Length);

            //convert encrypted byte[] to string
            string resultInText = GetString(cutRes.Reverse().ToArray());

            return resultInText;
        }
    }
}
