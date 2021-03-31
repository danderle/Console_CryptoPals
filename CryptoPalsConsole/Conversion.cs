using System;
using System.Collections.Generic;
using System.Text;

namespace CryptoPalsConsole
{
    static class Conversion
    {
        public static string BytesToAsciiString(byte[] data)
        {
            return Encoding.ASCII.GetString(data);
        }

        public static string BytesToBase64String(byte[] data)
        {
            return Convert.ToBase64String(data);
        }

        public static string BytesToHexString(byte[] bytes)
        {
            return BitConverter.ToString(bytes).Replace("-", "").ToLower();
        }

        public static byte[] AsciiToBytes(string text)
        {
            return Encoding.ASCII.GetBytes(text);
        }

        public static byte[] Base64StringToBytes(string base64String)
        {
            return Convert.FromBase64String(base64String);
        }

        public static byte[] HexStringToBytes(string hexString)
        {
            if (hexString.Length == 0 || hexString.Length % 2 != 0)
                return null;

            var result = new List<byte>();
            for(int i = 0; i < hexString.Length; i+=2)
            {
                var sub = hexString.Substring(i, 2);
                byte b = Convert.ToByte(sub, 16);
                result.Add(b);
            }
            return result.ToArray();
        }

    }
}
