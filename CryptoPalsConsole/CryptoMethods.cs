using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace CryptoPalsConsole
{
    static class CryptoMethods
    {
        public static byte Xor(byte a, byte b)
        {
            return Convert.ToByte(a ^ b);
        }

        public static byte[] Xor(byte[] a, byte[] b)
        {
            if (a.Length != b.Length)
                return null;
            var result = new List<byte>();
            for( int index = 0; index < a.Length; index++)
            {
                result.Add(Xor(a[index], b[index]));
            }

            return result.ToArray();
        }

        public static KeyValuePair<int, string> DetectSingleByteXorDecryption(byte[] encryption)
        {
            int maxLetters = 0;
            var result = new KeyValuePair<int, string>(0,"");
            for(int key = 0; key < 256; key++)
            {
                var decryption = new List<byte>();
                foreach(var bite in encryption)
                {
                    decryption.Add(Xor(Convert.ToByte(key), bite));
                }
                string message = Conversion.BytesToAsciiString(decryption.ToArray());
                int letterCount = 0;
                foreach(var c in message)
                {
                    if(Char.IsWhiteSpace(c) || Char.IsLetter(c))
                    {
                        letterCount++;
                    }
                    else
                    {
                        letterCount--;
                    }
                }
                if(maxLetters < letterCount)
                {
                    maxLetters = letterCount;
                    result = new KeyValuePair<int, string>(key, message);
                }
            }
            return result;
        }

        public static byte[] EncryptRepeatingXor(byte[] data, byte[] key)
        {
            var result = new List<byte>();
            for(int index = 0; index < data.Length; index++)
            {
                result.Add(Xor(data[index], key[index % key.Length]));
            }
            return result.ToArray();
        }

        public static int HammingDistance(byte a, byte b)
        {
            byte result = Convert.ToByte(a ^ b);
            int distance = Convert.ToString(result,2).Count(c => c == '1');
            return distance;
        }

        public static int HammingDistance(byte[] a, byte[] b)
        {
            if (a.Length != b.Length)
                return 0;
            int totalDistance = 0;
            for(int index = 0; index < a.Length; index++)
            {
                totalDistance += HammingDistance(a[index], b[index]);
            }
            return totalDistance;
        }

        public static float NormalizedHammingDistance(byte[][] chunks1, byte[][] chunks2, int keySize)
        {
            float score = 0;
            for (int chunkIndex = 0; chunkIndex < chunks1.Length; chunkIndex++)
            {
                if (chunkIndex < chunks2.Length)
                {
                    int distance = HammingDistance(chunks1[chunkIndex], chunks2[chunkIndex]);
                    float normalized = (float)distance / (float)keySize;
                    score += normalized;
                }
            }
            score /= chunks1.Length;
            return score;
        }

        public static int[] GetPossibleXorKeySize(int smallestKey, int largestKey, int numberOfKeys, byte[] data)
        {
            var keys = new List<KeyValuePair<int, float>>();
            for(int keySize = smallestKey; keySize < largestKey; keySize++)
            {
                var chunks1 = GetKeySizeChunks(keySize, 0, data);
                var chunks2 = GetKeySizeChunks(keySize, keySize, data);

                float score = NormalizedHammingDistance(chunks1.ToArray(), chunks2.ToArray(), keySize);
                var anotherKey = new KeyValuePair<int, float>(keySize, score);
                SaveBestScoreKeyLength(keys, numberOfKeys, anotherKey);
            }
            var keySizes = new int[keys.Count];
            int index = 0;
            foreach(var key in keys)
            {
                keySizes[index] = key.Key;
                index++;
            }
            return keySizes;
        }

        public static byte[][] BreakIntoBlocks(byte[] data, int blockSize)
        {
            var blocks = new List<byte[]>();
            var block = new List<byte>();
            for (int index = 0; index < data.Length; index++)
            {
                block.Add(data[index]);
                if(block.Count == blockSize)
                {
                    blocks.Add(block.ToArray());
                    block = new List<byte>();
                }
            }
            return blocks.ToArray();
        }

        public static byte[] DecryptAes(byte[] cipher, byte[] key, CipherMode cipherMode)
        {
            // Create an Aes object
            // with the specified key and IV.
            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.Key = key; ;
                aesAlg.Mode = CipherMode.ECB;
                aesAlg.Padding = PaddingMode.Zeros;

                // Create a decryptor to perform the stream transform.
                ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);

                // Create the streams used for decryption.
                using (MemoryStream msDecrypt = new MemoryStream(cipher))
                {
                    using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                    {
                        int b = csDecrypt.ReadByte();
                        var bytes = new List<byte>();
                        while(b != -1)
                        {
                            bytes.Add(Convert.ToByte(b));
                            b = csDecrypt.ReadByte();
                        }
                        return bytes.ToArray();
                    }
                }
            }
        }
        #region Helper Methods

        private static void SaveBestScoreKeyLength(List<KeyValuePair<int, float>> keys, int numberOfKeys, KeyValuePair<int, float> anotherKey)
        {
            if (keys.Count < numberOfKeys)
            {
                keys.Add(anotherKey);
            }
            else
            {
                foreach (var key in keys)
                {
                    if (anotherKey.Value < key.Value)
                    {
                        keys.Remove(key);
                        keys.Add(anotherKey);
                        break;
                    }
                }
            }
        }

        public static byte[][] TransposeBlocks(byte[][] keySizeBlocks)
        {
            var transposedBlocks = new List<byte[]>();
            
            for(int index = 0; index < keySizeBlocks[0].Length; index++)
            {
                var transposed = new List<byte>();
                foreach (var block in keySizeBlocks)
                {
                    transposed.Add(block[index]);
                }
                transposedBlocks.Add(transposed.ToArray());
            }
            return transposedBlocks.ToArray();
        }

        private static List<byte[]> GetKeySizeChunks(int keySize, int start, byte[] data)
        {
            var chunks = new List<byte[]>();
            for (int i = start; i + keySize < data.Length; i += (keySize * 2))
            {
                var chunk = new byte[keySize];
                Array.Copy(data, i, chunk, 0, keySize);
                if (chunk.Length == keySize)
                {
                    chunks.Add(chunk);
                }
            }
            return chunks;
        }

        #endregion

    }
}
