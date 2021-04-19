using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;

namespace CryptoPalsConsole
{
    static class CryptoMethods
    {
        #region Xor

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


        public static int[] GetPossibleXorKeySize(int smallestKey, int largestKey, int numberOfKeys, byte[] data)
        {
            var keys = new List<KeyValuePair<int, float>>();
            for (int keySize = smallestKey; keySize < largestKey; keySize++)
            {
                var chunks1 = GetKeySizeChunks(keySize, 0, data);
                var chunks2 = GetKeySizeChunks(keySize, keySize, data);

                float score = NormalizedHammingDistance(chunks1.ToArray(), chunks2.ToArray(), keySize);
                var anotherKey = new KeyValuePair<int, float>(keySize, score);
                SaveBestScoreKeyLength(keys, numberOfKeys, anotherKey);
            }
            var keySizes = new int[keys.Count];
            int index = 0;
            foreach (var key in keys)
            {
                keySizes[index] = key.Key;
                index++;
            }
            return keySizes;
        }

        #endregion

        #region Hamming Distance

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

        #endregion

        #region Blocks

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

        public static int NumberOfRepeatedBlocks(byte[] encrypted, out byte[] mostRepeatedBlock)
        {
            var blocks = BreakIntoBlocks(encrypted, 16);
            mostRepeatedBlock = null;
            int mostMatches = 0;
            for (int blockIndex = 0; blockIndex < blocks.Length; blockIndex++)
            {
                int matches = 0;
                for (int othersIndex = 0; othersIndex < blocks.Length; othersIndex++)
                {
                    if (blockIndex != othersIndex)
                    {
                        matches += AreEqual(blocks[blockIndex], blocks[othersIndex]);
                        if (matches > mostMatches)
                        {
                            mostMatches = matches;
                            mostRepeatedBlock = blocks[blockIndex];
                        }
                    }
                }
            }
            return mostMatches;
        }

        #endregion

        #region Aes

        public static byte[] RandomBytes(int length)
        {
            var rand = new Random();
            var bytes = new byte[length];
            rand.NextBytes(bytes);
            return bytes;
        }

        public static CipherMode RandomEncryption(byte[] plain, out byte[] encryption)
        {
            var rand = new Random();
            var numberOfAppendedBytes = rand.Next(5, 11);
            var front = RandomBytes(numberOfAppendedBytes);
            var rear = RandomBytes(numberOfAppendedBytes);
            var mode = rand.Next(0, 2);
            var key = RandomBytes(16);
            var iv = RandomBytes(16);
            var plainBytes = new List<byte>();
            plainBytes.AddRange(front);
            plainBytes.AddRange(plain);
            plainBytes.AddRange(rear);
            var paddedBytes = PKCS7Padding(plainBytes.ToArray(), 16);

            switch(mode)
            {
                case 0:
                    encryption = EncryptAes(paddedBytes, key, CipherMode.ECB, PaddingMode.None);
                    return CipherMode.ECB;
                case 1:
                    encryption = EncryptAesCBC(paddedBytes, key, iv);
                    return CipherMode.CBC;
                default:
                    encryption = null;
                    return CipherMode.CTS;
            }
        }

        public static int AesModeDetection(byte[] encryption)
        {
            return 1;
        }

        public static int GetAesEncryptionBlockSize(byte[] plainBytes, byte[] key, out byte[] encryption)
        {
            int blockSize = 0;
            int encryptionSize = 0;
            var textAddition = string.Empty;
            encryption = null;
            var plain = plainBytes.ToList();
            while (blockSize == 0)
            {
                var textAdditionBytes = Conversion.AsciiToBytes(textAddition);
                plain.AddRange(textAdditionBytes);
                var paddedPlainBytes = PKCS7Padding(plain.ToArray(), 16);
                var encrypt = EncryptAes(paddedPlainBytes, key, CipherMode.ECB, PaddingMode.None);
                if (encryptionSize == 0)
                {
                    encryption = encrypt;
                    encryptionSize = encrypt.Length;
                }
                else if (encryptionSize < encrypt.Length)
                {
                    blockSize = encrypt.Length - encryptionSize;
                }
                textAddition += "A";
            }
            return blockSize;
        }

        #region EBC

        public static byte[] EncryptAes(byte[] plainBytes, byte[] key, CipherMode cipherMode, PaddingMode padding)
        {
            // Create an Aes object
            // with the specified key and IV.
            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.Key = key; ;
                aesAlg.Mode = cipherMode;
                aesAlg.Padding = padding;

                // Create a encryptor to perform the stream transform.
                ICryptoTransform encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);

                // Create the streams used for encryption.
                using (MemoryStream msEncrypt = new MemoryStream(plainBytes))
                {
                    using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Read))
                    {
                        int b = csEncrypt.ReadByte();
                        var bytes = new List<byte>();
                        while (b != -1)
                        {
                            bytes.Add(Convert.ToByte(b));
                            b = csEncrypt.ReadByte();
                        }
                        return bytes.ToArray();
                    }
                }
            }
        }

        public static byte[] DecryptAes(byte[] cipher, byte[] key, CipherMode cipherMode, PaddingMode padding)
        {
            // Create an Aes object
            // with the specified key and IV.
            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.Key = key; ;
                aesAlg.Mode = cipherMode;
                aesAlg.Padding = padding;

                // Create a decryptor to perform the stream transform.
                ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);

                // Create the streams used for decryption.
                using (MemoryStream msDecrypt = new MemoryStream(cipher))
                {
                    using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                    {
                        int b = csDecrypt.ReadByte();
                        var bytes = new List<byte>();
                        while (b != -1)
                        {
                            bytes.Add(Convert.ToByte(b));
                            b = csDecrypt.ReadByte();
                        }
                        return bytes.ToArray();
                    }
                }
            }
        }

        public static byte[] BruteForceAesECBEncryption(byte[][] plainByteBlocks, byte[] key, int blockSize)
        {
            var decryptedBytes = new List<byte>();
            var decrypted = new List<byte>();
            foreach (var block in plainByteBlocks)
            {
                for (int i = 0; i < blockSize; i++)
                {
                    var knownBytes = Enumerable.Repeat(Convert.ToByte(0), blockSize - 1).ToArray();
                    var plainBytes = knownBytes.ToList();
                    var trimmedBlock = block.ToList();
                    trimmedBlock.RemoveRange(0, decryptedBytes.Count);
                    plainBytes.AddRange(trimmedBlock);
                    plainBytes.RemoveRange(16, plainBytes.Count - 16);
                    var encryption = EncryptAes(plainBytes.ToArray(), key, CipherMode.ECB, PaddingMode.None);
                    var bruteForceByte = BruteForceAesByte(encryption, key, blockSize);
                    decryptedBytes.Add(bruteForceByte);
                }
                decrypted.AddRange(decryptedBytes);
                decryptedBytes.Clear();
            }
            return decrypted.ToArray();
        }

        public static byte BruteForceAesByte(byte[] encryption, byte[] key, int blockSize)
        {
            var encryptedBlock = new byte[16];
            Array.Copy(encryption, 0, encryptedBlock, 0, 16);
            byte testByte = 0x00;
            while (true)
            {
                var knownBytes = Enumerable.Repeat(Convert.ToByte(0), blockSize).ToArray();
                knownBytes[blockSize - 1] = testByte;
                var plainBytes = knownBytes.ToList();
                encryption = EncryptAes(plainBytes.ToArray(), key, CipherMode.ECB, PaddingMode.None);
                var bruteForceBlock = new byte[16];
                Array.Copy(encryption, 0, bruteForceBlock, 0, 16);
                if (encryptedBlock.SequenceEqual(bruteForceBlock))
                    break;
                testByte++;
            }
            return testByte;
        }

        #endregion

        #region CBC

        public static byte[] EncryptAesCBC(byte[] plain, byte[] key, byte[] iv)
        {
            var padded = PKCS7Padding(plain, 16);
            var blocks = BreakIntoBlocks(padded, 16);
            var encrypted = new List<byte>();
            bool first = true;

            foreach (var block in blocks)
            {
                var xored = Xor(block, iv);
                var encryptedBlock = EncryptAes(xored, key, CipherMode.ECB, PaddingMode.None);
                if (first)
                {
                    encryptedBlock = EncryptAes(block, key, CipherMode.ECB, PaddingMode.None);
                    encrypted.AddRange(encryptedBlock);
                    first = false;
                }
                else
                {
                    encrypted.AddRange(encryptedBlock);
                }
                iv = encryptedBlock;
            }
            return encrypted.ToArray();
        }

        public static byte[] DecryptAesCBC(byte[] cipher, byte[] key, byte[] iv)
        {
            var decrypted = new List<byte>();
            bool first = true;
            var blocks = BreakIntoBlocks(cipher, 16);
            foreach (var block in blocks)
            {
                var decrypt = DecryptAes(block, key, CipherMode.ECB, PaddingMode.None);
                if (first)
                {
                    decrypted.AddRange(decrypt);
                    first = false;
                }
                else
                {
                    var xored = EncryptRepeatingXor(decrypt, iv);
                    decrypted.AddRange(xored);
                }

                iv = block;
            }
            return decrypted.ToArray();
        }

        #endregion

        #endregion

        #region Padding

        public static byte[] PKCS7Padding(int blockSize, int dataLength)
        {
            var padding = new List<byte>();
            int paddingNumber = 0;
            if (dataLength > blockSize)
            {
                while ((paddingNumber + dataLength) % blockSize != 0)
                {
                    paddingNumber++;
                }
            }
            else
            {
                paddingNumber = blockSize % dataLength;
            }

            while (padding.Count < paddingNumber)
            {
                padding.Add(Convert.ToByte(paddingNumber));
            }

            return padding.ToArray();
        }

        public static byte[] PKCS7Padding(byte[] dataToPad, int blockSize)
        {
            var padded = new List<byte>();
            int paddingNumber = 0;
            int dataLength = dataToPad.Length;
            if (dataLength > blockSize)
            {
                while ((paddingNumber + dataLength) % blockSize != 0)
                {
                    paddingNumber++;
                }
            }
            else
            {
                paddingNumber = blockSize % dataLength;
            }
            padded.AddRange(dataToPad);
            byte[] padding = new byte[paddingNumber];
            for(int i = 0; i < padding.Length; i++)
            {
                padding[i] = Convert.ToByte(paddingNumber);
            }
            padded.AddRange(padding);

            return padded.ToArray();
        }
        #endregion

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


        private static int AreEqual(byte[] a, byte[] b)
        {
            int count = 0;
            if (a.Length == b.Length)
            {
                for (int i = 0; i < a.Length; i++)
                {
                    count += a[i] == b[i] ? 1 : 0;
                }
            }
            if(count == a.Length)
            {
                return 1;
            }
            return 0;
        }

        #endregion

    }
}
