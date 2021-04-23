using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;

namespace CryptoPalsConsole
{
    public class Set2 : BaseSet
    {
        public Set2()
        {
            Console.WriteLine("Welcome to Set 2");
            Console.WriteLine();
            Challenge9();
            Console.WriteLine();
            Challenge10();
            Console.WriteLine();
            Challenge11();
            Console.WriteLine();
            Challenge12();
            Console.WriteLine();
            Challenge13();
        }

        #region Challenges

        public void Challenge9()
        {
            Console.WriteLine("Challenge 9");
            var data = "YELLOW SUBMARINE";
            var expected = "YELLOW SUBMARINE04040404";
            var resultBytes = CryptoMethods.PKCS7Padding(20, Conversion.AsciiToBytes(data).Length);
            var result = data + Conversion.BytesToHexString(resultBytes);

            CheckResult(result, expected);
        }


        public void Challenge10()
        {
            Console.WriteLine("Challenge 10");
            var key = "YELLOW SUBMARINE";
            var iv = "0000000000000000";
            var keyBytes = Conversion.AsciiToBytes(key);
            var ivBytes = Conversion.AsciiToBytes(iv);
            var dataBytes = Conversion.Base64StringToBytes(File.ReadAllText("Set2Challenge10.txt"));

            var decrypted = CryptoMethods.DecryptAesCBC(dataBytes, keyBytes, ivBytes);

            var decryptedTxt = Conversion.BytesToAsciiString(decrypted);
            Console.WriteLine(decryptedTxt);
            Console.WriteLine("Success");
        }

        public void Challenge11()
        {
            Console.WriteLine("Challenge 11");
            var dataText = File.ReadAllText("Set2Challenge11.txt").Replace("\r","").Replace("\n", "");
            int failCount = 0;
            int succesCount = 0;
            for (int i = 0; i < 1; i++)
            {
                var dataBytes = Conversion.AsciiToBytes(dataText);
                byte[] encryption;
                var mode = CryptoMethods.RandomEncryption(dataBytes, out encryption);
                byte[] mostRepeatedBlock;
                int maxRepeated = CryptoMethods.NumberOfRepeatedBlocks(encryption, out mostRepeatedBlock);

                if(maxRepeated >= 1)
                {
                    if(mode == CipherMode.CBC)
                    {
                        Console.WriteLine("Failed to Detect CBC --> " + maxRepeated + " *****Fail******");
                        failCount++;
                    }
                    else
                    {
                        Console.WriteLine("EBC Mode: Repeated Blocks --> " + maxRepeated + " Success");
                        succesCount++;
                    }
                }
                else
                {
                    if (mode == CipherMode.ECB)
                    {
                        Console.WriteLine("Failed to Detect ECB --> " + maxRepeated + " *****Fail******");
                        failCount++;
                    }
                    else
                    {
                        Console.WriteLine("CBC Mode: Repeated Blocks --> " + maxRepeated + " Success");
                        succesCount++;
                    }
                }
            }

            Console.WriteLine($"Success count: {succesCount}");
            Console.WriteLine($"Fail count: {failCount}");
        }

        public void Challenge12()
        {
            Console.WriteLine("Challenge 12");
            var key = CryptoMethods.RandomBytes(16);
            var unknownBytes = Conversion.Base64StringToBytes("Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK");
            var knownText = "YoooooooooooooooYooooooooooooooo";
            var knownBytes = Conversion.AsciiToBytes(knownText);
            var plainBytes = knownBytes.ToList();
            plainBytes.AddRange(unknownBytes);
            byte[] encryption;
            var blockSize = CryptoMethods.GetAesEncryptionBlockSize(plainBytes.ToArray(), key, out encryption);
            byte[] mostRepeatedBlock;
            int maxRepeated = CryptoMethods.NumberOfRepeatedBlocks(encryption, out mostRepeatedBlock);
            File.WriteAllBytes("EBCencryption.bin", encryption);
            if(maxRepeated >= 1)
            {
                Console.WriteLine("ECB Mode");
            }
            unknownBytes = CryptoMethods.PKCS7Padding(unknownBytes, 16);
            var unknownByteBlocks = CryptoMethods.BreakIntoBlocks(unknownBytes, blockSize);
            var decrypted = CryptoMethods.BruteForceAesECBEncryption(unknownByteBlocks, key, blockSize);
            Console.WriteLine(Conversion.BytesToAsciiString(decrypted));
        }

        public void Challenge13()
        {
            Console.WriteLine("Challenge 13");
            CryptoMethods.EqualsParser("foo=bar&baz=qux&zap=zazzle");
            var key = CryptoMethods.RandomBytes(16);
            var encodedProfile = CryptoMethods.Profile_For("danderle");
            var plainBytes = Conversion.AsciiToBytes(encodedProfile);
            var paddedBytes = CryptoMethods.PKCS7Padding(plainBytes, 16);
            var encryption = CryptoMethods.EncryptAes(paddedBytes, key, CipherMode.ECB, PaddingMode.None);
            var decryption = CryptoMethods.DecryptAes(encryption, key, CipherMode.ECB, PaddingMode.None);
            decryption = CryptoMethods.RemovePkcsPadding(decryption);
            var decrytedString = Conversion.BytesToAsciiString(decryption);
            CryptoMethods.EqualsParser(decrytedString);
            Console.WriteLine("Test completed");

            string email1 = "danderle@mail";
            string email2 = "AAAAAAAAAA";
            var email2Bytes = Conversion.AsciiToBytes(email2).ToList();
            email2Bytes.AddRange(CryptoMethods.PKCS7Padding(Conversion.AsciiToBytes("admin"), 16));
            var encryption1 = CryptoMethods.EncryptedProfile_For(email1, key);
            var paddedemail2 = CryptoMethods.PKCS7Padding(Conversion.AsciiToBytes(email2), 16);
            email2Bytes.AddRange(paddedemail2);
            var encryption2 = CryptoMethods.EncryptedProfile_For(Conversion.BytesToAsciiString(email2Bytes.ToArray()), key).ToList();

            var customEncryption = encryption1.ToList();
            customEncryption.RemoveRange(customEncryption.Count - 16, 16);
            customEncryption.AddRange(encryption2.GetRange(16,16));
            
            decryption = CryptoMethods.DecryptAes(customEncryption.ToArray(), key, CipherMode.ECB, PaddingMode.None);
            decryption = CryptoMethods.RemovePkcsPadding(decryption);
            decrytedString = Conversion.BytesToAsciiString(decryption.ToArray());
            Console.WriteLine(decrytedString);
            CryptoMethods.EqualsParser(decrytedString);
        }

        #endregion
    }
}
