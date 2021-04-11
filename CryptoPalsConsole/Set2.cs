﻿using System;
using System.IO;
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
        }

        #region Chgallenges

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
            for (int i = 0; i < 1000; i++)
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
            Console.WriteLine($"fail count: {failCount}");

        }

        #endregion
    }
}
