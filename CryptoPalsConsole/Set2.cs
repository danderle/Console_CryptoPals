using System;
using System.Collections.Generic;
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
            for(int i = 0; i < 1000; i++)
            {
                var dataBytes = File.ReadAllBytes("Set2Challenge11.txt");
                byte[] encryption;
                var mode = CryptoMethods.RandomEncryption(dataBytes, out encryption);
                byte[] mostRepeatedBlock;
                int maxRepeated = CryptoMethods.NumberOfRepeatedBlocks(encryption, out mostRepeatedBlock);
                if(maxRepeated > 1)
                {
                    if(mode == CipherMode.CBC)
                    {
                        Console.WriteLine("Failed to Detect CBC --> " + maxRepeated);
                    }
                    else
                    {
                        Console.WriteLine("EBC Mode: Repeated Blocks --> " + maxRepeated);
                    }
                }
                else
                {
                    Console.WriteLine("CBC Mode: Repeated Blocks --> " + maxRepeated);
                }
            }
            

        }

        #endregion
    }
}
