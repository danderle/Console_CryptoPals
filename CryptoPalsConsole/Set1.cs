using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace CryptoPalsConsole
{
    public class Set1
    {
        public Set1()
        {
            Console.WriteLine("Welcome to Set1");
            Console.WriteLine();
            Challenge1();
            Console.WriteLine();
            Challenge2();
            Console.WriteLine();
            Challenge3();
            Console.WriteLine();
            Challenge4();
            Console.WriteLine();
            Challenge5();
            Console.WriteLine();
            Challenge6();
            Console.WriteLine();
            Challenge7();
            Console.WriteLine();
            Challenge8();
        }

        #region Challenges

        public void Challenge1()
        {
            Console.WriteLine("Challenge 1");
            var dataSet1 = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
            var expected = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t";

            var bytes = Conversion.HexStringToBytes(dataSet1);
            var result = Conversion.BytesToBase64String(bytes);

            CheckResult(result, expected);
        }

        public void Challenge2()
        {
            Console.WriteLine("Challenge 2");
            var dataSet1 = "1c0111001f010100061a024b53535009181c";
            var dataSet2 = "686974207468652062756c6c277320657965";
            var expected = "746865206b696420646f6e277420706c6179";

            var bytes1 = Conversion.HexStringToBytes(dataSet1);
            var bytes2 = Conversion.HexStringToBytes(dataSet2);
            var resultBytes = CryptoMethods.Xor(bytes1, bytes2);
            var result = Conversion.BytesToHexString(resultBytes);
            CheckResult(result, expected);
        }

        public void Challenge3()
        {
            Console.WriteLine("Challenge 3");
            var dataSet1 = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";

            var keyAndMessage = CryptoMethods.DetectSingleByteXorDecryption(Conversion.HexStringToBytes(dataSet1));
            Console.WriteLine($"The key: {keyAndMessage.Key}");
            Console.WriteLine($"The Message: {keyAndMessage.Value}");
            Console.WriteLine("Success if the message is readable");
        }

        public void Challenge4()
        {
            Console.WriteLine("Challenge 4");
            var lines = File.ReadAllLines("Set1Challenge4.txt");

            int topScore = 0;
            string message = string.Empty;
            int key = 0;
            foreach(var line in lines)
            {
                var bytes = Conversion.HexStringToBytes(line);
                var keyAndMessage = CryptoMethods.DetectSingleByteXorDecryption(bytes);
                int letterCount = 0;
                foreach (var c in keyAndMessage.Value)
                {
                    if (Char.IsWhiteSpace(c) || Char.IsLetter(c))
                    {
                        letterCount++;
                    }
                    else
                    {
                        letterCount--;
                    }
                }
                if (topScore < letterCount)
                {
                    topScore = letterCount;
                    message = keyAndMessage.Value;
                    key = keyAndMessage.Key;
                }
            }
            Console.WriteLine($"The key: {key}");
            Console.WriteLine($"The Message: {message}");
            Console.WriteLine("Success if the message is readable");
        }

        public void Challenge5()
        {
            Console.WriteLine("Challenge 5");
            var dataSet1 = "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal";
            var key = "ICE";
            var expected = "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f";

            var bytes = CryptoMethods.EncryptRepeatingXor(Conversion.AsciiToBytes(dataSet1), Conversion.AsciiToBytes(key));
            var result = Conversion.BytesToHexString(bytes);

            CheckResult(result, expected);
        }

        public void Challenge6()
        {
            Console.WriteLine("Challenge 6");
            var dataSet1 = "this is a test";
            var dataSet2 = "wokka wokka!!!";
            var expected = 37.ToString();

            var result = CryptoMethods.HammingDistance(Conversion.AsciiToBytes(dataSet1), Conversion.AsciiToBytes(dataSet2)).ToString();

            Console.WriteLine("Hamming Distance Check");
            CheckResult(result, expected);

            var fileText = File.ReadAllText("Set1Challenge6.txt");
            var fileBytes = Conversion.Base64StringToBytes(fileText);
            var keySizes = CryptoMethods.GetPossibleXorKeySize(2, 42, 3, fileBytes);

            int index = 1;

            foreach (var keySize in keySizes)
            {
                var possibleKeys = new List<byte>();
                var keySizeBlocks = CryptoMethods.BreakIntoBlocks(fileBytes, keySize);
                var transposedBlocks = CryptoMethods.TransposeBlocks(keySizeBlocks);
                foreach(var block in transposedBlocks)
                {
                    possibleKeys.Add(Convert.ToByte(CryptoMethods.DetectSingleByteXorDecryption(block).Key));
                }

                Console.WriteLine("Key " + index);
                Console.WriteLine(Conversion.BytesToAsciiString(possibleKeys.ToArray()));
                if(index == 1)
                {
                    var decrypted = CryptoMethods.EncryptRepeatingXor(fileBytes, possibleKeys.ToArray());
                    Console.WriteLine(Conversion.BytesToAsciiString(decrypted));
                }
                index++;
            }
        }

        public void Challenge7()
        {
            Console.WriteLine("Challenge 7");
            var key = "YELLOW SUBMARINE";
            var fileText = File.ReadAllText("Set1Challenge7.txt");
            var encrypted = Conversion.Base64StringToBytes(fileText);
            var hexstring = Conversion.BytesToHexString(encrypted);

            var decryptedBytes = CryptoMethods.DecryptAes(encrypted, Conversion.AsciiToBytes(key), CipherMode.ECB);
            Console.WriteLine($"The Message: {Conversion.BytesToAsciiString(decryptedBytes)}");
            Console.WriteLine("Success if the message is readable");
        }

        public void Challenge8()
        {
            Console.WriteLine("Challenge 8");
            var fileText = File.ReadAllText("Set1Challenge8.txt").Replace("\r", "").Replace("\n","");
            var encrypted = Conversion.HexStringToBytes(fileText);
            var blocks = CryptoMethods.BreakIntoBlocks(encrypted, 16);
            var bytes = new byte[16];
            int mostMatches = 0;
            for(int blockIndex = 0; blockIndex < blocks.Length; blockIndex++)
            {
                int matches = 0;
                for (int othersIndex = 0; othersIndex < blocks.Length; othersIndex++)
                {
                    if (blockIndex != othersIndex)
                    {
                         matches += AreEqual(blocks[blockIndex], blocks[othersIndex]);
                        if(matches > mostMatches)
                        {
                            mostMatches = matches;
                            bytes = blocks[blockIndex];
                        }
                    }
                }
            }

            Console.WriteLine("Repeated Block");
            Console.WriteLine(Conversion.BytesToHexString(bytes));
        }

        #endregion

        private int AreEqual(byte[] a, byte[] b)
        {
            int count = 0;
            if(a.Length == b.Length)
            {
                for(int i = 0; i < a.Length; i++)
                {
                    count += a[i] == b[i] ? 1 : 0;
                }
                return count;
            }
            return 0;
        }

        private void CheckResult(string result, string expected)
        {
            if(result.Equals(expected))
            {
                Console.WriteLine("Success");
            }
            else
            {
                Console.WriteLine("Fail");
            }
        }
    }
}
