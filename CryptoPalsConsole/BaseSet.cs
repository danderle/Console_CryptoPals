using System;
using System.Collections.Generic;
using System.Text;

namespace CryptoPalsConsole
{
    public class BaseSet
    {
        protected void CheckResult(string result, string expected)
        {
            if (result.Equals(expected))
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
