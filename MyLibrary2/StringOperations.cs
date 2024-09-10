using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace MyLibrary2
{
    public class StringOperations
    {
        public string Concatenate(string str1, string str2)
        {
            return str1 + str2;
        }

        public int GetLength(string str)
        {
            return str.Length;
        }
    }
}
