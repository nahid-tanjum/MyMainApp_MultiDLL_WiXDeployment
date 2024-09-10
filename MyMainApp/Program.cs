using System;
using MyLibrary1;
using MyLibrary2;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace MyMainApp
{
    class Program
    {
        static void Main(string[] args)
        {
            // Create instances of classes from the DLLs
            MathOperations math = new MathOperations();
            StringOperations strOps = new StringOperations();

            // Use methods from MyLibrary1 (MathOperations)
            int sum = math.Add(5, 10);
            int diff = math.Subtract(20, 5);

            // Use methods from MyLibrary2 (StringOperations)
            string concatenated = strOps.Concatenate("Hello", " World");
            int length = strOps.GetLength(concatenated);


            MessageBox.Show($"Sum: {sum}, Difference: {diff}\nConcatenated: {concatenated}, Length: {length}",
                           "Results", MessageBoxButtons.OK, MessageBoxIcon.Information);

            // Output the results
            Console.WriteLine($"Sum: {sum}, Difference: {diff}");
            Console.WriteLine($"Concatenated: {concatenated}, Length: {length}");
        }
    }
}

