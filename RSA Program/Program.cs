using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace RSA_Program
{
    class Program
    {
        static void Main(string[] args)
        {
            RSAEncryption myEncryption = new RSAEncryption();
            if (args.Length == 0)
            {
                Console.WriteLine("Improper Arguments! v for verify s for sign!");
                Console.ReadKey();
                return;
            }
            if(args[0].CompareTo("s") == 0)
            {
                String myRemain = "";
                for(int i = 1; i <args.Length; i++)
                {
                    myRemain += args[i];
                }
                myEncryption.CreateEncryptedDigitalSignature("./" + myRemain);

            }
            else if (args[0].CompareTo("v") == 0)
            {
                String myRemain = "";
                for (int i = 1; i < args.Length; i++)
                {
                    myRemain += args[i];
                }
                myRemain = myRemain.Remove(myRemain.LastIndexOf('.'));
                myEncryption.verifyFile("./" + myRemain);
            }
        }

        public static void testSuite(RSAEncryption myEncryption)
        {
            myEncryption.testPrimes();
            myEncryption.testEncrypt();
            myEncryption.testDecrypt();
            myEncryption.testEuclideanExtended();
            myEncryption.testMMI();
            myEncryption.testSimpleEncryptedDigitalSignature();
            Console.ReadKey();
            Console.WriteLine("./bible_part1.txt");
            myEncryption.CreateEncryptedDigitalSignature("./bible_part1.txt");
            
            Console.ReadKey();
            Console.ReadKey();
            Console.ReadKey();
            Console.ReadKey();
            Console.ReadKey();
            // Console.WriteLine("./bible_part1.docx");
            // myEncryption.CreateEncryptedDigitalSignature("./bible_part1.docx");
            // Console.WriteLine("./monkey.jpg");
            // myEncryption.CreateEncryptedDigitalSignature("./monkey.jpg");
            ///  Console.WriteLine("./rsa435.exe");
            //myEncryption.CreateEncryptedDigitalSignature("./rsa435.exe");


        }

    }
}
