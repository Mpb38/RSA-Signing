using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Numerics;
using System.Security.Cryptography;
using System.IO;
using System.Diagnostics;

namespace RSA_Program
{
    class RSAEncryption
    {
        private RandomNumberGenerator myGenerator;
        private SHA256 mySHAGenerator;
        private BigInteger myE;
        private BigInteger myN;
        private BigInteger myP;
        private BigInteger myQ;
        private BigInteger myD;

        private void clearData()
        {
            myE = 0;
            myN = 0;
            myP = 0; ;
            myQ = 0; ;
            myD = 0; ;
            aPossiblePrime = 0;
        }

        internal void testMMI()
        {
           BigInteger g = getMultiplicativeInverse(3, 11);
            Console.WriteLine("MMI of 3,11: Expected 4: Result: " + g);
            Console.ReadKey();
        }

        public void CreateEncryptedDigitalSignature(String Path)
        {
            clearData();
            myGenerator = new RNGCryptoServiceProvider();
            Byte[] SHA256ToEncrypt = CreateSHA256FromFile(Path);
            Byte[] SHA256ToEncrypt2 = new BigInteger(SHA256ToEncrypt).ToByteArray();
            String aPath;
            String aFileName;
            seperatePathAndFileName(Path, out aPath, out aFileName);

            generateRSAKeys(512);
            writePublicKey(aPath);
            writePrivateKey(aPath);
            writePrimes(aPath);

            Console.WriteLine(SHA256ToEncrypt);
            Byte[] myEncryptedSHA = decryptBytes(SHA256ToEncrypt);
            Console.WriteLine(myEncryptedSHA);
            Console.WriteLine(encryptBytes(myEncryptedSHA));

           FileStream mySignatureFile = File.Create(Path.Remove(Path.LastIndexOf('/') + 1) + aFileName + ".signed");
            mySignatureFile.Write(myEncryptedSHA, 0, myEncryptedSHA.Length);

            Console.Write("inputted lines: " + myEncryptedSHA.Length);
            Console.Write("inputted lines SHA: " + SHA256ToEncrypt.Length);
            mySignatureFile.Close();
        }

        public void testSimpleEncryptedDigitalSignature()
        {
            clearData();
            myGenerator = new RNGCryptoServiceProvider();


            generateRSAKeys(512);

            BigInteger myBit = BigInteger.Parse("688");

            Console.WriteLine("Byte must equal: 688  Result: " + myBit);
            byte[] myReturnedBytes = decryptBytes(myBit.ToByteArray());
            Console.WriteLine("Decrypt: " + new BigInteger(myReturnedBytes));
            myReturnedBytes = encryptBytes(myReturnedBytes);
            Console.WriteLine("Byte must equal: 688  Result: ");
            Console.Write(new BigInteger(myReturnedBytes));
        }


        private void seperatePathAndFileName(string path, out string aPath, out string aFileName)
        {
            aPath = path.Remove(path.LastIndexOf('/') + 1);
            aFileName = path.Substring(path.LastIndexOf('/') + 1);
            Console.WriteLine(aPath);
            Console.WriteLine(aFileName);
        }

        private void generateRSAKeys(int bits)
        {
            myE = generatePrime(bits);
            BigInteger LCM;
            BigInteger Test;
            do
            {
                myP = generatePrime(bits);
                myQ = generatePrime(bits);
                LCM = findLeastCommonMultiple(BigInteger.Subtract(myP, new BigInteger(1)), BigInteger.Subtract(myQ, new BigInteger(1)));
                Test = BigInteger.Multiply(myE, myD); //Derived from wiki example
            } while (findGreatestCommonDenominator(myE, LCM).CompareTo(BigInteger.One) != 0 && BigInteger.Remainder(Test, BigInteger.Multiply(BigInteger.Subtract(myP, new BigInteger(1)), BigInteger.Subtract(myQ, new BigInteger(1)))).CompareTo(1) == 1);

            myD = getMultiplicativeInverse(myE, LCM);
           
            myN = BigInteger.Multiply(myP, myQ);
            Console.WriteLine("N length: " + myN.ToByteArray().Length*8);
            
        }

        private BigInteger findGreatestCommonDenominator(BigInteger x, BigInteger y)
        {
            BigInteger oldGCD = x;
            BigInteger GCD =  y;
            while(GCD != 0)
            {
                BigInteger Quotient = BigInteger.Divide(oldGCD, GCD);
                BigInteger tempMult = GCD;
                GCD = oldGCD - Quotient * GCD;
                oldGCD = tempMult;
            }
            return oldGCD;
        }

        private BigInteger getMultiplicativeInverse(BigInteger x, BigInteger y)
        {
            BigInteger x0 = 0;
            BigInteger x1 = 1;
            BigInteger ystart = y;
            while (x > 1)
            {
                BigInteger Quotient = BigInteger.Divide(x, y);
                BigInteger tempMult = y;
                y = x % y;
                x = tempMult; //Derived from Code Geeks Code Example
                tempMult = x0;
                x0 = x1 - Quotient * x0;
                x1 = tempMult;
            }
            if (x1 < 0) x1 += ystart;

            return x1;
        }

        private BigInteger findLeastCommonMultiple(BigInteger myP, BigInteger myQ)
        {
            BigInteger MassiveInt = BigInteger.Multiply(myP, myQ);
            BigInteger GCDInt = findGreatestCommonDenominator(myP, myQ); //Derived from Code Geeks Code Example
            return BigInteger.Divide(MassiveInt, GCDInt);
        }

      
        public void testPrimes()
        {
            bits = 2;
            myGenerator = new RNGCryptoServiceProvider();
            Console.WriteLine("6461333093 Expected: true Test Result = " + isPrime(new BigInteger(6461333093)));
            Console.WriteLine("6461333687 Expected: true Test Result = " + isPrime(new BigInteger(6461333687)));
            Console.WriteLine("6461334059 Expected: true Test Result = " + isPrime(new BigInteger(6461334559)));
            Console.WriteLine("6461334559 Expected: true Test Result = " + isPrime(new BigInteger(6461334559)));
            Console.WriteLine("1000000000 Expected: false Test Result = " + isPrime(new BigInteger(1000000000)));
            Console.WriteLine("1000000002 Expected: false Test Result = " + isPrime(new BigInteger(1000000002)));
            Console.ReadKey();
        }

        public void testEncrypt()
        {
            myN = new BigInteger(3337);
            myE = new BigInteger(79);
            BigInteger myBit = BigInteger.Parse("688");
            
            Console.WriteLine("Byte must equal: 688  Result: " + myBit);
            byte[] myReturnedBytes = encryptBytes(myBit.ToByteArray());
            myBit = new BigInteger(myReturnedBytes);
            Console.WriteLine("TestByte: 688; Expected Result: 1570; Result: " + myBit);
            Console.ReadLine();
        }

        public void testDecrypt()
        {
            myN = new BigInteger(3337);
            myE = new BigInteger(79);
            myD = new BigInteger(1019);
            BigInteger myBit = BigInteger.Parse("1570");
            Console.WriteLine("Byte must equal: 1570  Result: " + myBit);
            Console.WriteLine("Byte must equal: 688  Result: " + new BigInteger(decryptBytes(myBit.ToByteArray())));
            Console.ReadLine();
        }


        public void testEuclideanExtended() //GCD
        {
           BigInteger retVal = findGreatestCommonDenominator(BigInteger.Parse("125"), BigInteger.Parse("87"));
           Console.WriteLine("Byte must equal: 1  Result: " + retVal);
            retVal = findGreatestCommonDenominator(BigInteger.Parse("54"), BigInteger.Parse("24"));
            Console.WriteLine("Byte must equal: 6  Result: " + retVal);
            Console.ReadLine();
        }

        private Byte[] CreateSHA256FromFile(String Path)
        {
            FileStream fileStream = File.Open(Path, FileMode.Open);
            mySHAGenerator = SHA256Managed.Create();
            Byte[] myHash = mySHAGenerator.ComputeHash(fileStream);
            mySHAGenerator.Clear();
            fileStream.Close();
            return myHash;
        }

        public Byte[] encryptBytes(Byte[] myByte)
        {
            BigInteger myTestInt = new BigInteger(myByte);
            Byte[] Test = myTestInt.ToByteArray();// = new BigInteger(myByte);
            Byte[] myReturnBytes = BigInteger.ModPow(myTestInt, myE, myN).ToByteArray();
            return myReturnBytes;
        }

        public Byte[] decryptBytes(Byte[] anEncryptedByte)
        {
            BigInteger myTestInt = new BigInteger(anEncryptedByte);
            Byte[] Test = myTestInt.ToByteArray();// = new BigInteger(myByte);
            Byte[] myReturnBytes = BigInteger.ModPow(myTestInt, myD, myN).ToByteArray();
            return myReturnBytes;
        }

        private void writePublicKey(String myPath)
        {
            TextWriter myWriter = File.CreateText(myPath + "/e_n.txt");
            Console.WriteLine("Writing public key... to " + myPath + "/e_n.txt");
            myWriter.WriteLine(myE);
            myWriter.WriteLine(myN);
            myWriter.Close();
        }

        private void writePrimes(String myPath)
        {
            TextWriter myWriter = File.CreateText(myPath + "/p_q.txt");
            Console.WriteLine("Writing primes... to " + myPath + "/p_q.txt");
            //byte[] myPArray = myP.ToByteArray();
            //byte[] myQArray = myQ.ToByteArray();
            myWriter.WriteLine(myP);
            myWriter.WriteLine(myQ);
            //fileStream.WriteLine(p);
            //fileStream.WriteLine(q);
            myWriter.Close();
        }

        private void writePrivateKey(String myPath)
        {
            TextWriter myWriter = File.CreateText(myPath + "/d_n.txt");
            Console.WriteLine("Writing private... to " + myPath + "/d_n.txt");
            myWriter.WriteLine(myD);
            myWriter.WriteLine(myN);
            myWriter.Close();
        }

        public void verifyFile(String myPath)
        {
            String aPath;
            String aFileName;
            seperatePathAndFileName(myPath, out aPath, out aFileName);
            TextReader myReader = File.OpenText(aPath + "\\e_n.txt");
            myE = BigInteger.Parse(myReader.ReadLine());
            myN = BigInteger.Parse(myReader.ReadLine());
            myReader.Close();
            Byte[] mySHA = CreateSHA256FromFile(myPath);
            FileStream originalFileSignature = File.OpenRead(aPath + "\\" + aFileName + ".signed");
            FileStream newFile = File.OpenRead(aPath + "\\HashToCheck.txt");
            Byte[] myStream = new Byte[originalFileSignature.Length];
            originalFileSignature.Read(myStream, 0, (int)originalFileSignature.Length);
            myStream = encryptBytes(myStream);
            byte[] plsStream = encryptBytes(mySHA);
            BigInteger myInteger = new BigInteger(myStream);
            BigInteger mySHAInt = new BigInteger(mySHA);
            int gLength = mySHA.Length;
            if (myInteger.CompareTo(mySHAInt) == 0)
            {
                Console.WriteLine("Verified!");
            } else
            {
                Console.WriteLine("Verification failed!!");
            }

        }


        public void printBytes(byte[] myBytes)
        {
            foreach(byte A in myBytes)
            {
                Console.Write(A);
            }
            Console.WriteLine("END");
        }

        private double bits;
        private Byte[] GenerateRandomNumber(double Bits)
        {
            
            bits = Bits;
            String BigIntString = "";
            double BytesFromBitsalt = Bits / 8;
            Byte[] myBytes = new Byte[(int)Math.Ceiling(BytesFromBitsalt)];
            myGenerator.GetNonZeroBytes(myBytes);
            return myBytes;
        }

     

        private BigInteger GetValueInRange(BigInteger v, BigInteger bigInteger)
        {
            BigInteger retVal;
            do
            {
                retVal = new BigInteger(GenerateRandomNumber(bits));
            } while (retVal.CompareTo(v) < 0 || retVal.CompareTo(bigInteger) > 0);
            return retVal;
        }

        private static BigInteger aPossiblePrime; //Moved out of recursive function to try and save space;
        private bool isPrime(BigInteger possiblePrime)
        {
            RSAEncryption.aPossiblePrime = possiblePrime;
            if (possiblePrime.CompareTo(0) < 0) return false;
            for(int i = 0; i < 10; i++)
            {
                BigInteger FermatA = GetValueInRange(BigInteger.One, possiblePrime - 1);
                BigInteger myA = BigInteger.ModPow(FermatA, BigInteger.Subtract(possiblePrime, BigInteger.One), possiblePrime);
                if (myA != BigInteger.One)
                {
                    return false;
                }
            }
            return true;
        }


        private BigInteger generatePrime(int Bits)
        {
            Byte[] myRandom = GenerateRandomNumber(Bits);
            while (!isPrime(new BigInteger(myRandom)))
            {
                myRandom = GenerateRandomNumber(Bits);
            }
            BigInteger Test = new BigInteger(myRandom);
            Debug.Assert(Test.CompareTo(0) > 0);
            return new BigInteger(myRandom);
        }
    }
}
