using System.Security.Cryptography;
using System.Text;

namespace crypto.Crypto.Tripledes
{
    public static class CryptoTripledes
    {
        private static readonly string tripledesKey = "BF27AE49-8E62-4368-ADAF-8196656A1699";

        public static string Encrypt(string value)
        {
            var tripledes = CreateTripledes(tripledesKey);
            var cryptoTransform = tripledes.CreateEncryptor();
            var input = Encoding.UTF8.GetBytes(value);
            var output = cryptoTransform.TransformFinalBlock(input, 0, input.Length);
            return Convert.ToBase64String(output);
        }

        public static string Decrypt(string value)
        {
            var tripledes = CreateTripledes(tripledesKey);
            var cryptoTransform = tripledes.CreateDecryptor();
            var input = Convert.FromBase64String(value);
            var output = cryptoTransform.TransformFinalBlock(input, 0, input.Length);
            return Encoding.UTF8.GetString(output);
        }

        private static TripleDES CreateTripledes(string key)
        {
            var md5 = new MD5CryptoServiceProvider();
            var tripledes = new TripleDESCryptoServiceProvider();
            var hash = md5.ComputeHash(Encoding.UTF8.GetBytes(key));
            tripledes.Key = hash;
            tripledes.IV = new byte[tripledes.BlockSize / 8];
            tripledes.Padding = PaddingMode.PKCS7;
            tripledes.Mode = CipherMode.ECB;
            return tripledes;
        }
    }
}