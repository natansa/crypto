using System.Security.Cryptography;
using System.Text;

namespace crypto.Crypto.Sha
{
    public static class CryptoSha
    {
        private static readonly string preSalt = "FCF2741E-0B74-424D-83F9-9EAA0C8B897F";
        private static readonly string posSalt = "E603DCA8-1B6E-4AF9-AE35-6449FC1F84DF";

        public static string Encrypt(string dataToEncrypt)
        {
            string encryptedData;

            using (var sha512 = SHA512.Create())
            {
                var bytes = Encoding.UTF8.GetBytes($"{preSalt}{dataToEncrypt}{posSalt}");
                var hash = sha512.ComputeHash(bytes);
                encryptedData = GetStringFromHash(hash);
            }

            return encryptedData;
        }

        private static string GetStringFromHash(byte[] hash)
        {
            var result = new StringBuilder();

            for (var i = 0; i < hash.Length; i++)
            {
                result.Append(hash[i].ToString("X2"));
            }

            return result.ToString();
        }
    }
}
