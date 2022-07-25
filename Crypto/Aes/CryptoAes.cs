using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace crypto.Crypto.Aes
{
    public class CryptoAes
    {
        private static readonly string saltAES = "D330F679-2130-4EC8-A857-04170C0E9EB9";
        private static string inputKey;

        public CryptoAes()
        {
            inputKey = new string(saltAES.Reverse().ToArray());
        }

        public string Encrypt(string value)
        {
            if (string.IsNullOrEmpty(value))
            {
                return value;
            }

            var aes = NewRijndaelManaged();
            var encryptor = aes.CreateEncryptor(aes.Key, aes.IV);
            var memoryStreamEncrypt = new MemoryStream();
            using (var csEncrypt = new CryptoStream(memoryStreamEncrypt, encryptor, CryptoStreamMode.Write))
            using (var swEncrypt = new StreamWriter(csEncrypt))
            {
                swEncrypt.Write(value);
            }

            return Convert.ToBase64String(memoryStreamEncrypt.ToArray());
        }

        public string Decrypt(string value)
        {
            if (string.IsNullOrEmpty(value) || !IsBase64String(value))
            {
                return value;
            }

            var aes = NewRijndaelManaged();
            var decryptor = aes.CreateDecryptor(aes.Key, aes.IV);
            var cipher = Convert.FromBase64String(value);
            string result;

            using (var memoryStreamDecrypt = new MemoryStream(cipher))
            {
                using var csDecrypt = new CryptoStream(memoryStreamDecrypt, decryptor, CryptoStreamMode.Read);
                using var srDecrypt = new StreamReader(csDecrypt);
                result = srDecrypt.ReadToEnd();
            }

            return result;
        }

        private RijndaelManaged NewRijndaelManaged()
        {
            var saltBytes = Encoding.ASCII.GetBytes(saltAES);
            var key = new Rfc2898DeriveBytes(inputKey, saltBytes);

            var aes = new RijndaelManaged();
            aes.Key = key.GetBytes(aes.KeySize / 8);
            aes.IV = key.GetBytes(aes.BlockSize / 8);

            return aes;
        }

        private static bool IsBase64String(string base64String)
        {
            base64String = base64String.Trim();
            return (base64String.Length % 4 == 0) && Regex.IsMatch(base64String, @"^[a-zA-Z0-9\+/]*={0,3}$", RegexOptions.None);
        }
    }
}
