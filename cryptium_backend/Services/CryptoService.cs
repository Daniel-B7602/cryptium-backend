using System.Security.Cryptography;
using System.Text;

namespace cryptium_backend.Services
{
    public class CryptoService
    {
        public string Encrypt(string plainText, string key)
        {
            byte[] keyBytes = SHA256.HashData(Encoding.UTF8.GetBytes(key));

            using Aes aes = Aes.Create();

            aes.Key = keyBytes;
            aes.GenerateIV();

            byte[] plainBytes = Encoding.UTF8.GetBytes(plainText);

            using ICryptoTransform encryptor = aes.CreateEncryptor();

            byte[] encryptedBytes = encryptor.TransformFinalBlock(
                plainBytes,
                0,
                plainBytes.Length
            );

            byte[] result = new byte[aes.IV.Length + encryptedBytes.Length];

            Buffer.BlockCopy(
                aes.IV,
                0,
                result,
                0,
                aes.IV.Length
            );

            Buffer.BlockCopy(
                encryptedBytes,
                0,
                result,
                aes.IV.Length,
                encryptedBytes.Length
            );

            return Convert.ToBase64String(result);
        }

        public string Decrypt(string encryptedText, string key)
        {
            byte[] keyBytes = SHA256.HashData(Encoding.UTF8.GetBytes(key));

            byte[] encryptedData =
                Convert.FromBase64String(encryptedText);

            using Aes aes = Aes.Create();

            aes.Key = keyBytes;

            byte[] iv = new byte[aes.BlockSize / 8];

            byte[] cipherText = new byte[
                encryptedData.Length - iv.Length
            ];

            Buffer.BlockCopy(
                encryptedData,
                0,
                iv,
                0,
                iv.Length
            );

            Buffer.BlockCopy(
                encryptedData,
                iv.Length,
                cipherText,
                0,
                cipherText.Length
            );

            aes.IV = iv;

            using ICryptoTransform decryptor = aes.CreateDecryptor();

            byte[] decryptedBytes = decryptor.TransformFinalBlock(
                cipherText,
                0,
                cipherText.Length
            );

            return Encoding.UTF8.GetString(decryptedBytes);
        }
    }
}