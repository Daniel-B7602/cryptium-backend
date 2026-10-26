using System.Security.Cryptography;
using System.Text;

namespace cryptium_backend.Services
{
    public class FileCryptoService
    {
        public byte[] EncryptFile(byte[] fileBytes, string key)
        {
            byte[] keyBytes = SHA256.HashData(
                Encoding.UTF8.GetBytes(key)
            );

            using Aes aes = Aes.Create();

            aes.Key = keyBytes;
            aes.GenerateIV();

            using ICryptoTransform encryptor = aes.CreateEncryptor();

            byte[] encrypted = encryptor.TransformFinalBlock(
                fileBytes,
                0,
                fileBytes.Length
            );

            byte[] result = new byte[
                aes.IV.Length + encrypted.Length
            ];

            Buffer.BlockCopy(
                aes.IV,
                0,
                result,
                0,
                aes.IV.Length
            );

            Buffer.BlockCopy(
                encrypted,
                0,
                result,
                aes.IV.Length,
                encrypted.Length
            );

            return result;
        }

        public byte[] DecryptFile(byte[] encryptedFile, string key)
        {
            byte[] keyBytes = SHA256.HashData(
                Encoding.UTF8.GetBytes(key)
            );

            using Aes aes = Aes.Create();

            aes.Key = keyBytes;

            byte[] iv = new byte[aes.BlockSize / 8];

            byte[] cipherText = new byte[
                encryptedFile.Length - iv.Length
            ];

            Buffer.BlockCopy(
                encryptedFile,
                0,
                iv,
                0,
                iv.Length
            );

            Buffer.BlockCopy(
                encryptedFile,
                iv.Length,
                cipherText,
                0,
                cipherText.Length
            );

            aes.IV = iv;

            using ICryptoTransform decryptor = aes.CreateDecryptor();

            return decryptor.TransformFinalBlock(
                cipherText,
                0,
                cipherText.Length
            );
        }
    }
}