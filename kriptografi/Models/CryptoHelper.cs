using System.Security.Cryptography;
using System.Text;

namespace kriptografi.Models
{
    public static class CryptoHelper
    {
        public static (string publicKey, string privateKey) GenerateRSAKeys()
        {
            try
            {
                using (var rsa = new RSACryptoServiceProvider(2048))
                {
                    try
                    {
                        var publicKey = Convert.ToBase64String(rsa.ExportRSAPublicKey());
                        var privateKey = Convert.ToBase64String(rsa.ExportRSAPrivateKey());
                        return (publicKey, privateKey);
                    }
                    finally
                    {
                        rsa.PersistKeyInCsp = false;
                    }
                }
            }
            catch (Exception ex)
            {
                throw new Exception($"Anahtar oluşturma hatası: {ex.Message}");
            }
        }

        public static string EncryptRSA(string plainText, string publicKey)
        {
            try
            {
                using (var rsa = new RSACryptoServiceProvider())
                {
                    rsa.ImportRSAPublicKey(Convert.FromBase64String(publicKey), out _);
                    byte[] dataToEncrypt = Encoding.UTF8.GetBytes(plainText);
                    byte[] encryptedData = rsa.Encrypt(dataToEncrypt, true);
                    return Convert.ToBase64String(encryptedData);
                }
            }
            catch (Exception ex)
            {
                throw new Exception($"Şifreleme hatası: {ex.Message}");
            }
        }

        public static string DecryptRSA(string cipherText, string privateKey)
        {
            try
            {
                using (var rsa = new RSACryptoServiceProvider())
                {
                    rsa.ImportRSAPrivateKey(Convert.FromBase64String(privateKey), out _);
                    byte[] dataToDecrypt = Convert.FromBase64String(cipherText);
                    byte[] decryptedData = rsa.Decrypt(dataToDecrypt, true);
                    return Encoding.UTF8.GetString(decryptedData);
                }
            }
            catch (Exception ex)
            {
                throw new Exception($"Şifre çözme hatası: {ex.Message}");
            }
        }

        public static string CalculateSHA256(string input)
        {
            using (SHA256 sha256 = SHA256.Create())
            {
                byte[] bytes = Encoding.UTF8.GetBytes(input);
                byte[] hash = sha256.ComputeHash(bytes);
                return BitConverter.ToString(hash).Replace("-", "").ToLower();
            }
        }

        public static string CalculateFileSHA256(IFormFile file)
        {
            using (SHA256 sha256 = SHA256.Create())
            using (var stream = file.OpenReadStream())
            {
                byte[] hash = sha256.ComputeHash(stream);
                return BitConverter.ToString(hash).Replace("-", "").ToLower();
            }
        }

        public static (string key, string iv) GenerateAesKey()
        {
            try
            {
                using (Aes aes = Aes.Create())
                {
                    aes.GenerateKey();
                    aes.GenerateIV();
                    return (
                        Convert.ToBase64String(aes.Key),
                        Convert.ToBase64String(aes.IV)
                    );
                }
            }
            catch (Exception ex)
            {
                throw new Exception($"AES anahtar oluşturma hatası: {ex.Message}");
            }
        }

        public static string EncryptAES(string plainText, string key, string iv)
        {
            try
            {
                using (Aes aes = Aes.Create())
                {
                    aes.Key = Convert.FromBase64String(key);
                    aes.IV = Convert.FromBase64String(iv);

                    ICryptoTransform encryptor = aes.CreateEncryptor();

                    using (MemoryStream msEncrypt = new MemoryStream())
                    {
                        using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                        using (StreamWriter swEncrypt = new StreamWriter(csEncrypt))
                        {
                            swEncrypt.Write(plainText);
                        }

                        return Convert.ToBase64String(msEncrypt.ToArray());
                    }
                }
            }
            catch (Exception ex)
            {
                throw new Exception($"AES şifreleme hatası: {ex.Message}");
            }
        }

        public static string DecryptAES(string cipherText, string key, string iv)
        {
            try
            {
                using (Aes aes = Aes.Create())
                {
                    aes.Key = Convert.FromBase64String(key);
                    aes.IV = Convert.FromBase64String(iv);

                    ICryptoTransform decryptor = aes.CreateDecryptor();

                    using (MemoryStream msDecrypt = new MemoryStream(Convert.FromBase64String(cipherText)))
                    using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                    using (StreamReader srDecrypt = new StreamReader(csDecrypt))
                    {
                        return srDecrypt.ReadToEnd();
                    }
                }
            }
            catch (Exception ex)
            {
                throw new Exception($"AES şifre çözme hatası: {ex.Message}");
            }
        }

        public static async Task<string> CalculateFileSHA256Async(IFormFile file)
        {
            using (var memoryStream = new MemoryStream())
            {
                await file.CopyToAsync(memoryStream);
                memoryStream.Position = 0;

                using (var sha256 = SHA256.Create())
                {
                    byte[] hashBytes = sha256.ComputeHash(memoryStream);
                    StringBuilder builder = new StringBuilder();
                    for (int i = 0; i < hashBytes.Length; i++)
                    {
                        builder.Append(hashBytes[i].ToString("x2"));
                    }
                    return builder.ToString();
                }
            }
        }
    }
} 