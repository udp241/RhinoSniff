using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using Newtonsoft.Json;

namespace RhinoSniff.Classes
{
    public static class Security
    {
        private const int SaltSize = 16;
        private const int KeySize = 32;
        private const int IvSize = 16;
        private const int Iterations = 100_000;
        private static readonly HashAlgorithmName HashAlg = HashAlgorithmName.SHA256;

        private static readonly string SaltFilePath = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
            "RhinoSniff", ".install_salt");

        /// <summary>
        /// Per-install salt protected by DPAPI (CurrentUser scope).
        /// Data is bound to the current Windows user on this machine.
        /// </summary>
        private static byte[] GetOrCreateInstallSalt()
        {
            var dir = Path.GetDirectoryName(SaltFilePath);
            if (!Directory.Exists(dir))
                Directory.CreateDirectory(dir!);

            if (File.Exists(SaltFilePath))
            {
                var protectedSalt = File.ReadAllBytes(SaltFilePath);
                return ProtectedData.Unprotect(protectedSalt, null, DataProtectionScope.CurrentUser);
            }

            var salt = RandomNumberGenerator.GetBytes(SaltSize);
            var protectedBytes = ProtectedData.Protect(salt, null, DataProtectionScope.CurrentUser);
            File.WriteAllBytes(SaltFilePath, protectedBytes);
            return salt;
        }

        private static byte[] DeriveKey(string passphrase, byte[] salt)
        {
            using var kdf = new Rfc2898DeriveBytes(passphrase, salt, Iterations, HashAlg);
            return kdf.GetBytes(KeySize);
        }

        /// <summary>
        /// AES-256-CBC with random IV prepended. Key derived from machine-bound passphrase.
        /// </summary>
        public static string Encrypt(string input)
        {
            try
            {
                var installSalt = GetOrCreateInstallSalt();
                var passphrase = $"RhinoSniff_{Environment.MachineName}_{Environment.UserName}";
                var key = DeriveKey(passphrase, installSalt);

                var clearBytes = Encoding.UTF8.GetBytes(input);
                using var aes = Aes.Create();
                aes.Key = key;
                aes.GenerateIV();
                aes.Mode = CipherMode.CBC;
                aes.Padding = PaddingMode.PKCS7;

                using var ms = new MemoryStream();
                ms.Write(aes.IV, 0, IvSize);
                using (var cs = new CryptoStream(ms, aes.CreateEncryptor(), CryptoStreamMode.Write))
                {
                    cs.Write(clearBytes, 0, clearBytes.Length);
                    cs.FlushFinalBlock();
                }
                return Convert.ToBase64String(ms.ToArray());
            }
            catch (Exception e)
            {
                _ = e.AutoDumpExceptionAsync();
                return JsonConvert.SerializeObject(new { error = "Encryption failed" });
            }
        }

        public static async Task<string> EncryptAsync(string input)
        {
            return await Task.Run(() => Encrypt(input));
        }

        public static string Decrypt(string input)
        {
            try
            {
                input = input.Replace(" ", "+");
                var cipherWithIv = Convert.FromBase64String(input);
                if (cipherWithIv.Length < IvSize + 1)
                    return JsonConvert.SerializeObject(new { error = "Invalid ciphertext" });

                var installSalt = GetOrCreateInstallSalt();
                var passphrase = $"RhinoSniff_{Environment.MachineName}_{Environment.UserName}";
                var key = DeriveKey(passphrase, installSalt);

                var iv = new byte[IvSize];
                Buffer.BlockCopy(cipherWithIv, 0, iv, 0, IvSize);
                var cipher = new byte[cipherWithIv.Length - IvSize];
                Buffer.BlockCopy(cipherWithIv, IvSize, cipher, 0, cipher.Length);

                using var aes = Aes.Create();
                aes.Key = key;
                aes.IV = iv;
                aes.Mode = CipherMode.CBC;
                aes.Padding = PaddingMode.PKCS7;

                using var ms = new MemoryStream();
                using (var cs = new CryptoStream(ms, aes.CreateDecryptor(), CryptoStreamMode.Write))
                {
                    cs.Write(cipher, 0, cipher.Length);
                    cs.FlushFinalBlock();
                }
                return Encoding.UTF8.GetString(ms.ToArray());
            }
            catch (Exception e)
            {
                _ = e.AutoDumpExceptionAsync();
                return JsonConvert.SerializeObject(new { error = "Decryption failed" });
            }
        }

        public static async Task<string> DecryptAsync(string input)
        {
            return await Task.Run(() => Decrypt(input));
        }

        /// <summary>
        /// Theme encryption uses a portable passphrase so themes work across users.
        /// Salt is embedded in output (first 16 bytes before IV).
        /// </summary>
        public static async Task<string> EncryptThemeAsync(string input)
        {
            return await Task.Run(() =>
            {
                try
                {
                    const string themePassphrase = "RhinoSniff_ThemeExport_v1";
                    var salt = RandomNumberGenerator.GetBytes(SaltSize);
                    var key = DeriveKey(themePassphrase, salt);
                    var clearBytes = Encoding.UTF8.GetBytes(input);

                    using var aes = Aes.Create();
                    aes.Key = key;
                    aes.GenerateIV();
                    aes.Mode = CipherMode.CBC;
                    aes.Padding = PaddingMode.PKCS7;

                    using var ms = new MemoryStream();
                    ms.Write(salt, 0, SaltSize);
                    ms.Write(aes.IV, 0, IvSize);
                    using (var cs = new CryptoStream(ms, aes.CreateEncryptor(), CryptoStreamMode.Write))
                    {
                        cs.Write(clearBytes, 0, clearBytes.Length);
                        cs.FlushFinalBlock();
                    }
                    return Convert.ToBase64String(ms.ToArray());
                }
                catch (Exception e)
                {
                    _ = e.AutoDumpExceptionAsync();
                    return JsonConvert.SerializeObject(new { error = "Encryption failed" });
                }
            });
        }

        public static async Task<string> DecryptThemeAsync(string input)
        {
            return await Task.Run(() =>
            {
                try
                {
                    input = input.Replace(" ", "+");
                    const string themePassphrase = "RhinoSniff_ThemeExport_v1";
                    var data = Convert.FromBase64String(input);
                    if (data.Length < SaltSize + IvSize + 1)
                        return JsonConvert.SerializeObject(new { error = "Invalid theme data" });

                    var salt = new byte[SaltSize];
                    Buffer.BlockCopy(data, 0, salt, 0, SaltSize);
                    var iv = new byte[IvSize];
                    Buffer.BlockCopy(data, SaltSize, iv, 0, IvSize);
                    var cipher = new byte[data.Length - SaltSize - IvSize];
                    Buffer.BlockCopy(data, SaltSize + IvSize, cipher, 0, cipher.Length);

                    var key = DeriveKey(themePassphrase, salt);

                    using var aes = Aes.Create();
                    aes.Key = key;
                    aes.IV = iv;
                    aes.Mode = CipherMode.CBC;
                    aes.Padding = PaddingMode.PKCS7;

                    using var ms = new MemoryStream();
                    using (var cs = new CryptoStream(ms, aes.CreateDecryptor(), CryptoStreamMode.Write))
                    {
                        cs.Write(cipher, 0, cipher.Length);
                        cs.FlushFinalBlock();
                    }
                    return Encoding.UTF8.GetString(ms.ToArray());
                }
                catch (Exception e)
                {
                    _ = e.AutoDumpExceptionAsync();
                    return JsonConvert.SerializeObject(new { error = "Decryption failed" });
                }
            });
        }
    }
}
