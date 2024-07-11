using System;
using System.Collections;
using System.Security.Cryptography;
using System.Text;

public class PasswordHelper
{
    
    private static byte[] GenerateSalt(int length)
    {
        using (var rng = new RNGCryptoServiceProvider())
        {
            var salt = new byte[length];
            rng.GetBytes(salt);
            return salt;
        }
    }

    
    public static string HashPassword(string password, out string salt)
    {
        salt = Convert.ToBase64String(GenerateSalt(16)); // 16 byte uzunluğunda salt oluştur
        byte[] passwordBytes = Encoding.UTF8.GetBytes(password);
        byte[] saltBytes = Convert.FromBase64String(salt);

        byte[] combinedBytes = new byte[passwordBytes.Length + saltBytes.Length];
        Array.Copy(passwordBytes, 0, combinedBytes, 0, passwordBytes.Length);
        Array.Copy(saltBytes, 0, combinedBytes, passwordBytes.Length, saltBytes.Length);

        using (var sha256 = SHA256.Create())
        {
            byte[] hashBytes = sha256.ComputeHash(combinedBytes);
            return Convert.ToBase64String(hashBytes);
        }
    }

    
    public static bool VerifyPassword(string enteredPassword, string storedHash, string storedSalt)
    {
        byte[] hashBytes = Convert.FromBase64String(storedHash);
        byte[] saltBytes = Convert.FromBase64String(storedSalt);

        byte[] enteredPasswordBytes = Encoding.UTF8.GetBytes(enteredPassword);
        byte[] combinedBytes = new byte[enteredPasswordBytes.Length + saltBytes.Length];
        Array.Copy(enteredPasswordBytes, 0, combinedBytes, 0, enteredPasswordBytes.Length);
        Array.Copy(saltBytes, 0, combinedBytes, enteredPasswordBytes.Length, saltBytes.Length);

        using (var sha256 = SHA256.Create())
        {
            byte[] computedHash = sha256.ComputeHash(combinedBytes);
            return StructuralComparisons.StructuralEqualityComparer.Equals(hashBytes, computedHash);
        }
    }
}
