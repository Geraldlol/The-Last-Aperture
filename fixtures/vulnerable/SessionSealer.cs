// V-005 — VULNERABLE fixture. NOT RUNNABLE. Written from scratch.
//
// Bug class (exactly one): unauthenticated ciphertext — nothing on the encrypt or
// decrypt path authenticates the bytes, and the decrypt path unpads and parses
// attacker-supplied input.
// Lens: crypto-and-key-management / topic `symmetric-encryption-and-nonce-handling`
// Expected: Critical, CWE-353
//
// `Aes.Create()` defaults to CBC with PKCS7, and nothing on the line says so —
// which is why the owning lens names the bare constructor as the artifact. The IV
// is a correct per-message random draw, and the finding stands anyway: the defect
// is the absence of integrity, not a weak IV. Under CBC an attacker who can flip
// IV bits flips the first plaintext block, and because Unseal deserialises
// whatever decrypts, the endpoint is a format oracle for a probing caller.
//
// NOTE for anyone editing this file: do not name an authenticated mode or a
// message-authentication primitive here, even in a comment. The owning lens's
// absence sweep clears any file whose text contains one, so a comment naming the
// fix would clear this fixture without changing the defect. That property is
// recorded in EXPECTED.md.
//
// NOT RUNNABLE: no project file, no entry point, no key. `KeyBytes` reads an
// environment variable that is not set anywhere in this repository, and there is
// no ciphertext sample and no tampering routine in the file.

using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace Fixtures.Vulnerable
{
    /// <summary>Seals a session record into a cookie value. Nothing verifies it.</summary>
    public static class SessionSealer
    {
        private static byte[] KeyBytes =>
            Convert.FromBase64String(
                Environment.GetEnvironmentVariable("SESSION_SEAL_KEY_B64") ?? string.Empty);

        public sealed class SessionRecord
        {
            public string UserId { get; set; } = string.Empty;
            public string Role { get; set; } = string.Empty;
            public long ExpiresAtUnix { get; set; }
        }

        public static string Seal(SessionRecord record)
        {
            using var aes = Aes.Create();
            aes.Key = KeyBytes;
            aes.GenerateIV();

            var plaintext = JsonSerializer.SerializeToUtf8Bytes(record);

            using var encryptor = aes.CreateEncryptor();
            var ciphertext = encryptor.TransformFinalBlock(plaintext, 0, plaintext.Length);

            // IV prepended in the clear, ciphertext appended, and nothing covers
            // either one. The cookie is handed to the browser exactly like this.
            var sealed_ = new byte[aes.IV.Length + ciphertext.Length];
            Buffer.BlockCopy(aes.IV, 0, sealed_, 0, aes.IV.Length);
            Buffer.BlockCopy(ciphertext, 0, sealed_, aes.IV.Length, ciphertext.Length);
            return Convert.ToBase64String(sealed_);
        }

        public static SessionRecord? Unseal(string cookieValue)
        {
            var blob = Convert.FromBase64String(cookieValue);

            using var aes = Aes.Create();
            aes.Key = KeyBytes;

            var iv = new byte[16];
            Buffer.BlockCopy(blob, 0, iv, 0, iv.Length);
            aes.IV = iv;

            using var decryptor = aes.CreateDecryptor();

            // Unpadding and JSON parsing both happen before anything has checked
            // that these bytes are the bytes this service produced — because
            // nothing in this type ever produced a check to make.
            var plaintext = decryptor.TransformFinalBlock(blob, iv.Length, blob.Length - iv.Length);
            return JsonSerializer.Deserialize<SessionRecord>(
                Encoding.UTF8.GetString(plaintext));
        }

        /// <summary>Reads the role out of a cookie. The authorization consumer.</summary>
        public static bool IsAdministrator(string cookieValue)
        {
            try
            {
                return Unseal(cookieValue)?.Role == "admin";
            }
            catch (CryptographicException)
            {
                return false;
            }
            catch (IOException)
            {
                return false;
            }
        }
    }
}
