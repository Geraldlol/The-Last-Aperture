// C-012 — clean fixture. Expected findings at Low or above: ZERO.
//
// Why this pattern-matches as vulnerable:
//   `Cipher.getInstance("AES/CBC/PKCS5Padding")` is the single most-flagged
//   crypto literal after ECB, and "hand-rolled AES-CBC with a separate HMAC" is
//   named as a misuse idiom in crypto-and-key-management's own signal list. The
//   file also contains an explicit MAC comparison.
//
// Why it is not a finding:
//   The construction is Encrypt-then-MAC, in the correct order, over the correct
//   bytes, with separated keys, and the MAC is verified BEFORE any decryption is
//   attempted. Specifically:
//
//     * two independent keys, derived by HKDF-Expand from one input keying
//       material with distinct `info` labels, so the encryption key and the MAC
//       key are cryptographically separated and neither can be substituted for
//       the other;
//     * a fresh 16-byte IV drawn from `SecureRandom` INSIDE the per-message
//       method — not a field, not a constant, not a constructor argument — so
//       there is no object-, class- or module-scope IV to reuse;
//     * the tag covers the version byte, the IV and the full ciphertext, in that
//       order, with the length of each fixed or prefixed, so no two distinct
//       messages produce the same MAC input (no canonicalisation ambiguity);
//     * on the decrypt path the tag is recomputed and compared with
//       `MessageDigest.isEqual` (constant-time) and the method RETURNS before
//       `doFinal` if it does not match — so a padding oracle has nothing to
//       answer. CBC's malleability and its padding oracle are both closed by
//       verifying first.
//
//   AES-CBC + HMAC-SHA256 in this order is a standard, still-recommended
//   construction. The finding shapes are MAC-then-Encrypt, Encrypt-and-MAC, a MAC
//   over the plaintext only, a MAC that omits the IV, a shared key for both
//   primitives, a non-constant-time tag comparison, and decrypting before
//   verifying. None of them is here.
//
// False-positive entries exercised:
//   crypto-and-key-management (absence sweep, item 3)  a CBC ciphertext WITH
//       authentication in the same file — the sweep's clearing list is what has
//       to fire here, and `Mac`/`Hmac` is in it
//   crypto-and-key-management (3)  a constant-time comparison the lens's own
//       safe list names (`MessageDigest.isEqual`)
//   crypto-and-key-management (1)  a fresh CSPRNG IV drawn per call, inside the
//       per-message function

package com.example.fieldnotes.crypto;

import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/** Authenticated encryption for at-rest field notes, built from CBC + HMAC. */
public final class CbcThenHmac {

    private static final byte VERSION = 0x02;
    private static final int IV_LEN = 16;
    private static final int TAG_LEN = 32;

    private static final String ENC_INFO = "fieldnotes/v2/aes-cbc";
    private static final String MAC_INFO = "fieldnotes/v2/hmac-sha256";

    private final SecretKeySpec encKey;
    private final SecretKeySpec macKey;
    private final SecureRandom random = new SecureRandom();

    /**
     * @param ikm 32 bytes of input keying material from the key service. Split
     *            below; never used directly as either key.
     */
    public CbcThenHmac(byte[] ikm) throws GeneralSecurityException {
        if (ikm.length < 32) {
            throw new IllegalArgumentException("input keying material too short");
        }
        this.encKey = new SecretKeySpec(hkdfExpand(ikm, ENC_INFO, 32), "AES");
        this.macKey = new SecretKeySpec(hkdfExpand(ikm, MAC_INFO, 32), "HmacSHA256");
    }

    /** One-block HKDF-Expand. Distinct `info` is what separates the two keys. */
    private static byte[] hkdfExpand(byte[] prk, String info, int length)
            throws GeneralSecurityException {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(prk, "HmacSHA256"));
        mac.update(info.getBytes(java.nio.charset.StandardCharsets.UTF_8));
        mac.update((byte) 0x01);
        return Arrays.copyOf(mac.doFinal(), length);
    }

    /**
     * Seal a plaintext.
     *
     * <p>Wire format: VERSION || IV(16) || CIPHERTEXT || TAG(32). The tag is
     * computed over VERSION || IV || CIPHERTEXT — everything that precedes it —
     * after encryption. That is Encrypt-then-MAC.
     */
    public byte[] seal(byte[] plaintext) throws GeneralSecurityException {
        // Fresh per message, drawn inside this method. Nothing outside this frame
        // can observe or reuse it.
        byte[] iv = new byte[IV_LEN];
        random.nextBytes(iv);

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, encKey, new IvParameterSpec(iv));
        byte[] ciphertext = cipher.doFinal(plaintext);

        byte[] tag = tagOver(iv, ciphertext);

        return ByteBuffer.allocate(1 + IV_LEN + ciphertext.length + TAG_LEN)
                .put(VERSION)
                .put(iv)
                .put(ciphertext)
                .put(tag)
                .array();
    }

    /**
     * Open a sealed blob, or throw.
     *
     * <p>The tag is verified first and the method returns before any decryption
     * is attempted, so an attacker who mutates the ciphertext gets one
     * indistinguishable failure and never a padding answer.
     */
    public byte[] open(byte[] sealed) throws GeneralSecurityException {
        if (sealed.length < 1 + IV_LEN + TAG_LEN || sealed[0] != VERSION) {
            throw new GeneralSecurityException("unrecognised sealed blob");
        }

        int ctLen = sealed.length - 1 - IV_LEN - TAG_LEN;
        byte[] iv = Arrays.copyOfRange(sealed, 1, 1 + IV_LEN);
        byte[] ciphertext = Arrays.copyOfRange(sealed, 1 + IV_LEN, 1 + IV_LEN + ctLen);
        byte[] presentedTag = Arrays.copyOfRange(sealed, 1 + IV_LEN + ctLen, sealed.length);

        byte[] expectedTag = tagOver(iv, ciphertext);

        // Constant-time. And decisive: nothing below runs unless it matches.
        if (!MessageDigest.isEqual(expectedTag, presentedTag)) {
            throw new GeneralSecurityException("authentication failed");
        }

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, encKey, new IvParameterSpec(iv));
        return cipher.doFinal(ciphertext);
    }

    /** Tag input is VERSION || IV || CIPHERTEXT — every byte that precedes the tag. */
    private byte[] tagOver(byte[] iv, byte[] ciphertext) throws GeneralSecurityException {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(macKey);
        mac.update(VERSION);
        mac.update(iv);
        mac.update(ciphertext);
        return mac.doFinal();
    }
}
