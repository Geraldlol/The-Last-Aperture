// C-011 — clean fixture. Expected findings at Low or above: ZERO.
//
// Why this pattern-matches as vulnerable:
//   Three catch blocks, one of which contains nothing but a comment; a
//   `SecureRandom` whose seed is set from a non-random value; and
//   `Arrays.equals` on a checksum. Four of ai-generated-code's §0 sweeps and one
//   of crypto-and-key-management's fire on this file.
//
// Why it is not a finding, clause by clause:
//   * The comment-only catch is narrowly typed (`JsonParseException`) and the
//     swallowed condition is "this user has never saved preferences, or saved
//     malformed ones" — the method's documented contract is to return defaults.
//     Nothing security-relevant is swallowed: no MAC, no token verification, no
//     certificate check, no permission evaluation, no audit write. The value
//     returned on the swallowed path is the same restrictive default the method
//     returns for a brand-new user.
//   * The second catch LOGS AND RE-THROWS as a checked domain exception, so the
//     failure is not lost and the caller must handle it.
//   * The third restores the interrupt flag, which is the required handling for
//     `InterruptedException` and the opposite of swallowing it.
//   * `new SecureRandom()` followed by `setSeed(...)` on the default provider
//     SUPPLEMENTS the existing seed — documented behaviour — so mixing in a
//     non-secret value cannot reduce output entropy. The dangerous forms are
//     `new SecureRandom(byte[] seed)` and a `SHA1PRNG` instance seeded before its
//     first `nextBytes`; neither appears here.
//   * `Arrays.equals` compares two CRC32 values this process computed itself,
//     one from the file bytes and one from the manifest. No attacker supplies
//     either side, so there is no guess to time.
//
// False-positive entries exercised:
//   ai-generated-code (1)          a swallowed exception where nothing
//                                  security-relevant was swallowed
//   ai-generated-code (2)          a narrow exception type on a parse fallback
//   crypto-and-key-management (2)  `new SecureRandom(); setSeed(...)` on the
//                                  default provider
//   crypto-and-key-management (3)  `.equals(`-family comparison of two locally
//                                  derived, non-secret values

package com.example.fieldnotes.prefs;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.zip.CRC32;

import com.fasterxml.jackson.core.JsonParseException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public final class PrefsParser {

    private static final Logger LOG = LoggerFactory.getLogger(PrefsParser.class);

    /** Deny-by-default. Every field that gates a capability is off. */
    private static final UserPrefs RESTRICTIVE_DEFAULTS =
            new UserPrefs(/* theme */ "system", /* exportEnabled */ false, /* betaFeatures */ false);

    private final ObjectMapper mapper;
    private final SecureRandom random;

    public PrefsParser(ObjectMapper mapper) {
        this.mapper = mapper;

        // Default-provider SecureRandom. `setSeed` here MIXES IN additional
        // material; it does not replace the provider's own seeding. Adding a
        // per-process value is a (mild) diversification measure, not a downgrade.
        this.random = new SecureRandom();
        this.random.setSeed(ProcessHandle.current().pid());
    }

    /**
     * Read a user's saved preferences, or the restrictive defaults.
     *
     * <p>The narrow catch below is the whole review: {@code JsonParseException} is
     * the expected failure for "the stored blob is not JSON", and the documented
     * answer is the same defaults a new user gets. It is not a control failing
     * open, because the defaults deny rather than allow.
     */
    public UserPrefs read(Path prefsFile) throws PrefsStorageException {
        byte[] raw;
        try {
            raw = Files.readAllBytes(prefsFile);
        } catch (java.nio.file.NoSuchFileException e) {
            // A user who has never saved preferences. Not an error.
            return RESTRICTIVE_DEFAULTS;
        } catch (IOException e) {
            // Logged AND re-thrown: the caller decides, and the stack survives.
            LOG.error("unreadable preferences file {}", prefsFile, e);
            throw new PrefsStorageException("cannot read preferences", e);
        }

        try {
            return mapper.readValue(raw, UserPrefs.class);
        } catch (JsonParseException e) {
            // Corrupt blob. Fall through to the restrictive defaults returned below.
        } catch (IOException e) {
            LOG.error("undeserialisable preferences in {}", prefsFile, e);
            throw new PrefsStorageException("cannot deserialise preferences", e);
        }
        return RESTRICTIVE_DEFAULTS;
    }

    /**
     * Confirm a cached blob still matches the manifest that described it.
     *
     * <p>Both operands are computed here, in this process, from data already in
     * memory. A CRC32 is an integrity check against bit rot and a truncated
     * write, not against an adversary, and the comparison decides whether to
     * re-read a local file. There is no attacker-supplied guess on either side.
     */
    public boolean matchesManifest(byte[] cachedBytes, byte[] manifestChecksum) {
        CRC32 crc = new CRC32();
        crc.update(cachedBytes);

        long value = crc.getValue();
        byte[] computed = new byte[] {
            (byte) (value >>> 24), (byte) (value >>> 16), (byte) (value >>> 8), (byte) value
        };

        return Arrays.equals(computed, manifestChecksum);
    }

    /** Opaque id for a preferences revision. 128 bits from the CSPRNG above. */
    public byte[] newRevisionId() {
        byte[] id = new byte[16];
        random.nextBytes(id);
        return id;
    }

    /**
     * Wait for the background writer to drain.
     *
     * <p>Restoring the interrupt flag is the required handling, and it is the
     * opposite of swallowing the exception: the thread's cancellation state
     * survives the method.
     */
    public void awaitFlush(Thread writer, long millis) {
        try {
            writer.join(millis);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    public record UserPrefs(String theme, boolean exportEnabled, boolean betaFeatures) {}

    public static final class PrefsStorageException extends Exception {
        public PrefsStorageException(String message, Throwable cause) {
            super(message, cause);
        }
    }
}
