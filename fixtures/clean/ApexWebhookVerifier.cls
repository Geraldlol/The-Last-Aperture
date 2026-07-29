/**
 * C-033 — FIXTURE — fixtures/clean/ApexWebhookVerifier.cls
 *
 * Reads as:  CWE-208, timing-unsafe comparison of a webhook signature. This file
 *            contains no call from the §0 constant-time safe list. Apex provides
 *            a built-in Blob comparator; this fixture deliberately exercises the
 *            verified legacy-local-helper read-to-clear path without naming it.
 *
 * Lens:      crypto-and-key-management
 * Topic:     hmac-and-constant-time-comparison
 * Expected:  no finding at Low or above.
 * Exercises: Known false positives (10), and the Apex clause of the severity row
 *            "Timing-unsafe comparison of an attacker-supplied MAC, signature,
 *            API key, TOTP code or reset token".
 *
 * Why the finding does not stand: the comparison below satisfies all four
 * conditions item 4 requires of a project-local Apex helper — length check
 * first (the expected width is a public constant, so it leaks nothing), then a
 * single pass over every byte of both operands, differences accumulated into
 * one Integer with no break, no return and no branch inside the loop, and the
 * verifier calling it on the value that arrived in the request. A preferred
 * built-in exists for production code; this fixture retains a correct local
 * helper solely to prove the manual read-to-clear path remains valid.
 *
 * The pair file is fixtures/vulnerable/WebhookSignatureEquals.cls, which is the
 * same verifier with the helper call replaced by `!=`. A rule that cannot
 * separate these two files is not measuring anything on Apex.
 *
 * EDITING WARNING — do not name any member of the §0 constant-time safe list in
 * this file, not even inside a comment, and do not quote the list here for the
 * reader's convenience. The absence sweep clears on a token found anywhere in the
 * file, comments included; the tokens are in the lens, and this fixture exists to
 * show that not one of them appears in correct Apex. Naming them here would clear
 * the file for the wrong reason and the fixture would stop measuring anything.
 *
 * Inert: no meta.xml, no sfdx-project.json, no @RestResource, no trigger, no DML,
 * no SOQL. Webhook_Secret__mdt is not defined anywhere in this repository, so this
 * file cannot compile, let alone deploy. No credential literal, by corpus rule.
 */
public with sharing class ApexWebhookVerifier {

    // Five minutes, in milliseconds. The freshness window is bound into the
    // signed string and compared below, so this fixture carries exactly one
    // subject — the comparison — and not a second, missing-timestamp defect.
    private static final Long TOLERANCE_MS = 300000L;

    /**
     * Length first, then one pass over the whole operand.
     *
     * `diff` is the accumulator. The loop body has no branch and no exit, so the
     * work done depends on the length of the operands and not on the position of
     * the first differing character. The early return above it compares lengths
     * only, which for a fixed-width base64 digest is public information.
     */
    public static Boolean equalsConstantTime(String given, String expected) {
        if (given == null || expected == null) {
            return false;
        }
        if (given.length() != expected.length()) {
            return false;
        }
        Integer diff = 0;
        for (Integer i = 0; i < expected.length(); i++) {
            diff |= given.charAt(i) ^ expected.charAt(i);
        }
        return diff == 0;
    }

    /**
     * The verifier. Reads the signature and the timestamp off the live request,
     * recomputes the MAC over the raw body rather than over a re-serialization,
     * and hands both values to the helper above — condition (4).
     */
    public static Boolean verifyCurrentRequest() {
        RestRequest req = RestContext.request;
        String givenSignature = req.headers.get('X-Provider-Signature');
        String sentAtHeader = req.headers.get('X-Provider-Timestamp');
        if (String.isBlank(givenSignature) || String.isBlank(sentAtHeader)) {
            return false;
        }

        Long sentAt = Long.valueOf(sentAtHeader);
        if (Math.abs(System.currentTimeMillis() - sentAt) > TOLERANCE_MS) {
            return false;
        }

        // Raw bytes, not a re-serialized body, and the timestamp is inside the
        // signed string rather than merely present in a header.
        Blob signed = Blob.valueOf(sentAtHeader + '.' + req.requestBody.toString());
        Blob mac = Crypto.generateMac('hmacSHA256', signed, signingKey());

        return equalsConstantTime(givenSignature, EncodingUtil.base64Encode(mac));
    }

    /**
     * The secret is a protected custom metadata field read at run time. No
     * literal appears in this file; the corpus forbids credential-shaped strings
     * whether they are valid or not.
     */
    private static Blob signingKey() {
        Webhook_Secret__mdt row = Webhook_Secret__mdt.getInstance('Inbound_Status');
        return EncodingUtil.base64Decode(row.Key_Material__c);
    }
}
