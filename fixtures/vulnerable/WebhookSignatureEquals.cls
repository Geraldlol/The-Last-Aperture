/**
 * V-014 — FIXTURE — fixtures/vulnerable/WebhookSignatureEquals.cls
 *
 * Bug class (one per file): timing-unsafe comparison of an attacker-supplied
 * webhook signature. The MAC is computed correctly — right primitive, right key
 * source, raw bytes, timestamp bound in and checked — and then compared with a
 * short-circuiting operator, which is the entire defect.
 *
 * Lens:      crypto-and-key-management
 * Topic:     hmac-and-constant-time-comparison
 * Expected:  High
 * CWE:       CWE-208
 * Fires:     severity row "Timing-unsafe comparison of an attacker-supplied MAC,
 *            signature, API key, TOTP code or reset token → High", on its Apex
 *            clause: a `.cls` comparing a request signature with `!=` and calling
 *            neither the built-in comparator nor a verified local helper. All
 *            four re-grade conditions hold — the value arrives in a header,
 *            server-computed MAC, no per-identity attempt cap appears in this
 *            class or in front of it, and the operand is attacker-supplied.
 *
 * This file has a clean pair in fixtures/clean/ — the same verifier with the
 * comparison routed through a length-checked branch-free accumulator — and it is
 * deliberately referred to by row ID rather than by a plausible helper symbol.
 * An earlier draft proved that an unqualified clearing token in a file name or
 * comment could silence this candidate. The current safe list qualifies that API,
 * but the row-ID convention remains as a guard against reintroducing the collision.
 * EXPECTED.md row C-033 names the pair. This file calls neither the built-in
 * comparator nor a verified local fallback.
 *
 * EDITING WARNING — name no member of the §0 constant-time safe list in this file,
 * in code or in a comment, and add none of the project-local helper names §0's
 * Apex arm enumerates either. Both lists are in the lens and are deliberately not
 * quoted here: the absence sweep clears on a token found anywhere in the file, and
 * the helper arm is what separates this fixture from its clean pair, so either
 * edit would silently disarm this file while leaving it exactly as vulnerable.
 *
 * Inert: no meta.xml, no sfdx-project.json, no DML, no SOQL. The urlMapping is a
 * string inside fixtures/, which no org reads; MessageStatusRouter and
 * Webhook_Secret__mdt are not defined anywhere in this repository, so this file
 * cannot compile, let alone deploy. No credential literal, by corpus rule.
 */
@RestResource(urlMapping='/inbound/message-status/*')
global with sharing class WebhookSignatureEquals {

    private static final Long TOLERANCE_MS = 300000L;

    @HttpPost
    global static void handleStatusCallback() {
        RestRequest req = RestContext.request;
        String givenSignature = req.headers.get('X-Provider-Signature');
        String sentAtHeader = req.headers.get('X-Provider-Timestamp');
        if (String.isBlank(givenSignature) || String.isBlank(sentAtHeader)) {
            RestContext.response.statusCode = 401;
            return;
        }

        Long sentAt = Long.valueOf(sentAtHeader);
        if (Math.abs(System.currentTimeMillis() - sentAt) > TOLERANCE_MS) {
            RestContext.response.statusCode = 401;
            return;
        }

        Blob signed = Blob.valueOf(sentAtHeader + '.' + req.requestBody.toString());
        Blob mac = Crypto.generateMac('hmacSHA256', signed, signingKey());
        String expectedSignature = EncodingUtil.base64Encode(mac);

        // THE DEFECT. String inequality in Apex stops at the first differing
        // character, so the time this branch takes tells the caller how many
        // leading characters of its guess were right. Production code should use
        // the platform comparator; a verified project-local helper is the legacy
        // fallback, and this file deliberately calls neither.
        if (givenSignature != expectedSignature) {
            RestContext.response.statusCode = 401;
            return;
        }

        MessageStatusRouter.dispatch(req.requestBody.toString());
        RestContext.response.statusCode = 204;
    }

    private static Blob signingKey() {
        Webhook_Secret__mdt row = Webhook_Secret__mdt.getInstance('Inbound_Status');
        return EncodingUtil.base64Decode(row.Key_Material__c);
    }
}
