// C-017 — clean fixture. Expected findings at Low or above: ZERO.
//
// Why this pattern-matches as vulnerable:
//   Three Luhn-valid card-shaped strings sit in this file, and a PAN regex is the
//   single most common automated finding in the payments domain. The file also
//   asserts on a stored brand and last four.
//
// Why it is not a finding:
//   `4242424242424242`, `4111111111111111` and `5555555555554444` are PUBLISHED
//   processor test numbers. They are documented on every gateway's testing page,
//   they are rejected by every acquirer, and they cannot authorize a transaction —
//   so they are not cardholder data and there is no account to compromise.
//   Flagging them is the most common automated false positive in this domain.
//
//   Brand plus last four is not a finding either. Display of a truncated PAN is
//   permitted up to the BIN and the last four, and this spec asserts exactly the
//   brand and the last four. Note the citations are different for the two halves:
//   DISPLAY is Req 3.4.1, and STORAGE of the expiration date and cardholder name
//   comes from the account-data table in Requirement 3 rather than from 3.4.1 —
//   so a finding that cites 3.4.1 for stored expiry is citing the wrong rule.
//
//   Nothing here persists sensitive authentication data. The CVC is typed into the
//   gateway's hosted field, never into an application input, and the last
//   assertion below is a negative control: it asserts the API response carries no
//   `cvc`, no `cvv`, no track data and no full PAN.
//
// False-positive entries exercised:
//   privacy-and-data-protection (3)  Luhn-valid processor test PANs in specs and
//                                    fixtures, and stored/displayed brand + last
//                                    four with the right requirement cited

import { expect, test } from "@playwright/test";

/**
 * Published gateway test numbers. Each is documented as a test value and is
 * declined by the network; none is a real account.
 */
const TEST_CARDS = {
  visaApproved: "4242424242424242",
  visaAlternate: "4111111111111111",
  mastercardApproved: "5555555555554444",
} as const;

const EXPIRY = "12/34";
const CVC = "123";

test.describe("checkout", () => {
  test("stores a payment method and shows brand plus last four", async ({ page }) => {
    await page.goto("/checkout");

    // The PAN is typed into the gateway's hosted iframe. It never touches an
    // input this application owns, so it never enters this application's DOM,
    // its state, its logs or its network requests.
    const hosted = page.frameLocator('iframe[title="Secure card entry"]');
    await hosted.locator('[name="cardnumber"]').fill(TEST_CARDS.visaApproved);
    await hosted.locator('[name="exp-date"]').fill(EXPIRY);
    await hosted.locator('[name="cvc"]').fill(CVC);

    await page.getByRole("button", { name: "Save card" }).click();

    // Truncated display. Brand and last four only.
    await expect(page.getByTestId("saved-card")).toHaveText("Visa ending 4242");
  });

  test("declines a card the gateway rejects", async ({ page }) => {
    await page.goto("/checkout");

    const hosted = page.frameLocator('iframe[title="Secure card entry"]');
    await hosted.locator('[name="cardnumber"]').fill(TEST_CARDS.mastercardApproved);
    await hosted.locator('[name="exp-date"]').fill("01/20");
    await hosted.locator('[name="cvc"]').fill(CVC);

    await page.getByRole("button", { name: "Save card" }).click();
    await expect(page.getByRole("alert")).toContainText("card has expired");
  });

  /**
   * Negative control. A clean fixture that only asserts the happy path proves
   * nothing about what is retained, so this asserts the absence directly.
   */
  test("the payment-method API returns no sensitive authentication data", async ({ request }) => {
    const res = await request.get("/api/payment-methods");
    expect(res.ok()).toBeTruthy();

    const body = await res.text();
    const parsed = JSON.parse(body) as Array<Record<string, unknown>>;

    for (const method of parsed) {
      expect(Object.keys(method).sort()).toEqual(["brand", "expMonth", "expYear", "id", "last4"]);
      expect(method).not.toHaveProperty("cvc");
      expect(method).not.toHaveProperty("cvv");
      expect(method).not.toHaveProperty("track1");
      expect(method).not.toHaveProperty("track2");
      expect(method).not.toHaveProperty("pan");
      expect(String(method.last4)).toMatch(/^\d{4}$/);
    }

    // No sixteen-digit run anywhere in the response.
    expect(body).not.toMatch(/\d{13,19}/);
  });
});
