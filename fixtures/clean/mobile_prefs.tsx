// C-030 — clean fixture. Expected findings at Low or above: ZERO.
//
// Three mobile reflexes, three discriminators. Read this file together with
// `fixtures/clean/android/app/build.gradle`, which is where the first one is
// established rather than assumed.
//
//   1. INSECURE-LOOKING CODE INSIDE `if (__DEV__)`. Lines 74-84 wire a debugging
//      bridge and log a request header. Metro folds `__DEV__` to `false` and
//      removes the branch WHEN THE BUNDLE IS BUILT WITH `dev: false`, which is the
//      stock release path — and that precondition is what makes the clearance
//      valid, so it is established from the build artifacts rather than inferred:
//        * `android/app/build.gradle` has no `project.ext.react`, no
//          `extraPackagerArgs`, no `--dev true` and no replaced `bundleCommand`,
//          so the Gradle release path runs the stock bundle command;
//        * there is no `eas.json` profile with `developmentClient: true` and no
//          debug `gradleCommand`/`buildConfiguration` anywhere in this fixture;
//        * `metro.config.js` sets no `transformerPath`, no
//          `transformer.babelTransformerPath` and no custom serializer;
//        * the guard is the LITERAL `__DEV__`, not a runtime read like
//          `config.debug` or a remote-config `process.env.NODE_ENV`, either of
//          which would survive the transform;
//        * and none of the guarded code is duplicated outside the guard.
//      `--minify false` is deliberately NOT cited either way: it is the normal
//      state of a Hermes release build. Nor is `minifierEnabled` mentioned, because
//      it is not a Metro option and an absent literal proves nothing.
//
//      What the entry warns about and this file avoids: there is NO string literal
//      inside the guard that would be worth extracting even if the branch shipped.
//      No staging token, no admin key, no trust-all flag — the guarded code reads
//      values it already has and prints them.
//
//   2. `AsyncStorage.setItem` USED AT ALL. Every key written here is non-secret
//      local UI state, and each is named and classified at the call site: a theme
//      name, a locale, an onboarding flag, a last-viewed screen id and a draft the
//      user typed. The session and refresh tokens are in `expo-secure-store`, and —
//      because a secure store used elsewhere clears nothing — BOTH tokens are
//      there, not one of the two.
//
//   3. A LONG HIGH-ENTROPY STRING IN A CONFIG FILE. `EXPO_PUBLIC_MAPS_KEY` and the
//      Sentry DSN are public client identifiers designed to ship in the binary.
//      The question the entry asks is whether the credential authorises privileged
//      reads or writes on its own, and the answer is recorded: the Maps key is
//      restricted by package name and signing-certificate fingerprint in the
//      provider console (`android:package` + SHA-1 restriction, plus a daily quota),
//      and a Sentry DSN can only submit events. The inverse — "it is in a config
//      file, so it must be public" — is explicitly not the argument: a
//      `service_role` key, a service-account JSON or a client secret would be a
//      finding in the same file, which is why none is here.
//
// False-positive entries exercised:
//   mobile-app-security (1)  insecure-looking code inside `if (__DEV__)`, with the
//                            `dev: false` precondition established
//   mobile-app-security (2)  AsyncStorage used for non-secret local state
//   mobile-app-security (3)  a public client identifier in a shipped config file

import AsyncStorage from "@react-native-async-storage/async-storage";
import * as SecureStore from "expo-secure-store";
import Constants from "expo-constants";

/** Non-secret local UI state. Each key is classified in the comment beside it. */
const PREF_KEYS = {
  theme: "pref.theme", //            "light" | "dark" | "system"
  locale: "pref.locale", //          BCP-47 tag
  onboarded: "pref.onboarded", //    "1" once the tour is finished
  lastScreen: "pref.lastScreen", //  route name, for restore-on-launch
  draftBody: "pref.draftBody", //    text the user typed and has not saved
} as const;

/** Credential-bearing values. Never AsyncStorage — both of them, not just one. */
const SECURE_KEYS = {
  accessToken: "auth.accessToken",
  refreshToken: "auth.refreshToken",
} as const;

export async function saveTheme(theme: "light" | "dark" | "system"): Promise<void> {
  await AsyncStorage.setItem(PREF_KEYS.theme, theme);
}

export async function saveDraft(body: string): Promise<void> {
  // The user's own unsaved text on their own device. Not a credential, not a
  // token, not a key, and not regulated data in this product.
  await AsyncStorage.multiSet([
    [PREF_KEYS.draftBody, body],
    [PREF_KEYS.lastScreen, "NoteEditor"],
  ]);
}

export async function saveSession(access: string, refresh: string): Promise<void> {
  // Both tokens. A secure store holding the access token while the refresh token
  // sits in AsyncStorage two files away is the shape that clears nothing.
  await SecureStore.setItemAsync(SECURE_KEYS.accessToken, access, {
    keychainAccessible: SecureStore.WHEN_UNLOCKED_THIS_DEVICE_ONLY,
    requireAuthentication: false,
  });
  await SecureStore.setItemAsync(SECURE_KEYS.refreshToken, refresh, {
    keychainAccessible: SecureStore.WHEN_UNLOCKED_THIS_DEVICE_ONLY,
    requireAuthentication: false,
  });
}

/**
 * Public client identifiers. Both ship in the binary by design.
 *
 * Maps key: restricted in the provider console to this package name and signing
 * certificate, with a daily request quota. On its own it authorises nothing but
 * map tiles for this app.
 * Sentry DSN: an ingest endpoint. It can submit events and read nothing.
 */
export const PUBLIC_CLIENT_IDS = {
  mapsKey: Constants.expoConfig?.extra?.EXPO_PUBLIC_MAPS_KEY as string,
  sentryDsn: "https://examplepublickey@o0.ingest.example.invalid/0",
  oauthClientId: "1043927481-3n8example.apps.exampleusercontent.invalid",
} as const;

export async function bootstrap(): Promise<void> {
  const theme = (await AsyncStorage.getItem(PREF_KEYS.theme)) ?? "system";
  const locale = (await AsyncStorage.getItem(PREF_KEYS.locale)) ?? "en-GB";

  if (__DEV__) {
    // Removed from the bundle by the `dev: false` transform on the stock release
    // path. Nothing here is worth extracting even if it were not: it prints values
    // this function already holds and enables a local inspector.
    // eslint-disable-next-line no-console
    console.log(`[boot] theme=${theme} locale=${locale}`);
    const { connectToDevTools } = await import("react-devtools-core");
    connectToDevTools({ host: "localhost", port: 8097 });
  }
}
