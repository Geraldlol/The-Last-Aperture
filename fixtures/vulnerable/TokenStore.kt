// V-011 — VULNERABLE fixture. NOT RUNNABLE. Written from scratch.
//
// Bug class (exactly one): a refresh token written to an unencrypted local store
// on a mobile device.
// Lens: mobile-app-security / topic `mobile-local-data-storage`
// Expected: High, CWE-312
//
// `SharedPreferences` is the intended store for non-secret local state, and the
// owning lens says so — theme, locale, onboarding flags. It is a finding here
// because of WHAT is written to it, not because it is used: a refresh token, which
// is a long-lived bearer credential, plus the user identifier it belongs to. On a
// rooted or backed-up device the file is readable as plain XML.
//
// The private-mode flag is not encryption. `MODE_PRIVATE` scopes the file to the
// application's uid and does nothing once that boundary is gone, which is the
// threat this row is about.
//
// Deliberately NOT in this file, so the fixture carries one bug class only: no
// trust-all TLS, no cleartext-traffic policy, no WebView, no exported component,
// no deep-link handler, no logging of the token.
//
// NOT RUNNABLE: no Gradle module, no manifest, no Android SDK on the path, and no
// token value in the file. `Context` is the platform type and is never
// constructed here.

package fixtures.vulnerable

import android.content.Context
import android.content.SharedPreferences

/**
 * Persists the tokens the app needs across launches.
 *
 * The access token is short-lived and is held in memory only. The refresh token
 * is the durable credential, and it is the one written to disk in the clear.
 */
class TokenStore(context: Context) {

    private val prefs: SharedPreferences =
        context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)

    private var accessTokenInMemory: String? = null

    fun saveSession(accessToken: String, refreshToken: String, userId: String) {
        accessTokenInMemory = accessToken

        // --- the finding -----------------------------------------------------
        // A bearer credential and the identity it authenticates, written as
        // plain XML under the app's data directory. Nothing wraps the value and
        // nothing derives a key for it.
        prefs.edit()
            .putString(KEY_REFRESH_TOKEN, refreshToken)
            .putString(KEY_USER_ID, userId)
            .putLong(KEY_SAVED_AT, System.currentTimeMillis())
            .apply()
        // --- end of the finding ----------------------------------------------
    }

    fun refreshToken(): String? = prefs.getString(KEY_REFRESH_TOKEN, null)

    fun accessToken(): String? = accessTokenInMemory

    fun clear() {
        accessTokenInMemory = null
        prefs.edit().clear().apply()
    }

    private companion object {
        const val PREFS_NAME = "session_prefs"
        const val KEY_REFRESH_TOKEN = "refresh_token"
        const val KEY_USER_ID = "user_id"
        const val KEY_SAVED_AT = "saved_at"
    }
}
