package com.antivirusalai

import android.content.Context

/**
 * Explicit, revocable in-app consent for reading the installed-app inventory
 * and inspecting readable base/split APK paths. This is separate from the
 * Android all-files special access setting.
 */
object InstalledAppInventoryConsent {
    private const val PREFS = "alai-privacy-consent"
    private const val KEY_GRANTED = "installed_app_inventory_granted"

    fun isGranted(context: Context): Boolean =
        context.applicationContext
            .getSharedPreferences(PREFS, Context.MODE_PRIVATE)
            .getBoolean(KEY_GRANTED, false)

    fun setGranted(context: Context, granted: Boolean) {
        check(
            context.applicationContext
                .getSharedPreferences(PREFS, Context.MODE_PRIVATE)
                .edit()
                .putBoolean(KEY_GRANTED, granted)
                .commit()
        ) { "Installed-app inventory consent could not be saved." }
    }
}
