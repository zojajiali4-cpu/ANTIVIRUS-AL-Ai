package com.antivirusalai

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.After
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class InstalledAppInventoryConsentTest {
    private val context: Context = ApplicationProvider.getApplicationContext()

    @Before
    @After
    fun clearConsentForIsolation() {
        context.getSharedPreferences("alai-privacy-consent", Context.MODE_PRIVATE)
            .edit()
            .clear()
            .commit()
    }

    @Test
    fun inventoryConsentDefaultsToDenied() {
        assertFalse(InstalledAppInventoryConsent.isGranted(context))
    }

    @Test
    fun consentCanBeGrantedAndExplicitlyRevoked() {
        InstalledAppInventoryConsent.setGranted(context, true)
        assertTrue(InstalledAppInventoryConsent.isGranted(context))

        InstalledAppInventoryConsent.setGranted(context, false)
        assertFalse(InstalledAppInventoryConsent.isGranted(context))
    }
}
