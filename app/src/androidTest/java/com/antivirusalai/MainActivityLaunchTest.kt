package com.antivirusalai

import android.content.Intent
import android.graphics.BitmapFactory
import android.view.ViewGroup
import androidx.test.core.app.ActivityScenario
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import androidx.work.WorkManager
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class MainActivityLaunchTest {
    @Test
    fun workManagerIsInitializedBeforeComposeRequestsIt() {
        ActivityScenario.launch(MainActivity::class.java).use { scenario ->
            InstrumentationRegistry.getInstrumentation().waitForIdleSync()
            scenario.onActivity { activity ->
                assertNotNull(WorkManager.getInstance(activity.applicationContext))
            }
        }
    }

    @Test
    fun guardianArtworkResourceDecodesToBitmap() {
        ActivityScenario.launch(MainActivity::class.java).use { scenario ->
            InstrumentationRegistry.getInstrumentation().waitForIdleSync()
            scenario.onActivity { activity ->
                val bitmap = requireNotNull(
                    BitmapFactory.decodeResource(
                        activity.resources,
                        R.drawable.guardian_robot
                    )
                ) { "Guardian robot drawable did not decode to a Bitmap on Android" }
                assertTrue("Guardian robot bitmap must have a valid width", bitmap.width > 0)
                assertTrue("Guardian robot bitmap must have a valid height", bitmap.height > 0)
            }
        }
    }

    @Test
    fun launcherActivityAttachesItsComposeContentAfterStartup() {
        val targetContext = InstrumentationRegistry.getInstrumentation().targetContext
        val launchIntent = requireNotNull(
            targetContext.packageManager.getLaunchIntentForPackage(targetContext.packageName)
        ) { "The app must expose a launcher activity." }.apply {
            addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TASK)
        }

        // startActivitySync waits for the main looper to become idle. That is a
        // stronger condition than Activity startup and can time out while the
        // Compose UI is still scheduling work. ActivityScenario waits for the
        // Activity lifecycle instead, then lets this test inspect the attached
        // content on the main thread without treating queue idleness as success.
        ActivityScenario.launch<MainActivity>(launchIntent).use { scenario ->
            scenario.onActivity { activity ->
                assertNotNull("The launcher Activity must create a window.", activity.window)
                val content = activity.findViewById<ViewGroup>(android.R.id.content)
                assertNotNull("The Activity content host must exist.", content)
                assertTrue(
                    "setContent must attach a content view before startup is considered successful.",
                    content.childCount > 0
                )
                assertTrue(
                    "The Compose content root must be attached to the active window.",
                    content.getChildAt(0).isAttachedToWindow
                )
            }
        }
    }
}
