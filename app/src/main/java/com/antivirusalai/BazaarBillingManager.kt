package com.antivirusalai

import android.content.Context
import androidx.activity.ComponentActivity
import androidx.activity.result.ActivityResultRegistry
import com.antivirusalai.BuildConfig
import ir.cafebazaar.poolakey.Connection
import ir.cafebazaar.poolakey.Payment
import ir.cafebazaar.poolakey.entity.PurchaseState
import ir.cafebazaar.poolakey.config.PaymentConfiguration
import ir.cafebazaar.poolakey.config.SecurityCheck
import ir.cafebazaar.poolakey.entity.PurchaseInfo
import ir.cafebazaar.poolakey.entity.SkuDetails
import ir.cafebazaar.poolakey.request.PurchaseRequest
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

data class BazaarPlanOffer(
    val sku: String,
    val title: String,
    val description: String,
    val price: String
)

data class BazaarBillingState(
    val connected: Boolean = false,
    val loading: Boolean = false,
    val checkoutReady: Boolean = false,
    val offers: List<BazaarPlanOffer> = emptyList(),
    val trialAvailable: Boolean = false,
    val trialPeriodDays: Int = 0,
    val entitled: Boolean = false,
    val currentSku: String? = null,
    val expiresAtEpochMillis: Long? = null,
    val cloudAccessToken: String? = null,
    val message: String? = null
)

/**
 * Cafe Bazaar billing adapter. Poolakey performs the native Bazaar checkout and
 * product lookup; the first-party Worker independently verifies each purchase
 * before any PLUS entitlement or cloud capability is enabled.
 */
class BazaarBillingManager(
    private val activity: ComponentActivity,
    context: Context,
    private val onStateChanged: (BazaarBillingState) -> Unit
) {
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Main.immediate)
    private val payment = Payment(
        context = context.applicationContext,
        config = PaymentConfiguration(
            localSecurityCheck = SecurityCheck.Disable,
            shouldSupportSubscription = true
        )
    )
    private var connection: Connection? = null
    private var closed = false
    private var connected = false
    private var serverReady = false
    private var catalogLoaded = false
    private var statusLoaded = false
    private var offers: List<BazaarPlanOffer> = emptyList()
    private var trialAvailable = false
    private var trialPeriodDays = 0
    private var verificationJob: Job? = null
    private var state = BazaarBillingState()

    private val supportedSkus = setOf(
        BuildConfig.ALAI_BAZAAR_MONTHLY_SKU,
        BuildConfig.ALAI_BAZAAR_ANNUAL_SKU
    )

    fun connect() {
        if (closed || connection != null) return
        publish(state.copy(loading = true, message = null))
        connection = payment.connect {
            connectionSucceed {
                if (!closed) {
                    connected = true
                    publish(state.copy(connected = true, loading = true, message = null))
                    refresh()
                }
            }
            connectionFailed { _ ->
                connection = null
                if (!closed) {
                    connected = false
                    clearEntitlement(
                        "اتصال به پرداخت کافه‌بازار برقرار نشد. برای خرید باید برنامه بازار روی دستگاه نصب و وارد حساب شده باشد."
                    )
                }
            }
            disconnected {
                connection = null
                if (!closed) {
                    connected = false
                    clearEntitlement("اتصال پرداخت بازار قطع شد؛ برای ادامه دوباره تلاش کن.")
                }
            }
        }
    }

    fun refresh() {
        if (closed) return
        if (!connected) {
            connect()
            return
        }
        catalogLoaded = false
        statusLoaded = false
        serverReady = false
        offers = emptyList()
        trialAvailable = false
        trialPeriodDays = 0
        verificationJob?.cancel()
        publish(
            state.copy(
                loading = true,
                checkoutReady = false,
                offers = emptyList(),
                entitled = false,
                currentSku = null,
                expiresAtEpochMillis = null,
                cloudAccessToken = null,
                trialAvailable = false,
                trialPeriodDays = 0,
                message = null
            )
        )

        scope.launch {
            try {
                serverReady = withContext(Dispatchers.IO) {
                    BazaarBillingApi.billingStatus().checkoutReady
                }
            } catch (cancelled: CancellationException) {
                throw cancelled
            } catch (_: Exception) {
                serverReady = false
            } finally {
                statusLoaded = true
                finishRefresh()
            }
        }

        payment.getSubscriptionSkuDetails(supportedSkus.toList()) {
            getSkuDetailsSucceed { details ->
                if (closed) return@getSkuDetailsSucceed
                offers = details
                    .filter { it.sku in supportedSkus && it.type.equals("subs", ignoreCase = true) }
                    .distinctBy { it.sku }
                    .map { it.toPlanOffer() }
                catalogLoaded = true
                finishRefresh()
            }
            getSkuDetailsFailed { throwable ->
                if (closed) return@getSkuDetailsFailed
                catalogLoaded = true
                offers = emptyList()
                publish(state.copy(message = throwable.message?.take(180)
                    ?: "دریافت قیمت و طرح‌های بازار انجام نشد."))
                finishRefresh()
            }
        }

        payment.checkTrialSubscription {
            checkTrialSubscriptionSucceed { trial ->
                if (closed) return@checkTrialSubscriptionSucceed
                trialAvailable = trial.isAvailable && trial.trialPeriodDays > 0
                trialPeriodDays = trial.trialPeriodDays.coerceAtLeast(0)
                publish(
                    state.copy(
                        trialAvailable = trialAvailable,
                        trialPeriodDays = trialPeriodDays
                    )
                )
            }
            checkTrialSubscriptionFailed {
                if (!closed) {
                    trialAvailable = false
                    trialPeriodDays = 0
                    publish(state.copy(trialAvailable = false, trialPeriodDays = 0))
                }
            }
        }

        querySubscribedPurchases(showRestoreMessage = false)
    }

    fun restorePurchases() {
        if (closed || !connected) {
            publish(state.copy(message = "برای بازیابی اشتراک ابتدا به کافه‌بازار متصل شو."))
            connect()
            return
        }
        verificationJob?.cancel()
        publish(
            state.copy(
                loading = true,
                entitled = false,
                currentSku = null,
                expiresAtEpochMillis = null,
                cloudAccessToken = null,
                message = "در حال بازیابی و اعتبارسنجی اشتراک از کافه‌بازار…"
            )
        )
        querySubscribedPurchases(showRestoreMessage = true)
    }

    fun purchase(sku: String) {
        if (closed || !connected || !serverReady || !catalogLoaded ||
            sku !in supportedSkus || offers.none { it.sku == sku }) {
            publish(state.copy(message = "خرید تا زمان تأیید اتصال بازار، قیمت محصول و سرویس اعتبارسنجی فعال نمی‌شود."))
            return
        }
        if (state.entitled) {
            publish(state.copy(message = "یک اشتراک معتبر PLUS روی این حساب فعال است."))
            return
        }
        publish(state.copy(loading = true, message = null))
        val request = PurchaseRequest(
            productId = sku,
            payload = "antivirus-al-ai-v1"
        )
        payment.subscribeProduct(activity.activityResultRegistry, request) {
            purchaseFlowBegan {
                if (!closed) publish(state.copy(loading = true, message = "صفحه پرداخت کافه‌بازار باز شد."))
            }
            failedToBeginFlow { throwable ->
                if (!closed) publish(state.copy(
                    loading = false,
                    message = throwable.message?.take(180) ?: "باز کردن صفحه پرداخت بازار ناموفق بود."
                ))
            }
            purchaseSucceed { purchaseInfo ->
                if (closed) return@purchaseSucceed
                if (purchaseInfo.productId != sku ||
                    purchaseInfo.packageName != activity.packageName ||
                    purchaseInfo.purchaseState != PurchaseState.PURCHASED) {
                    clearEntitlement("اطلاعات خرید با محصول یا برنامه مطابقت ندارد؛ دسترسی PLUS فعال نشد.")
                } else {
                    verifyPurchases(listOf(purchaseInfo), showRestoreMessage = false)
                }
            }
            purchaseCanceled {
                if (!closed) publish(state.copy(loading = false, message = "پرداخت لغو شد؛ تغییری در اشتراک ایجاد نشد."))
            }
            purchaseFailed { throwable ->
                if (!closed) publish(state.copy(
                    loading = false,
                    entitled = false,
                    cloudAccessToken = null,
                    message = throwable.message?.take(180) ?: "خرید در کافه‌بازار ناموفق بود."
                ))
            }
        }
    }

    private fun querySubscribedPurchases(showRestoreMessage: Boolean) {
        if (closed || !connected) return
        payment.getSubscribedProducts {
            querySucceed { purchases ->
                if (closed) return@querySucceed
                val candidates = purchases
                    .filter {
                        it.productId in supportedSkus &&
                            it.packageName == activity.packageName &&
                            it.purchaseState == PurchaseState.PURCHASED
                    }
                    .sortedByDescending { it.purchaseTime }
                if (candidates.isEmpty()) {
                    if (showRestoreMessage) {
                        publish(
                            state.copy(
                                loading = false,
                                entitled = false,
                                currentSku = null,
                                expiresAtEpochMillis = null,
                                cloudAccessToken = null,
                                message = "اشتراک فعالی برای حساب فعلی کافه‌بازار پیدا نشد."
                            )
                        )
                    } else {
                        publish(state.copy(
                            entitled = false,
                            currentSku = null,
                            expiresAtEpochMillis = null,
                            cloudAccessToken = null
                        ))
                    }
                } else {
                    verifyPurchases(candidates, showRestoreMessage)
                }
            }
            queryFailed { throwable ->
                if (!closed) {
                    publish(
                        state.copy(
                            loading = false,
                            entitled = false,
                            currentSku = null,
                            expiresAtEpochMillis = null,
                            cloudAccessToken = null,
                            message = throwable.message?.take(180)
                                ?: "بازیابی اشتراک از کافه‌بازار ناموفق بود."
                        )
                    )
                }
            }
        }
    }

    private fun verifyPurchases(
        purchases: List<PurchaseInfo>,
        showRestoreMessage: Boolean
    ) {
        verificationJob?.cancel()
        verificationJob = scope.launch {
            var verified: BazaarSubscriptionEntitlement? = null
            var failureMessage: String? = null
            for (purchase in purchases) {
                if (closed) return@launch
                try {
                    val candidate = withContext(Dispatchers.IO) {
                        BazaarBillingApi.verifySubscription(
                            purchase.productId,
                            purchase.purchaseToken
                        )
                    }
                    if (candidate.entitled) {
                        verified = candidate
                        break
                    }
                } catch (cancelled: CancellationException) {
                    throw cancelled
                } catch (error: Exception) {
                    failureMessage = error.message?.take(180)
                }
            }

            if (closed) return@launch
            val entitlement = verified
            publish(
                state.copy(
                    loading = false,
                    entitled = entitlement != null,
                    currentSku = entitlement?.productId,
                    expiresAtEpochMillis = entitlement?.expiresAtEpochMillis,
                    cloudAccessToken = entitlement?.cloudAccessToken,
                    message = when {
                        entitlement != null -> "اشتراک شما توسط کافه‌بازار و سرور تأیید شد."
                        failureMessage != null -> failureMessage
                        showRestoreMessage -> "اشتراک معتبری برای بازیابی پیدا نشد."
                        else -> "خرید ثبت شد، اما اعتبار اشتراک تأیید نشد؛ دسترسی ویژه فعال نماند."
                    }
                )
            )
        }
    }

    private fun finishRefresh() {
        if (closed) return
        val ready = statusLoaded && catalogLoaded &&
            connected && serverReady && offers.any { it.sku in supportedSkus }
        publish(
            state.copy(
                connected = connected,
                loading = !(statusLoaded && catalogLoaded),
                checkoutReady = ready,
                offers = offers,
                trialAvailable = trialAvailable,
                trialPeriodDays = trialPeriodDays,
                message = when {
                    !statusLoaded || !catalogLoaded -> state.message
                    !serverReady -> "سرویس تأیید امن کافه‌بازار هنوز پیکربندی نشده است؛ خرید غیرفعال است."
                    offers.isEmpty() -> "شناسه یا قیمت اشتراک‌ها در پنل کافه‌بازار پیدا نشد؛ شناسه کالاها را بررسی کن."
                    else -> state.message
                }
            )
        )
    }

    private fun clearEntitlement(message: String) {
        verificationJob?.cancel()
        publish(
            state.copy(
                connected = connected,
                loading = false,
                checkoutReady = false,
                entitled = false,
                currentSku = null,
                expiresAtEpochMillis = null,
                cloudAccessToken = null,
                message = message
            )
        )
    }

    private fun SkuDetails.toPlanOffer() = BazaarPlanOffer(
        sku = sku,
        title = title,
        description = description,
        price = price
    )

    private fun publish(next: BazaarBillingState) {
        if (closed) return
        state = next
        onStateChanged(next)
    }

    fun close() {
        if (closed) return
        closed = true
        verificationJob?.cancel()
        scope.cancel()
        connection?.disconnect()
        connection = null
    }
}
