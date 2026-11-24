package com.antivirusalai

import android.content.Context
import androidx.activity.result.ActivityResultRegistry
import ir.cafebazaar.poolakey.Connection
import ir.cafebazaar.poolakey.ConnectionState
import ir.cafebazaar.poolakey.Payment
import ir.cafebazaar.poolakey.config.PaymentConfiguration
import ir.cafebazaar.poolakey.config.SecurityCheck
import ir.cafebazaar.poolakey.entity.PurchaseInfo
import ir.cafebazaar.poolakey.entity.PurchaseState
import ir.cafebazaar.poolakey.request.PurchaseRequest
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.util.UUID

data class BazaarPlanOffer(val productId: String, val title: String, val description: String, val formattedPrice: String)
data class BazaarBillingUiState(
    val connected: Boolean = false, val loading: Boolean = false,
    val offers: List<BazaarPlanOffer> = emptyList(), val checkoutReady: Boolean = false,
    val activeBasePlans: Set<String> = emptySet(), val entitled: Boolean = false,
    val isTrial: Boolean = false, val trialEligible: Boolean = false, val trialPeriodDays: Int = 0,
    val cloudAccessToken: String? = null, val currentBasePlanId: String? = null,
    val expiresAtEpochMillis: Long? = null, val message: String? = null
)

class BazaarBillingManager(
    context: Context,
    private val registry: ActivityResultRegistry,
    private val onStateChanged: (BazaarBillingUiState) -> Unit
) {
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Main.immediate)
    private val payment = Payment(context, PaymentConfiguration(localSecurityCheck = SecurityCheck.Disable))
    private var connection: Connection? = null
    private var state = BazaarBillingUiState()
    private var closed = false
    private val products = mapOf(BuildConfig.ALAI_MONTHLY_PRODUCT_ID to "monthly", BuildConfig.ALAI_ANNUAL_PRODUCT_ID to "annual")

    fun connect() {
        if (closed) return
        if (connection?.getState() == ConnectionState.Connected) { refresh(); return }
        publish(state.copy(loading = true, message = null))
        connection = payment.connect {
            connectionSucceed {
                if (!closed) { publish(state.copy(connected = true, loading = false, message = null)); refresh() }
            }
            connectionFailed {
                if (!closed) publish(state.copy(connected = false, loading = false, checkoutReady = false,
                    entitled = false, cloudAccessToken = null,
                    message = "اتصال به سرویس پرداخت کافه‌بازار برقرار نشد. نصب و به‌روزرسانی بازار را بررسی کن."))
            }
            disconnected {
                if (!closed) publish(state.copy(connected = false, loading = false, checkoutReady = false,
                    entitled = false, isTrial = false, cloudAccessToken = null,
                    currentBasePlanId = null, expiresAtEpochMillis = null,
                    message = "اتصال بازار قطع شد. برای بررسی دوباره، فروشگاه را بازخوانی کن."))
            }
        }
    }

    fun refresh() {
        if (closed) return
        if (connection?.getState() != ConnectionState.Connected) { connect(); return }
        publish(state.copy(loading = true, checkoutReady = false, offers = emptyList(),
            activeBasePlans = emptySet(), entitled = false, isTrial = false, trialEligible = false,
            trialPeriodDays = 0, cloudAccessToken = null, currentBasePlanId = null,
            expiresAtEpochMillis = null, message = null))
        scope.launch {
            val readiness = runCatching { withContext(Dispatchers.IO) { CloudBillingApi.billingStatus() } }.getOrNull()
            if (closed) return@launch
            if (readiness == null || !readiness.checkoutReady) {
                publish(state.copy(loading = false, checkoutReady = false, activeBasePlans = emptySet(),
                    message = "فروش اشتراک هنوز در سرور آماده نشده است. اسکن پایه همچنان رایگان و فعال است."))
            } else {
                payment.getSubscriptionSkuDetails(products.keys.toList()) {
                    getSkuDetailsSucceed { details ->
                        if (closed) return@getSkuDetailsSucceed
                        val offers = details.filter { it.sku in products }.map { BazaarPlanOffer(it.sku, it.title, it.description, it.price) }
                        val activePlans = readiness.activeBasePlans.intersect(offers.mapNotNull { products[it.productId] }.toSet())
                        publish(state.copy(loading = false, offers = offers, activeBasePlans = activePlans,
                            checkoutReady = activePlans.isNotEmpty(),
                            message = if (activePlans.isEmpty()) "محصول اشتراک در پنل بازار فعال یا قابل دریافت نیست." else null))
                    }
                    getSkuDetailsFailed {
                        if (!closed) publish(state.copy(loading = false, checkoutReady = false, offers = emptyList(),
                            message = "دریافت قیمت و مشخصات اشتراک از کافه‌بازار ناموفق بود."))
                    }
                }
            }
            checkTrialEligibility()
            queryOwnedSubscriptions(false)
        }
    }

    private fun checkTrialEligibility() {
        payment.checkTrialSubscription {
            checkTrialSubscriptionSucceed { info ->
                if (!closed) publish(state.copy(trialEligible = info.isAvailable, trialPeriodDays = info.trialPeriodDays.coerceIn(0, 365)))
            }
            checkTrialSubscriptionFailed { if (!closed) publish(state.copy(trialEligible = false, trialPeriodDays = 0)) }
        }
    }

    fun launchPlan(productId: String) {
        if (closed) return
        if (connection?.getState() != ConnectionState.Connected) { publish(state.copy(message = "ابتدا اتصال کافه‌بازار را برقرار کن.")); connect(); return }
        val plan = products[productId]
        if (plan == null || !state.checkoutReady || plan !in state.activeBasePlans ||
            state.offers.none { it.productId == productId } || state.entitled || state.loading) {
            publish(state.copy(message = "این طرح هنوز برای خرید تأیید و آماده نشده است.")); return
        }
        publish(state.copy(loading = true, message = null, cloudAccessToken = null))
        payment.subscribeProduct(registry, PurchaseRequest(productId = productId, payload = UUID.randomUUID().toString())) {
            purchaseFlowBegan { if (!closed) publish(state.copy(loading = true, message = null)) }
            failedToBeginFlow { error ->
                if (!closed) publish(state.copy(loading = false, message = "شروع پرداخت بازار ناموفق بود: " + (error.message ?: "خطای نامشخص").take(120)))
            }
            purchaseSucceed { purchase ->
                if (closed) return@purchaseSucceed
                if (purchase.productId != productId || purchase.purchaseState != PurchaseState.PURCHASED) {
                    publish(state.copy(loading = false, entitled = false, cloudAccessToken = null, message = "اطلاعات خرید با محصول انتخاب‌شده مطابقت ندارد."))
                } else scope.launch { verifyPurchase(purchase) }
            }
            purchaseCanceled { if (!closed) publish(state.copy(loading = false, message = "پرداخت لغو شد؛ تغییری در دسترسی حساب ایجاد نشد.")) }
            purchaseFailed { error ->
                if (!closed) publish(state.copy(loading = false, entitled = false, cloudAccessToken = null,
                    message = "پرداخت بازار تأیید نشد: " + (error.message ?: "خطای نامشخص").take(120)))
            }
        }
    }

    fun restorePurchases() {
        if (closed) return
        if (connection?.getState() != ConnectionState.Connected) { connect(); return }
        publish(state.copy(loading = true, entitled = false, isTrial = false, cloudAccessToken = null,
            currentBasePlanId = null, expiresAtEpochMillis = null, message = null))
        queryOwnedSubscriptions(true)
    }

    private fun queryOwnedSubscriptions(showRestoreMessage: Boolean) {
        if (closed || connection?.getState() != ConnectionState.Connected) return
        payment.getSubscribedProducts {
            querySucceed { purchases ->
                if (closed) return@querySucceed
                val owned = purchases.filter { it.productId in products && it.purchaseState == PurchaseState.PURCHASED }
                if (owned.isEmpty()) publish(state.copy(loading = false, entitled = false, isTrial = false,
                    cloudAccessToken = null, currentBasePlanId = null, expiresAtEpochMillis = null,
                    message = if (showRestoreMessage) "اشتراک فعالی برای این حساب بازار پیدا نشد. امکانات پایه همچنان رایگان است." else state.message))
                else scope.launch {
                    for (purchase in owned.sortedByDescending { it.purchaseTime }) {
                        if (closed) return@launch
                        verifyPurchase(purchase)
                        if (state.entitled) return@launch
                    }
                    if (!state.entitled && showRestoreMessage) publish(state.copy(loading = false,
                        message = "خرید پیدا شد، اما سرور بازار اشتراک فعال و معتبر را تأیید نکرد."))
                }
            }
            queryFailed { error ->
                if (!closed) publish(state.copy(loading = false, entitled = false, cloudAccessToken = null,
                    message = "بازیابی خریدهای بازار ناموفق بود: " + (error.message ?: "خطای نامشخص").take(120)))
            }
        }
    }

    private suspend fun verifyPurchase(purchase: PurchaseInfo) {
        val plan = products[purchase.productId] ?: return
        publish(state.copy(loading = true, entitled = false, cloudAccessToken = null, message = null))
        val result = runCatching { withContext(Dispatchers.IO) {
            CloudBillingApi.verifySubscription(purchase.productId, purchase.purchaseToken)
        } }
        if (closed) return
        val entitlement = result.getOrNull()
        if (entitlement?.entitled == true && entitlement.basePlanId == plan) {
            publish(state.copy(loading = false, entitled = true, isTrial = entitlement.isTrial,
                cloudAccessToken = entitlement.cloudAccessToken, currentBasePlanId = plan,
                expiresAtEpochMillis = entitlement.expiresAtEpochMillis, message = null))
        } else publish(state.copy(loading = false, entitled = false, isTrial = false,
            cloudAccessToken = null, currentBasePlanId = null, expiresAtEpochMillis = null,
            message = result.exceptionOrNull()?.message ?: "کافه‌بازار این اشتراک را فعال و معتبر اعلام نکرد."))
    }

    private fun publish(next: BazaarBillingUiState) { state = next; onStateChanged(next) }
    fun close() {
        if (closed) return
        closed = true
        runCatching { connection?.disconnect() }
        connection = null
        scope.cancel(CancellationException("Bazaar billing manager closed"))
    }
}
