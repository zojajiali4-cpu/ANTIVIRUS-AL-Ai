package com.antivirusalai

import android.app.Activity
import android.content.Context
import com.android.billingclient.api.BillingClient
import com.android.billingclient.api.BillingClientStateListener
import com.android.billingclient.api.BillingFlowParams
import com.android.billingclient.api.BillingResult
import com.android.billingclient.api.PendingPurchasesParams
import com.android.billingclient.api.ProductDetails
import com.android.billingclient.api.Purchase
import com.android.billingclient.api.PurchasesUpdatedListener
import com.android.billingclient.api.QueryProductDetailsParams
import com.android.billingclient.api.QueryPurchasesParams
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

data class PlayPlanOffer(
    val basePlanId: String,
    val offerToken: String,
    val hasFreeTrial: Boolean,
    val trialPeriod: String?,
    val recurringPrice: String,
    val recurringPeriod: String
)

data class PlayBillingUiState(
    val connected: Boolean = false,
    val loading: Boolean = false,
    val offers: List<PlayPlanOffer> = emptyList(),
    val checkoutReady: Boolean = false,
    val entitled: Boolean = false,
    val isTrial: Boolean = false,
    val currentBasePlanId: String? = null,
    val expiresAtEpochMillis: Long? = null,
    val message: String? = null
)

class PlayBillingManager(
    context: Context,
    private val activity: Activity,
    private val onStateChanged: (PlayBillingUiState) -> Unit
) : PurchasesUpdatedListener {
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Main.immediate)
    private var uiState = PlayBillingUiState()
    private var closed = false
    private val processingTokens = mutableSetOf<String>()
    private var queriedCatalogOffers: List<PlayPlanOffer> = emptyList()
    private var activeBasePlans: Set<String> = emptySet()
    private var billingStatusLoaded = false
    private var billingStatusError: String? = null
    private val billingClient = BillingClient.newBuilder(context.applicationContext)
        .setListener(this)
        .enablePendingPurchases(PendingPurchasesParams.newBuilder().enableOneTimeProducts().build())
        .enableAutoServiceReconnection()
        .build()

    fun connect() {
        if (closed) return
        if (billingClient.isReady) { refresh(); return }
        publish(uiState.copy(loading = true, message = null))
        billingClient.startConnection(object : BillingClientStateListener {
            override fun onBillingSetupFinished(result: BillingResult) {
                if (closed) return
                if (result.responseCode == BillingClient.BillingResponseCode.OK) {
                    publish(uiState.copy(connected = true, loading = true, message = null))
                    refresh()
                } else {
                    publish(uiState.copy(connected = false, loading = false,
                        message = "Google Play billing is unavailable on this device or account."))
                }
            }
            override fun onBillingServiceDisconnected() {
                if (!closed) publish(uiState.copy(connected = false, loading = false,
                    message = "Google Play connection was interrupted. Reopen the Store to retry."))
            }
        })
    }

    fun refresh() {
        if (closed) return
        if (!billingClient.isReady) { connect(); return }
        billingStatusLoaded = false
        activeBasePlans = emptySet()
        queriedCatalogOffers = emptyList()
        publish(uiState.copy(loading = true, checkoutReady = false, offers = emptyList(), message = null))
        queryBillingStatus()
        queryCatalog()
        queryOwnedPurchases()
    }

    fun restorePurchases() {
        if (closed) return
        publish(uiState.copy(loading = true, message = null))
        queryOwnedPurchases(showRestoreMessage = true)
    }

    fun launchPlan(basePlanId: String) {
        if (closed || !billingClient.isReady) {
            publish(uiState.copy(message = "Google Play billing is not connected."))
            connect()
            return
        }
        if (uiState.entitled) {
            publish(uiState.copy(message = "A verified subscription is already active."))
            return
        }
        if (basePlanId !in setOf("monthly", "annual")) {
            publish(uiState.copy(message = "This subscription option is not supported."))
            return
        }
        if (!uiState.checkoutReady || basePlanId !in activeBasePlans) {
            publish(uiState.copy(loading = false,
                message = "Secure billing verification is not ready for this subscription plan. No payment was started."))
            return
        }
        publish(uiState.copy(loading = true, message = null))
        val params = productQueryParams()
        billingClient.queryProductDetailsAsync(params) { result, query ->
            if (closed) return@queryProductDetailsAsync
            if (result.responseCode != BillingClient.BillingResponseCode.OK) {
                publish(uiState.copy(loading = false, message = "Subscription offers could not be loaded from Google Play."))
                return@queryProductDetailsAsync
            }
            val details = query.productDetailsList.firstOrNull {
                it.productId == BuildConfig.ALAI_SUBSCRIPTION_PRODUCT_ID
            }
            val offer = details?.subscriptionOfferDetails
                ?.filter { it.basePlanId == basePlanId }
                ?.maxByOrNull { if (isFreeTrial(it)) 1 else 0 }
            if (details == null || offer == null) {
                publish(uiState.copy(loading = false,
                    message = "This offer is not currently available for your Play account or region."))
                return@queryProductDetailsAsync
            }
            val item = BillingFlowParams.ProductDetailsParams.newBuilder()
                .setProductDetails(details).setOfferToken(offer.offerToken).build()
            val flow = BillingFlowParams.newBuilder().setProductDetailsParamsList(listOf(item)).build()
            val launch = billingClient.launchBillingFlow(activity, flow)
            if (launch.responseCode != BillingClient.BillingResponseCode.OK) {
                publish(uiState.copy(loading = false,
                    message = "Google Play could not open checkout: " + launch.debugMessage.take(140)))
            }
        }
    }

    override fun onPurchasesUpdated(result: BillingResult, purchases: List<Purchase>?) {
        if (closed) return
        when (result.responseCode) {
            BillingClient.BillingResponseCode.OK -> {
                if (purchases.isNullOrEmpty()) publish(uiState.copy(loading = false,
                    message = "Google Play returned no purchase details."))
                else purchases.forEach(::processPurchase)
            }
            BillingClient.BillingResponseCode.USER_CANCELED ->
                publish(uiState.copy(loading = false,
                    message = "Purchase was canceled. No payment or access change was made."))
            else -> publish(uiState.copy(loading = false,
                message = "Google Play purchase failed: " + result.debugMessage.take(140)))
        }
    }

    private fun productQueryParams() = QueryProductDetailsParams.newBuilder()
        .setProductList(listOf(
            QueryProductDetailsParams.Product.newBuilder()
                .setProductId(BuildConfig.ALAI_SUBSCRIPTION_PRODUCT_ID)
                .setProductType(BillingClient.ProductType.SUBS).build()
        )).build()

    private fun queryBillingStatus() {
        scope.launch {
            try {
                val status = withContext(Dispatchers.IO) { CloudBillingApi.billingStatus() }
                billingStatusLoaded = true
                activeBasePlans = status.activeBasePlans
                billingStatusError = if (status.checkoutReady) null else
                    "Play Console subscription product or server verification is not configured."
                publishAvailableOffers()
            } catch (cancelled: CancellationException) {
                throw cancelled
            } catch (_: Exception) {
                billingStatusLoaded = true
                activeBasePlans = emptySet()
                billingStatusError = "Secure billing verification is unavailable. Purchases remain disabled."
                publishAvailableOffers()
            }
        }
    }

    private fun publishAvailableOffers() {
        val activeOffers = if (billingStatusLoaded) {
            queriedCatalogOffers.filter { it.basePlanId in activeBasePlans }
        } else emptyList()
        val ready = billingStatusLoaded && billingClient.isReady && activeBasePlans.isNotEmpty()
        publish(uiState.copy(
            connected = billingClient.isReady,
            loading = false,
            offers = activeOffers,
            checkoutReady = ready,
            message = when {
                !billingStatusLoaded -> "Checking secure billing configuration…"
                !ready -> billingStatusError ?: "No active regional subscription plans are configured."
                activeOffers.isEmpty() -> "No eligible subscription offers are currently available for this Play account or region."
                else -> null
            }
        ))
    }

    private fun queryCatalog() {
        billingClient.queryProductDetailsAsync(productQueryParams()) { result, query ->
            if (closed) return@queryProductDetailsAsync
            if (result.responseCode != BillingClient.BillingResponseCode.OK) {
                queriedCatalogOffers = emptyList()
                publish(uiState.copy(
                    connected = true,
                    loading = false,
                    offers = emptyList(),
                    checkoutReady = false,
                    message = "Google Play could not load regional subscription prices."
                ))
                return@queryProductDetailsAsync
            }
            val details = query.productDetailsList.firstOrNull {
                it.productId == BuildConfig.ALAI_SUBSCRIPTION_PRODUCT_ID
            }
            queriedCatalogOffers = details?.subscriptionOfferDetails.orEmpty()
                .mapNotNull(::toPlanOffer)
                .groupBy { it.basePlanId }
                .values
                .mapNotNull { candidates -> candidates.maxByOrNull { if (it.hasFreeTrial) 1 else 0 } }
                .sortedBy { it.basePlanId }
            publishAvailableOffers()
        }
    }

    private fun toPlanOffer(details: ProductDetails.SubscriptionOfferDetails): PlayPlanOffer? {
        val phases = details.pricingPhases.pricingPhaseList
        val paid = phases.lastOrNull { it.priceAmountMicros > 0L } ?: return null
        val trial = phases.firstOrNull { it.priceAmountMicros == 0L && it.billingCycleCount > 0 }
        return PlayPlanOffer(
            basePlanId = details.basePlanId,
            offerToken = details.offerToken,
            hasFreeTrial = trial != null,
            trialPeriod = trial?.billingPeriod,
            recurringPrice = paid.formattedPrice,
            recurringPeriod = paid.billingPeriod
        )
    }

    private fun isFreeTrial(details: ProductDetails.SubscriptionOfferDetails): Boolean =
        details.pricingPhases.pricingPhaseList.any {
            it.priceAmountMicros == 0L && it.billingCycleCount > 0
        }

    private fun queryOwnedPurchases(showRestoreMessage: Boolean = false) {
        if (!billingClient.isReady || closed) {
            publish(uiState.copy(loading = false, message = "Connect to Google Play before restoring purchases."))
            return
        }
        val params = QueryPurchasesParams.newBuilder().setProductType(BillingClient.ProductType.SUBS).build()
        billingClient.queryPurchasesAsync(params) { result, purchases ->
            if (closed) return@queryPurchasesAsync
            if (result.responseCode != BillingClient.BillingResponseCode.OK) {
                publish(uiState.copy(loading = false, message = "Google Play could not restore purchases."))
                return@queryPurchasesAsync
            }
            val owned = purchases.filter { BuildConfig.ALAI_SUBSCRIPTION_PRODUCT_ID in it.products }
            if (owned.isEmpty()) {
                publish(uiState.copy(
                    loading = false, entitled = false, isTrial = false,
                    currentBasePlanId = null, expiresAtEpochMillis = null,
                    message = if (showRestoreMessage) {
                        "No active ANTIVIRUS AL AI subscription was found for this Play account."
                    } else uiState.message
                ))
            } else owned.forEach(::processPurchase)
        }
    }

    private fun processPurchase(purchase: Purchase) {
        if (BuildConfig.ALAI_SUBSCRIPTION_PRODUCT_ID !in purchase.products) return
        when (purchase.purchaseState) {
            Purchase.PurchaseState.PENDING -> publish(uiState.copy(
                loading = false, entitled = false,
                message = "Payment is pending. Premium access stays locked until Google Play confirms it."
            ))
            Purchase.PurchaseState.PURCHASED -> {
                val token = purchase.purchaseToken
                if (!processingTokens.add(token)) return
                publish(uiState.copy(loading = true, message = "Verifying the purchase securely with Google Play…"))
                scope.launch {
                    try {
                        val entitlement = withContext(Dispatchers.IO) {
                            CloudBillingApi.verifySubscription(token)
                        }
                        publish(uiState.copy(
                            loading = false,
                            entitled = entitlement.entitled,
                            isTrial = entitlement.isTrial && entitlement.entitled,
                            currentBasePlanId = entitlement.basePlanId.takeIf { entitlement.entitled },
                            expiresAtEpochMillis = entitlement.expiresAtEpochMillis.takeIf { entitlement.entitled },
                            message = if (entitlement.entitled) {
                                if (entitlement.isTrial) "Your verified free-trial access is active."
                                else "Your Google Play subscription is verified and active."
                            } else "Google Play verified the purchase, but it does not currently grant access."
                        ))
                    } catch (cancelled: CancellationException) {
                        throw cancelled
                    } catch (error: Exception) {
                        publish(uiState.copy(
                            loading = false, entitled = false, isTrial = false,
                            currentBasePlanId = null, expiresAtEpochMillis = null,
                            message = error.message ?: "Secure purchase verification is unavailable. Restore purchases to retry."
                        ))
                    } finally { processingTokens.remove(token) }
                }
            }
        }
    }

    private fun publish(next: PlayBillingUiState) {
        uiState = next
        onStateChanged(next)
    }

    fun close() {
        if (closed) return
        closed = true
        scope.cancel()
        if (billingClient.isReady) billingClient.endConnection()
    }
}
