package org.matrix.TEESimulator.interception.keystore.shim

import android.os.IBinder
import android.os.Parcel
import android.system.keystore2.IKeystoreOperation
import org.matrix.TEESimulator.interception.core.BinderInterceptor
import org.matrix.TEESimulator.interception.keystore.InterceptorUtils

/**
 * Intercepts calls to an `IKeystoreOperation` service. This is used to log the data manipulation
 * methods of a cryptographic operation.
 */
class OperationInterceptor(private val original: IKeystoreOperation) : BinderInterceptor() {

    override fun onPreTransact(
        txId: Long,
        target: IBinder,
        code: Int,
        flags: Int,
        callingUid: Int,
        callingPid: Int,
        data: Parcel,
    ): TransactionResult {
        val methodName = transactionNames[code] ?: "unknown code=$code"
        logTransaction(txId, methodName, callingUid, callingPid, true)

        if (code == FINISH_TRANSACTION || code == ABORT_TRANSACTION) {
            KeyMintSecurityLevelInterceptor.removeOperationInterceptor(target)
        }

        return TransactionResult.ContinueAndSkipPost
    }

    companion object {
        private val UPDATE_AAD_TRANSACTION =
            InterceptorUtils.getTransactCode(IKeystoreOperation.Stub::class.java, "updateAad")
        private val UPDATE_TRANSACTION =
            InterceptorUtils.getTransactCode(IKeystoreOperation.Stub::class.java, "update")
        private val FINISH_TRANSACTION =
            InterceptorUtils.getTransactCode(IKeystoreOperation.Stub::class.java, "finish")
        private val ABORT_TRANSACTION =
            InterceptorUtils.getTransactCode(IKeystoreOperation.Stub::class.java, "abort")

        private val transactionNames: Map<Int, String> by lazy {
            mapOf(
                UPDATE_AAD_TRANSACTION to "updateAad",
                UPDATE_TRANSACTION to "update",
                FINISH_TRANSACTION to "finish",
                ABORT_TRANSACTION to "abort",
            )
        }
    }
}
