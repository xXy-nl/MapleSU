// SPDX-License-Identifier: GPL-3.0-or-later
package dev.maplesu.manager.runtime.ultra

import android.content.Context
import android.os.Process
import android.os.SystemClock
import android.util.Log
import dev.maplesu.manager.modules.UltraRootKeyStore
import dev.maplesu.manager.workmode.ModeRuntime
import dev.maplesu.manager.workmode.superuser.LiteImplantQuiesceGate
import dev.maplesu.manager.workmode.ui.WorkModeSwitchSession
import java.security.MessageDigest
import java.util.concurrent.CancellationException

object UltraEnvironmentInstaller {

    private const val TAG = "MapleSUUltraInstaller"
    private val backupMaintenance = UltraBackupMaintenance(SystemClock::elapsedRealtime)

    /** 安装意图。默认值保持既有调用点的语义（复用运行中的环境）。 */
    enum class Intent {
        /** 已经 Running 就复用，不重复写设备。 */
        ReuseRunning,

        /** 显式安装：由 SDK 决定能否安装，不以前置状态探测代替提交。 */
        InstallToBundledBuild,

        /** 升级：无论当前是否 Running，都必须提交一次随包载荷。 */
        UpgradeToBundledBuild,

        /** Legacy 软件载荷刷新，保留当前启动状态，不重启或重刷底层镜像。 */
        RefreshToBundledBuild,
    }

    /** 安装结果。[ok] 只由 SDK 回执决定；[verified] 是「设备上真的是这一版」的独立结论。 */
    data class Outcome(
        val ok: Boolean,
        val sdkError: String,
        val reason: String? = null,
        val whitelist: String? = null,
        val backup: String? = null,
        val detail: String? = null,
        /** 每次真正提交安装后核对；回读失败/摘要不符 → false（[ok] 仍可为 true）。 */
        val verified: Boolean = true,
        /** 回读到的（或随包的）构建号，供界面/日志显示。 */
        val buildId: String? = null,
        val sdkErrorCode: Int? = null,
        /** The installed state may have changed; replay requires reconciliation. */
        val submissionUnknown: Boolean = false,
    ) {
        val summary: String
            get() = "ok=$ok sdkError=$sdkError" +
                (sdkErrorCode?.let { " sdkErrorCode=$it" } ?: "") +
                (reason?.let { " reason=$it" } ?: "") +
                (whitelist?.let { " suAuth[$it]" } ?: "") +
                (backup?.let { " backup[$it]" } ?: "") +
                " verified=$verified" +
                " submissionUnknown=$submissionUnknown" +
                (buildId?.let { " buildId=$it" } ?: "") +
                (detail?.let { " detail=$it" } ?: "")
    }

    private fun failureOutcome(receipt: NativeReceipt, phase: String) = Outcome(
        false, receiptErrorName(receipt.succeeded, receipt.sdkError), receipt.reason,
        sdkErrorCode = receipt.sdkErrorCode,
        verified = false,
        detail = "phase=$phase operation=${receipt.operation} bridgeVersion=${receipt.bridgeVersion}",
        submissionUnknown = phase == "install" && (receipt.operationCompleted ||
            receipt.sdkError !in setOf("MAPLESU_SDK_BUSY", "MAPLESU_SDK_INTERRUPTED",
                "MAPLESU_BRIDGE_UNAVAILABLE", "MAPLESU_ULTRA_ROOT_KEY_ABSENT", "SDK_CREDENTIAL_SCOPE_CHANGED")),
    )

    /**
     * SDK 安装面（端口）。生产由 [UltraRuntimeClient] 支撑；主机测试用假实现数调用次数，
     * 从而能证明「升级真的调了安装，而不是被 Running 短路」。
     */
    interface InstallPort {
        fun environmentState(): NativeReceipt

        fun submitInstall(): NativeReceipt
    }

    /**
     * 安装之后的附带动作。主机测试传空实现；生产由 [install] 用真实 Context 装好。
     * 真正提交后先回读并保存身份，再做白名单、备份与探针刷新。
     */
    class Attachments(
        val whitelist: () -> UltraSelfWhitelist.Result,
        val backup: () -> String?,
        /** 每次真正提交安装后调用；复用 Running 不重复回读。 */
        val verify: () -> IdentityObservation = {
            IdentityObservation(InstalledIdentity.unknown(), IdentityVerification.passed(null))
        },
        /** 只有核对通过才落盘（未经验证的身份不许写成「已装」）。 */
        val persist: (InstalledIdentity) -> Unit = {},
        val refreshProbe: () -> Unit = {},
        /** Prepare the deployed current SDK/restorer before a Boot upgrade can reboot. */
        val prepareUpgrade: () -> Outcome? = { null },
        val prepareInstall: () -> String? = { null },
        val scopeFailure: () -> String? = { null },
        /** Explicit installation initializes only a genuinely absent durable authority. */
        val initializeAuthority: () -> String? = { null },
    )

    /**
     * 安装成功之后的附带动作（纯编排；主机测试直接调它，不需要 JNI/Context）。
     *
     * 规则：
     *  - `succeeded == false` → 白名单/备份**都不调用**；
     *  - 白名单抛异常 → 安装仍是成功，`whitelist` 记 `EXCEPTION:<类型>`；
     *  - 白名单失败或抛异常 → 仍通过 Key 通道备份，避免遗漏重装恢复材料；
     *  - 备份抛异常 → 安装仍是成功，`backup` 记 `EXCEPTION:<类型>`。
     */
    fun afterInstall(
        succeeded: Boolean,
        sdkError: String,
        reason: String?,
        whitelist: () -> UltraSelfWhitelist.Result,
        backup: () -> String?,
    ): Outcome {
        if (!succeeded) return Outcome(false, receiptErrorName(false, sdkError), reason)
        val white = try {
            whitelist()
        } catch (error: Throwable) {
            null
        }
        val whiteSummary = white?.summary ?: "EXCEPTION:WHITELIST"
        val backupReason = try {
            backup()
        } catch (error: Throwable) {
            "EXCEPTION:${error.javaClass.simpleName}"
        }
        return Outcome(
            ok = true,
            sdkError = sdkError,
            reason = reason,
            whitelist = whiteSummary,
            backup = backupReason,
        )
    }

    /**
     * 生产适配：全仓唯一出现 `installEnvironment("Boot"` 的地方。
     *
     * 显式升级和软件刷新均提交真实 SDK 写入；Running 不代替写入。
     */
    fun portOf(client: UltraRuntimeClient, intent: Intent = Intent.ReuseRunning): InstallPort = object : InstallPort {
        override fun environmentState(): NativeReceipt = client.environmentState()

        override fun submitInstall(): NativeReceipt = client.installEnvironment(
            if (intent == Intent.RefreshToBundledBuild) "Refresh" else "Boot", "")
    }

    /**
     * 用本地 key 安装环境。安装成功后自动自白名单 + 备份 key。
     *
     * <p>启动链路里 `UltraEnvironmentAutoSetup` 与 `UltraSelfHeal` 在不同
     * daemon 线程上可能同时判断出「需要补装」，锁内重新检查 Running，避免排队中的旧请求
     * 再次安装已激活的环境；自白名单与备份仍按原顺序补齐。
     *
     * @param intent 默认 [Intent.ReuseRunning]（保持既有调用点语义）；升级必须显式传
     *   [Intent.UpgradeToBundledBuild]，否则会被 Running 短路掉。
     * @param client 绑定 key 的客户端；默认复用 [UltraSdkCredentials] 的捕获身份。
     */
    fun install(
        context: Context,
        client: UltraRuntimeClient = UltraSdkCredentials.client(context),
        intent: Intent = Intent.ReuseRunning,
    ): Outcome {
        val key = UltraSdkCredentials.read(context)
        val bootId = UltraEnvironmentAutoSetup.currentBootId()
        val activation = ModeRuntime.activation
        val suspended = UltraSdkCredentials.suspended(context)
        val clientScope = client.logPolicyScope()
        val owner = if (key == null) client.queryManagerOwnerIdentity().identity else null
        val expectedScope = key?.let {
            MessageDigest.getInstance("SHA-256").digest(it.toByteArray(Charsets.US_ASCII))
                .joinToString("") { byte -> "%02x".format(byte.toInt() and 255) }
        }
        fun checkScope(): String? = when {
            Thread.currentThread().isInterrupted -> "MAPLESU_SDK_INTERRUPTED"
            bootId == null || UltraEnvironmentAutoSetup.currentBootId() != bootId -> "INSTALL_BOOT_CHANGED"
            ModeRuntime.activation != activation -> "INSTALL_MODE_CHANGED"
            LiteImplantQuiesceGate.isBlocked() || WorkModeSwitchSession.executing -> "INSTALL_SWITCH_PENDING"
            key == null && owner == null -> "INSTALL_IDENTITY_UNCONFIRMED"
            clientScope != expectedScope || UltraSdkCredentials.read(context) != key ||
                client.logPolicyScope() != clientScope ||
                owner != null && client.queryManagerOwnerIdentity().identity != owner -> "INSTALL_IDENTITY_CHANGED"
            UltraSdkCredentials.suspended(context) != suspended -> "INSTALL_SUSPENSION_CHANGED"
            else -> null
        }
        val scopedClient = client.scoped(key) { checkScope() == null }
        return synchronized(this) {
            install(
                port = portOf(scopedClient, intent),
                intent = intent,
                attachments = Attachments(
                    whitelist = { UltraSelfWhitelist.onEnvironmentInstalled(context, scopedClient) { checkScope() == null } },
                    backup = { if (owner != null) "SKIPPED:OWNER_IDENTITY" else backupKey(context, key)?.reason },
                    verify = {
                        // Boot 安装返回后设备马上重启，文件可能刚写完：给 3 次、每次 1s 的有界重试。
                        UltraInstalledIdentityProbe.readAndVerify(
                            context,
                            scopedClient,
                            attempts = 3,
                            delayMillis = 1_000L,
                        )
                    },
                    persist = { identity ->
                        check(checkScope() == null) { "INSTALL_CONTEXT_CHANGED" }
                        check(UltraInstalledIdentityProbe.persist(context, identity)) { "IDENTITY_PERSIST_FAILED" }
                    },
                    refreshProbe = {
                        runCatching { UltraEnvironmentProbe.refresh(context) }
                            .onFailure { Log.w(TAG, "probe refresh after install failed (ignored)") }
                    },
                    prepareUpgrade = {
                        // The SDK can reboot immediately after submission. Deploy the repaired
                        // SDK/boot restorer first, not in the remaining post-install window.
                        // Signed Owner installation uses the existing native gateway and
                        // boot-owned namespace; it does not need the legacy key broker.
                        // Tools/backend preparation and helper readback still run below.
                        if (owner != null) null else {
                            val prepared = backupKey(context, key, forceIdentity = true, preparingUpgrade = true)
                            upgradePreparationFailure(prepared)
                        }
                    },
                    prepareInstall = { UltraPolicyBackendDeployment.prepare(context, scopedClient) },
                    scopeFailure = ::checkScope,
                    initializeAuthority = {
                        val current = { checkScope() == null }
                        val scope = UltraAuthorization.Scope(scopedClient, current, current)
                        val initialized = dev.maplesu.manager.runtime.authorization.SuperuserControl
                            .initializeForInstallationIfAbsent(context, scope)
                        if (initialized.succeeded) null else listOfNotNull(
                            initialized.code ?: "SU_AUTH_APPLY_PENDING",
                            initialized.detail.takeIf(String::isNotBlank),
                        ).joinToString(":")
                    },
                ),
            )
        }
    }

    private fun scopeFailure(attachments: Attachments): String? =
        runCatching { attachments.scopeFailure() }.getOrDefault("INSTALL_SCOPE_UNREADABLE")

    internal fun upgradePreparationFailure(prepared: UltraRecoveryKeyStore.BackupOutcome?): Outcome? =
        if (prepared?.identityPrepared == true) null else Outcome(
            false, receiptErrorName(false, prepared?.sdkError ?: "UPGRADE_PREPARATION_FAILED"),
            reason = prepared?.reason ?: "IDENTITY_PREPARATION_UNAVAILABLE",
            sdkErrorCode = prepared?.sdkErrorCode,
            detail = prepared?.detail,
        )

    /**
     * 编排主体（不碰 Android）：提交/复用 → 回读身份 → 白名单 → 备份 → 刷新探针。
     * 只有复用路径需要先读 Running；显式升级已在入口核对事实。
     */
    fun install(port: InstallPort, intent: Intent, attachments: Attachments): Outcome {
        fun pendingScopeFailure(): Outcome? = scopeFailure(attachments)?.let {
            Outcome(false, "INSTALL_CONTEXT_CHANGED", reason = it)
        }
        if (Thread.currentThread().isInterrupted) return Outcome(false, "MAPLESU_SDK_INTERRUPTED")
        pendingScopeFailure()?.let { return it }
        val existing = if (intent == Intent.ReuseRunning) {
            val observation = try {
                port.environmentState()
            } catch (error: Exception) {
                if (error is InterruptedException) Thread.currentThread().interrupt()
                return Outcome(false, "ENVIRONMENT_PROBE_FAILED", detail = error.javaClass.simpleName)
            }
            // A queued recovery may outlive its initial probe. A failed channel is
            // not evidence of absence, and must never fall through to a Boot write.
            if (!observation.succeeded) return failureOutcome(observation, "probe")
            val state = observation.string("state")
            if (state != "Running" && state != "NotInstalled") {
                return Outcome(false, if (state == "Fault") "ENVIRONMENT_FAULT" else "ENVIRONMENT_STATE_UNKNOWN")
            }
            observation.takeIf { state == "Running" }
        } else null
        // ReuseRunning：已有 Running 就不再写设备（自愈/启动补装的既有语义）。
        // UpgradeToBundledBuild：Running 不是复用理由，必须重新提交载荷。
        val reuse = intent == Intent.ReuseRunning && existing != null
        pendingScopeFailure()?.let { return it }
        if (!reuse) {
            val failure = try {
                attachments.prepareInstall()
            } catch (error: Exception) {
                if (error is InterruptedException) Thread.currentThread().interrupt()
                "POLICY_BACKEND_PREPARATION_EXCEPTION"
            }
            if (failure != null) {
                quietLog { Log.w(TAG, "prepareInstall failed reason=$failure") }
                return Outcome(false, "POLICY_BACKEND_PREPARATION_FAILED", reason = failure)
            }
            pendingScopeFailure()?.let { return it }
            // Complete tools/policy preflight before replacing the recovery identity.
            // A tools failure must not first stop or publish the current broker tuple.
            if (intent == Intent.UpgradeToBundledBuild || intent == Intent.RefreshToBundledBuild) {
                val failure = try {
                    attachments.prepareUpgrade()
                } catch (error: Exception) {
                    if (error is InterruptedException) Thread.currentThread().interrupt()
                    Outcome(false, if (error is InterruptedException || error is CancellationException)
                        "MAPLESU_SDK_INTERRUPTED" else "UPGRADE_PREPARATION_FAILED",
                        reason = "PREPARATION_EXCEPTION:${error.javaClass.simpleName}")
                }
                if (failure != null) return failure
                pendingScopeFailure()?.let { return it }
            }
        }
        if (Thread.currentThread().isInterrupted) return Outcome(false, "MAPLESU_SDK_INTERRUPTED")
        pendingScopeFailure()?.let { return it }
        val receipt: NativeReceipt = try {
            existing ?: port.submitInstall()
        } catch (error: Throwable) {
            quietLog { Log.w(TAG, "install_maplesu_environment threw: ${error.javaClass.simpleName}") }
            return Outcome(false, "EXCEPTION", reason = UltraSdkLogging.redact(error.toString()),
                submissionUnknown = true)
        }
        quietLog {
            Log.i(
                TAG,
                "environment ready intent=$intent existing=${existing != null} reuse=$reuse " +
                    "ok=${receipt.succeeded} sdkError=${receipt.sdkError} reason=${receipt.reason.orEmpty()}",
            )
        }
        if (!receipt.succeeded) return failureOutcome(receipt, "install")
        fun submittedUnverified(reason: String) = Outcome(
            true, receipt.sdkError, receipt.reason, detail = "UNVERIFIED:$reason", verified = false,
            sdkErrorCode = receipt.sdkErrorCode,
            submissionUnknown = true,
        )
        scopeFailure(attachments)?.let { return submittedUnverified(it) }
        // Persist readback before whitelist/identity deployment can consume the reboot window.
        val verified = if (!reuse) verifyAndPersist(attachments) else IdentityVerification.passed(null)
        scopeFailure(attachments)?.let { return submittedUnverified(it) }
        val authorityFailure = if (intent == Intent.InstallToBundledBuild && verified.verified) {
            try { attachments.initializeAuthority() }
            catch (error: Exception) {
                if (error is InterruptedException) Thread.currentThread().interrupt()
                "AUTH_INITIALIZATION_EXCEPTION:${UltraSdkLogging.redact(error.toString())}"
            }
        } else null
        scopeFailure(attachments)?.let { return submittedUnverified(it) }
        val outcome = afterInstall(
            succeeded = true,
            sdkError = receipt.sdkError,
            reason = receipt.reason,
            whitelist = {
                check(scopeFailure(attachments) == null) { "INSTALL_CONTEXT_CHANGED" }
                if (authorityFailure == null) attachments.whitelist()
                else UltraSelfWhitelist.Result(false, false, false, false, false, authorityFailure)
            },
            backup = {
                check(scopeFailure(attachments) == null) { "INSTALL_CONTEXT_CHANGED" }
                attachments.backup()
            },
        )
        scopeFailure(attachments)?.let { return submittedUnverified(it) }
        attachments.refreshProbe()
        scopeFailure(attachments)?.let { return submittedUnverified(it) }
        val result = outcome.copy(
            verified = verified.verified && authorityFailure == null,
            detail = when {
                !verified.verified -> "UNVERIFIED:${verified.reason ?: "UNKNOWN"}"
                authorityFailure != null -> "UNVERIFIED:AUTHORITY:$authorityFailure"
                else -> outcome.detail
            },
            buildId = verified.buildId,
            sdkErrorCode = receipt.sdkErrorCode,
        )
        quietLog { Log.i(TAG, "environment install outcome ${result.summary}") }
        return result
    }

    /**
     * 回读 + 核对；只有通过才落持久化身份。任何异常都收敛成「未验证」。
     *
     * 所有日志都用 [quietLog]：主机单测里 `android.util.Log` 是 stub 会抛，编排路径不能
     * 因为记一行日志就失败（与 [UltraSuChannel] 的既有纪律一致）。
     */
    private fun verifyAndPersist(attachments: Attachments): IdentityVerification {
        scopeFailure(attachments)?.let { return IdentityVerification(false, it, null) }
        val observation = try {
            attachments.verify()
        } catch (error: Throwable) {
            return IdentityVerification(false, "VERIFY_EXCEPTION:${error.javaClass.simpleName}", null)
        }
        scopeFailure(attachments)?.let { return IdentityVerification(false, it, null) }
        if (!observation.verification.verified) {
            quietLog {
                Log.w(
                    TAG,
                    "install not verified: reason=${observation.verification.reason} " +
                        "source=${observation.identity.source}",
                )
            }
            return observation.verification
        }
        // 校验通过 = 设备上的 helper 就是随包这一份：把随包构建号盖上去再落盘。
        // 不盖的话「摘要相同但构建号未知」会永远停在待确认，用户会每点一次都重装。
        val stamped = observation.identity.copy(
            buildId = observation.identity.buildId ?: observation.verification.buildId,
        )
        scopeFailure(attachments)?.let { return IdentityVerification(false, it, null) }
        try {
            attachments.persist(stamped)
        } catch (error: Throwable) {
            quietLog { Log.w(TAG, "identity persist failed: ${error.javaClass.simpleName}") }
            return IdentityVerification(false, "IDENTITY_PERSIST_FAILED", null)
        }
        scopeFailure(attachments)?.let { return IdentityVerification(false, it, null) }
        return observation.verification.copy(
            buildId = stamped.buildId ?: observation.verification.buildId,
        )
    }

    /** 主机单测里 Log 是 stub：日志永远不允许把编排变成异常。 */
    private inline fun quietLog(block: () -> Unit) {
        runCatching(block)
    }

    /** The kernel credential owns recovery; a stale package/UID su grant is not required. */
    fun backupKey(context: Context, key: String? = null, forceIdentity: Boolean = false,
                  preparingUpgrade: Boolean = false): UltraRecoveryKeyStore.BackupOutcome? =
        runCatching {
            val resolved = key ?: UltraRootKeyStore.read(context)
                ?: return UltraRecoveryKeyStore.BackupOutcome(false, true, "BACKUP_CREDENTIAL_ABSENT", "BACKUP_CREDENTIAL_ABSENT")
            // Resolve scope under the maintenance monitor, including after waiting for a peer.
            backupMaintenance.ensure(identity = {
                val boot = UltraEnvironmentAutoSetup.currentBootId()
                if (!preparingUpgrade && boot != null && !UltraIdentityRecovery.blocked(context) &&
                    !dev.maplesu.manager.workmode.ui.WorkModeSwitchSession.executing && UltraRootKeyStore.read(context) == resolved) {
                    val fingerprint = MessageDigest.getInstance("SHA-256").digest(resolved.toByteArray(Charsets.US_ASCII))
                        .joinToString("") { "%02x".format(it.toInt() and 255) }
                    UltraBackupMaintenance.Identity(fingerprint, boot, context.packageName, Process.myUid())
                } else null
            }, force = forceIdentity || preparingUpgrade) {
                val client = UltraRuntimeClient { resolved }
                val boot = UltraEnvironmentAutoSetup.currentBootId()
                fun ineligible(): String? = when {
                    Thread.currentThread().isInterrupted -> "BACKUP_CANCELLED"
                    boot == null -> "BACKUP_BOOT_UNAVAILABLE"
                    UltraEnvironmentAutoSetup.currentBootId() != boot -> "BACKUP_BOOT_CHANGED"
                    dev.maplesu.manager.workmode.ui.WorkModeSwitchSession.executing -> "BACKUP_MODE_SWITCHING"
                    UltraRootKeyStore.read(context) != resolved -> "BACKUP_IDENTITY_CHANGED"
                    UltraIdentityRecovery.blocked(context, preparingUpgrade) -> "BACKUP_IDENTITY_SUSPENDED"
                    else -> null
                }
                val attempt = "${Thread.currentThread().id}:${System.nanoTime()}"
                fun rejected(reason: String, phase: String): UltraRecoveryKeyStore.BackupOutcome {
                    quietLog { Log.i(TAG, "backup attempt=$attempt upgrade=$preparingUpgrade phase=$phase status=$reason") }
                    return UltraRecoveryKeyStore.BackupOutcome(false, true, reason,
                        if (reason == "BACKUP_CANCELLED") "MAPLESU_SDK_INTERRUPTED" else reason)
                }
                fun eligible() = ineligible() == null
                ineligible()?.let { return@ensure rejected(it, "eligible-before") }
                // Keep the complete proof: busy/transport failure is not an invalid identity.
                val proofStarted = SystemClock.elapsedRealtime()
                val proof = client.runRootCommand("/system/bin/id -u")
                quietLog { Log.i(TAG, "backup attempt=$attempt upgrade=$preparingUpgrade phase=root-proof " +
                    "operation=${proof.operation} bridgeVersion=${proof.bridgeVersion} " +
                    "sdkError=${proof.sdkError} sdkErrorCode=${proof.sdkErrorCode} " +
                    "elapsedMs=${SystemClock.elapsedRealtime() - proofStarted}") }
                ineligible()?.let { return@ensure rejected(it, "eligible-after") }
                if (!proof.succeeded) {
                    return@ensure UltraRecoveryKeyStore.BackupOutcome(false, true,
                        proof.reason ?: "BACKUP_ROOT_PROOF_FAILED", receiptErrorName(false, proof.sdkError), proof.sdkErrorCode,
                        "phase=root-proof operation=${proof.operation} bridgeVersion=${proof.bridgeVersion}")
                }
                val uid = client.decodeText(proof.string("result"))?.trim()?.toIntOrNull()
                if (uid == null || uid < 0) return@ensure rejected("BACKUP_ROOT_UID_UNREADABLE", "root-uid")
                if (uid != 0) return@ensure rejected("BACKUP_ROOT_UID_NOT_ZERO", "root-uid")
                val logging = UltraSdkLogging.apply(client)
                if (logging != null && !logging.succeeded) quietLog {
                    Log.i(TAG, "backup attempt=$attempt phase=log-policy sdkError=${logging.sdkError} sdkErrorCode=${logging.sdkErrorCode}")
                }
                // Preparation must not depend on standard-su delivery, which an
                // authorization transaction may temporarily close. Keep the SDK-key
                // transport just verified above; never replay a submitted script.
                val maintenance = client
                val backup = UltraRecoveryKeyStore.ensureBackup(
                    context = context,
                    root = runner@{ script ->
                        if (!eligible()) return@runner null
                        val receipt = maintenance.runRootCommand(script)
                        if (!eligible()) return@runner null
                        SuExecResult(if (receipt.succeeded) 0 else -1,
                            maintenance.decodeText(receipt.string("result")).orEmpty())
                    },
                    key = resolved,
                )
                ineligible()?.let { return@ensure rejected(it, "backup-after") }
                val identity = UltraIdentityRecovery.ensure(context, resolved, maintenance, force = forceIdentity,
                    preparingUpgrade = preparingUpgrade)
                val identityPrepared = identity == "IDENTITY_READY" ||
                    preparingUpgrade && identity == "IDENTITY_UPGRADE_PREPARED"
                backup.copy(ok = backup.ok && identityPrepared, identityPrepared = identityPrepared,
                    reason = "${backup.reason};$identity")
            }
        }.getOrElse { error ->
            if (error is InterruptedException) Thread.currentThread().interrupt()
            val cancelled = error is InterruptedException || error is CancellationException
            quietLog { Log.w(TAG, "key backup failed: ${error.javaClass.simpleName}") }
            UltraRecoveryKeyStore.BackupOutcome(false, true, "BACKUP_EXCEPTION:${error.javaClass.simpleName}",
                if (cancelled) "MAPLESU_SDK_INTERRUPTED" else "UPGRADE_PREPARATION_FAILED")
        }
            ?.also { Log.i(TAG, "key backup outcome ${UltraSdkLogging.redact(it.reason)}") }
}
