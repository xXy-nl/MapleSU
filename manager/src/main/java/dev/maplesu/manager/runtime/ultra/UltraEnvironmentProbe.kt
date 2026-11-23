package dev.maplesu.manager.runtime.ultra

import android.content.Context
import android.os.Looper
import android.os.Process
import android.os.SystemClock
import android.util.Log
import dev.maplesu.manager.workmode.ModeActivation
import dev.maplesu.manager.workmode.ModeRuntime
import dev.maplesu.manager.workmode.WorkMode
import dev.maplesu.manager.modules.webui.ModuleWebUiSessions
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.distinctUntilChanged
import kotlinx.coroutines.flow.map
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.locks.ReentrantLock

/**
 * Cached, off-main-thread view of the Ultra (MapleSU) environment.
 *
 * Why this exists: [UltraRuntimeClient.environmentState] is a JNI call that mirrors the Ultra
 * host's own state machine. Calling it from composition (or from [android.app.Application]
 * startup) would put native work on the first frame, so every read is funneled through this
 * tiny cache:
 *
 *  - [refresh] is blocking and must be called from a background thread. It is the only path
 *    that reaches the SDK and it records the observation time (both elapsed and wall clock).
 *  - [requestRefresh] is the non-blocking kick for UI callers; it coalesces concurrent
 *    requests and runs the probe on a private daemon thread.
 *  - [current] and [currentSnapshot] only read the last observation. Before the first probe
 *    they answer [State.Unknown], never a made-up "not installed".
 *
 * Any throwable (missing bridge, unloadable library, SDK exception) collapses to
 * [State.Unknown] and is logged; the cache never propagates an exception to the UI.
 */
object UltraEnvironmentProbe {

    /** The five states the Manager is allowed to distinguish. */
    enum class State { Running, NotInstalled, Fault, Unknown, NoKey }

    /** One cached observation. [observedAtWallClockMs] is 0 until the first successful probe. */
    data class Snapshot(
        val state: State = State.Unknown,
        val observedAtElapsedMs: Long = -1,
        val observedAtWallClockMs: Long = 0,
        val detail: String? = null,
        /** A live uid-0 response, independent of the helper's Running receipt. */
        val kernelRootVerified: Boolean = false,
        /** The key-based SDK explicitly reported no Ultra kernel, not timeout/busy/bad key. */
        val kernelChannelAbsent: Boolean = false,
        /** Signed identity observed with this snapshot; it grants no Root capability. */
        val managerOwnerIdentity: UltraRuntimeClient.ManagerOwnerIdentity? = null,
        internal val modeActivation: ModeActivation = ModeRuntime.activation,
        /** A successful current-scope SDK response, independent of helper and SU readiness. */
        val sdkChannelAvailable: Boolean = false,
    ) {
        val rootAvailable: Boolean get() = kernelRootVerified &&
            (state == State.Running || state == State.Unknown || state == State.NotInstalled)
    }

    private const val TAG = "MapleSUUltraProbe"
    private const val CACHE_TTL_MS = 3_000L
    private val ADMISSION_FAILURES = setOf("MAPLESU_SDK_BUSY", "MAPLESU_SDK_INTERRUPTED")

    private val snapshots = MutableStateFlow(Snapshot())
    private val snapshot: Snapshot get() = snapshots.value

    /** Publish capability and identity changes even when the helper state stays Running. */
    val observations: Flow<Snapshot> = combine(snapshots, ModeRuntime.detectionRevision) { observation, _ ->
        if (observation.modeActivation === ModeRuntime.activation) observation else Snapshot()
    }.distinctUntilChanged()

    val states: Flow<State> = observations.map { it.state }.distinctUntilChanged()

    /** SDK Root is independent of helper and Manager standard-SU readiness. */
    val rootAvailability: Flow<Boolean> = observations.map { it.rootAvailable }.distinctUntilChanged()

    private data class VerifiedIdentity(val key: String, val bootId: String)
    private data class VerifiedOwnerIdentity(val owner: UltraRuntimeClient.ManagerOwnerIdentity,
                                             val bootId: String, val activation: ModeActivation)

    @Volatile
    private var verifiedInstalledIdentity: VerifiedIdentity? = null

    @Volatile
    private var verifiedOwnerIdentity: VerifiedOwnerIdentity? = null

    private val executor = Executors.newSingleThreadExecutor { task ->
        Thread(task, "maplesu-ultra-probe").apply { isDaemon = true }
    }
    private val refreshing = AtomicBoolean(false)
    private val lock = Any()
    private val probeLock = ReentrantLock()
    private var revision = 0L
    private var snapshotKey: String? = null
    private var snapshotBootId: String? = null

    fun current(): State = currentSnapshot().state

    fun currentSnapshot(): Snapshot {
        val observation = snapshot
        return if (observation.modeActivation === ModeRuntime.activation) observation else Snapshot()
    }

    internal fun webUiOwnerScope(context: Context): ModuleWebUiSessions.OwnerScope? =
        if (ModeRuntime.active == WorkMode.KSU) null else currentSnapshot(context).managerOwnerIdentity?.let {
            ModuleWebUiSessions.OwnerScope(it.fullUid, it.epoch, it.hostInstance)
        }

    /** A proof belongs to one key and boot; changing or suspending either discards it. */
    internal fun currentSnapshot(context: Context): Snapshot = synchronized(lock) {
        if (snapshot.modeActivation !== ModeRuntime.activation) return@synchronized Snapshot()
        val key = UltraSdkCredentials.read(context)
        val bootId = UltraEnvironmentAutoSetup.currentBootId()
        if (key == null) scopeOwnerSnapshot(snapshot, cachedOwner(bootId), bootId, snapshotBootId,
            UltraSdkCredentials.suspended(context), UltraSdkCredentials.hookWithoutSdk(context))
        else scopeSnapshot(snapshot, key, snapshotKey, bootId, snapshotBootId, UltraSdkCredentials.suspended(context),
            UltraSdkCredentials.hookWithoutSdk(context))
    }

    private fun cachedOwner(bootId: String?): UltraRuntimeClient.ManagerOwnerIdentity? =
        verifiedOwnerIdentity?.takeIf { !bootId.isNullOrBlank() && it.bootId == bootId &&
            it.owner.fullUid == Process.myUid() && it.activation === ModeRuntime.activation }?.owner

    internal fun scopeOwnerSnapshot(observation: Snapshot, owner: UltraRuntimeClient.ManagerOwnerIdentity?,
                                    bootId: String?, observedBootId: String?, suspended: Boolean,
                                    hookActive: Boolean = false): Snapshot = when {
        bootId.isNullOrBlank() || bootId != observedBootId || suspended || hookActive -> Snapshot()
        owner != null && observation.managerOwnerIdentity == owner -> observation
        // A current-boot absence receipt does not need an owner or grant Root.
        owner == null && observation.managerOwnerIdentity == null && observation.kernelChannelAbsent ->
            observation.copy(state = State.Unknown, kernelRootVerified = false)
        else -> Snapshot()
    }

    internal fun scopeSnapshot(observation: Snapshot, key: String?, observedKey: String?,
                               bootId: String?, observedBootId: String?, suspended: Boolean, hookActive: Boolean = false): Snapshot =
        when {
            key == null -> Snapshot(State.NoKey)
            key != observedKey || bootId.isNullOrBlank() || bootId != observedBootId || suspended || hookActive -> Snapshot()
            else -> observation
        }

    /** Root execution is independent of helper/module readiness; pairing flags grant neither. */
    fun isRootAvailable(context: Context): Boolean = usesUltraBackend(context) && currentSnapshot(context).rootAvailable

    fun isKernelRootVerified(context: Context): Boolean =
        ModeRuntime.active != WorkMode.KSU && currentSnapshot(context).kernelRootVerified

    /** Reuse only fresh current-key/owner, boot and activation scoped execution evidence. */
    internal fun hasCurrentRootProof(context: Context): Boolean {
        val observation = currentSnapshot(context)
        return rootProofCurrent(observation, SystemClock.elapsedRealtime())
    }

    internal fun rootProofCurrent(observation: Snapshot, nowElapsedMs: Long): Boolean =
        observation.rootAvailable &&
            observation.observedAtElapsedMs >= 0 &&
            nowElapsedMs - observation.observedAtElapsedMs in 0 until CACHE_TTL_MS

    /**
     * True when the cached observation says the Ultra environment is Running.
     *
     * This is a pure cache read - it never touches JNI - so it is safe on the main thread and
     * safe to use as a gate in front of any path that would otherwise start a real root
     * process. This is helper readiness only; key-based root capability is scoped by
     * [isRootAvailable] and does not require a userspace Running receipt.
     */
    fun isRunning(): Boolean = current() == State.Running

    /** Pure cache read: protection keeps the Ultra identity without granting running capabilities. */
    fun isSafeMode(): Boolean = ModeRuntime.active != WorkMode.KSU && current() == State.Fault

    /** A live Hook handover or a changed/suspended key must not inherit an old SDK fault. */
    fun isSafeMode(context: Context): Boolean = usesUltraBackend(context) && currentSnapshot(context).state == State.Fault

    /** Failed root commands do not clear protection; a fresh SDK observation owns that state. */
    fun invalidateAvailability() = synchronized(lock) {
        revision++
        publishSnapshot(if (snapshot.modeActivation === ModeRuntime.activation && snapshot.state == State.Fault)
            snapshot.copy(observedAtElapsedMs = -1) else Snapshot())
    }

    /**
     * Keep a verified SDK identity through temporary probe failures. This only selects the
     * backend; callers still require a live successful SDK response before using a capability.
     * SharedPreferences hot reads and the in-process key comparison never call JNI or root.
     */
    fun usesUltraBackend(context: Context): Boolean {
        if (ModeRuntime.active == WorkMode.KSU) return false
        // A successful current-boot Hook handover supersedes historical SDK pairing.
        // Failed, incomplete and previous-boot attempts never make this predicate true.
        if (UltraSdkCredentials.hookWithoutSdk(context)) return false
        if (UltraSdkCredentials.suspended(context)) return false
        val key = UltraSdkCredentials.read(context)
        if (key == null) return cachedOwner(UltraEnvironmentAutoSetup.currentBootId()) != null
        if (key.length != 48) return false
        if (UltraSdkSession.current(context) != null) return true
        val identity = verifiedInstalledIdentity
        return identity != null && identity.key == key &&
            identity.bootId == UltraEnvironmentAutoSetup.currentBootId() ||
            UltraKeyPairedStore.matchesVerifiedKey(context, key)
    }

    /** A successful recovery selects the SDK owner without publishing helper or Root readiness. */
    internal fun recordRecoveredIdentity(context: Context, key: String, bootId: String?) = synchronized(lock) {
        if (bootId.isNullOrBlank() || ModeRuntime.active == WorkMode.KSU ||
            UltraEnvironmentAutoSetup.currentBootId() != bootId || UltraSdkCredentials.read(context) != key ||
            UltraSdkCredentials.suspended(context) || UltraSdkCredentials.hookWithoutSdk(context)) return@synchronized
        verifiedInstalledIdentity = VerifiedIdentity(key, bootId)
    }

    /** Coalesced background probe; safe to call from the main thread. */
    fun requestRefresh(context: Context) {
        if (!refreshing.compareAndSet(false, true)) return
        val appContext = context.applicationContext
        executor.execute {
            try {
                probeWithRetry(appContext, force = false)
            } catch (error: Throwable) {
                Log.w(TAG, "Ultra environment background probe failed", error)
                // A failed background attempt must not overwrite a newer observation.
            } finally {
                refreshing.set(false)
            }
        }
    }

    /** Blocking probe. Callers must be off the main thread. */
    fun refresh(context: Context, force: Boolean = true): State {
        check(Looper.myLooper() != Looper.getMainLooper()) { "ULTRA_PROBE_BACKGROUND_THREAD_REQUIRED" }
        return probeWithRetry(context.applicationContext, force)
    }

    /** Reuses only the live Root proof from the current synchronous recovery. */
    internal fun refreshRecoveredIdentity(context: Context, key: String, bootId: String?): State {
        check(Looper.myLooper() != Looper.getMainLooper()) { "ULTRA_PROBE_BACKGROUND_THREAD_REQUIRED" }
        val app = context.applicationContext
        if (bootId.isNullOrBlank() || Thread.currentThread().isInterrupted ||
            UltraIdentityRecovery.blocked(app) || UltraSdkCredentials.read(app) != key ||
            UltraEnvironmentAutoSetup.currentBootId() != bootId) return State.Unknown
        recordRecoveredIdentity(app, key, bootId)
        return probeWithRetry(app, force = false, recoveredRoot = VerifiedIdentity(key, bootId))
    }

    private fun probeWithRetry(context: Context, force: Boolean, recoveredRoot: VerifiedIdentity? = null): State {
        // The current Hook owns root; a cached SDK identity must not start competing IPC.
        if (UltraSdkCredentials.hookWithoutSdk(context)) return State.Unknown
        val key = UltraSdkCredentials.read(context)
        val bootId = UltraEnvironmentAutoSetup.currentBootId()
        val activation = ModeRuntime.activation
        // Owner mode has one bounded observation; a later refresh obtains new evidence.
        if (key == null) return if (ModeRuntime.active == WorkMode.KSU || UltraSdkCredentials.suspended(context))
            State.Unknown else probe(context, force)
        var recoveryProof = recoveredRoot
        return readUntilConfirmed(force, { nextForce ->
            val proof = recoveryProof
            recoveryProof = null
            probe(context, nextForce, proof)
        }, sameIdentity = {
            key != null && bootId != null && UltraSdkCredentials.read(context) == key &&
                ModeRuntime.activation === activation &&
                UltraEnvironmentAutoSetup.currentBootId() == bootId &&
                !UltraSdkCredentials.suspended(context)
        }, kernelResolved = {
            val observed = currentSnapshot(context)
            observed.kernelRootVerified || observed.kernelChannelAbsent
        })
    }

    internal fun readUntilConfirmed(
        force: Boolean,
        read: (Boolean) -> State,
        sameIdentity: () -> Boolean = { true },
        pause: (Long) -> Unit = { Thread.sleep(it) },
        kernelResolved: () -> Boolean = { false },
    ): State {
        var state = read(force)
        // Retry observations only. No install, bootstrap or protection writes here.
        for (delay in longArrayOf(250L, 500L, 1_000L)) {
            if (state != State.Unknown || kernelResolved()) return state
            if (Thread.currentThread().isInterrupted || !sameIdentity()) return State.Unknown
            try {
                pause(delay)
            } catch (_: InterruptedException) {
                Thread.currentThread().interrupt()
                return State.Unknown
            }
            if (Thread.currentThread().isInterrupted || !sameIdentity()) return State.Unknown
            state = read(true)
        }
        return state
    }

    internal fun canReuse(state: State, age: Long, kernelResolved: Boolean = false): Boolean =
        (state != State.Unknown || kernelResolved) && age in 0 until CACHE_TTL_MS

    private fun probe(context: Context, force: Boolean, recoveredRoot: VerifiedIdentity? = null): State {
        val key = UltraSdkCredentials.read(context)
        val bootId = UltraEnvironmentAutoSetup.currentBootId()
        val requestActivation = ModeRuntime.activation
        fun requestCurrent(): Boolean = ModeRuntime.activation === requestActivation &&
            ModeRuntime.active != WorkMode.KSU && UltraSdkCredentials.read(context) == key &&
            UltraEnvironmentAutoSetup.currentBootId() == bootId &&
            (key != null || !bootId.isNullOrBlank()) && !UltraSdkCredentials.suspended(context) &&
            !UltraSdkCredentials.hookWithoutSdk(context)
        var cachedOwnerObservation: Snapshot? = null
        val requestRevision = synchronized(lock) {
            if (!requestCurrent()) return State.Unknown
            val age = SystemClock.elapsedRealtime() - snapshot.observedAtElapsedMs
            val sameIdentity = snapshot.modeActivation === requestActivation && snapshotKey == key &&
                snapshotBootId == bootId && (key != null ||
                    cachedOwner(bootId)?.let { it == snapshot.managerOwnerIdentity } == true)
            if (!force && sameIdentity && snapshot.observedAtElapsedMs >= 0 &&
                canReuse(snapshot.state, age, snapshot.kernelRootVerified || snapshot.kernelChannelAbsent)) {
                if (key != null) return snapshot.state
                // A transient Root failure must be retried, even if helper state was readable.
                cachedOwnerObservation = snapshot.takeIf { it.managerOwnerIdentity != null && it.kernelRootVerified }
            }
            // JNI runs outside the cache lock; readers do not wait for an SDK observation.
            if (!probeLock.tryLock()) return if (sameIdentity) snapshot.state else State.Unknown
            revision
        }
        try {
            val client = UltraSdkCredentials.client(context, key, bootId)
            val ownerBefore = if (key == null) client.queryManagerOwnerIdentity() else null
            val beforeIdentity = ownerBefore?.identity
            if (key == null) {
                if (beforeIdentity == null) {
                    return synchronized(lock) {
                        if (revision != requestRevision || !requestCurrent()) return@synchronized State.Unknown
                        verifiedOwnerIdentity = null
                        snapshotKey = null
                        snapshotBootId = bootId
                        publish(State.Unknown, "sdkError=${ownerBefore?.receipt?.sdkError}", false,
                            ownerBefore?.receipt?.sdkError == "ERR_MODULE_NO_BOOT", activation = requestActivation)
                    }
                }
                cachedOwnerObservation?.let { cached ->
                    if (beforeIdentity == cached.managerOwnerIdentity) {
                        return synchronized(lock) {
                            if (revision == requestRevision && requestCurrent()) cached.state else State.Unknown
                        }
                    }
                }
                val current = synchronized(lock) {
                    if (revision != requestRevision || !requestCurrent()) false else {
                        if (snapshot.modeActivation !== requestActivation || snapshotKey != null ||
                            snapshotBootId != bootId || snapshot.managerOwnerIdentity != beforeIdentity) {
                            snapshotKey = null
                            snapshotBootId = bootId
                            publishSnapshot(Snapshot(managerOwnerIdentity = beforeIdentity), requestActivation)
                        }
                        verifiedOwnerIdentity = VerifiedOwnerIdentity(beforeIdentity, requireNotNull(bootId), requestActivation)
                        true
                    }
                }
                if (!current) return State.Unknown
            }
            var sdkError: String? = null
            var next = State.Unknown
            var kernelRootVerified = false
            var kernelChannelAbsent = false
            var ownerIdentity: UltraRuntimeClient.ManagerOwnerIdentity? = null
            var sdkChannelAvailable = beforeIdentity != null
            val detail = try {
                if (!requestCurrent()) return State.Unknown
                val receipt = client.environmentState()
                sdkError = receipt.sdkError
                sdkChannelAvailable = sdkChannelAvailable || receipt.succeeded
                kernelChannelAbsent = sdkError == "ERR_MODULE_NO_BOOT"
                val stateName = receipt.string("state")
                next = when {
                    !receipt.succeeded -> State.Unknown
                    stateName == "Running" -> State.Running
                    stateName == "NotInstalled" -> State.NotInstalled
                    stateName == "Fault" -> State.Fault
                    else -> State.Unknown
                }
                // Helper state, signed identity and live Root remain separate observations.
                if (key == null) {
                    if (requestCurrent() && !Thread.currentThread().isInterrupted) {
                        val root = client.probeManagerOwnerRoot()
                        val currentOwner = client.queryManagerOwnerIdentity()
                        ownerIdentity = currentOwner.identity?.takeIf { it == beforeIdentity }
                        kernelChannelAbsent = kernelChannelAbsent || root.receipt.sdkError == "ERR_MODULE_NO_BOOT" ||
                            currentOwner.receipt.sdkError == "ERR_MODULE_NO_BOOT"
                        kernelRootVerified = ownerIdentity != null && root.proof?.owner == ownerIdentity
                        sdkChannelAvailable = sdkChannelAvailable || kernelRootVerified
                        if (ownerIdentity == null || (root.proof != null && !kernelRootVerified)) next = State.Unknown
                    } else next = State.Unknown
                } else if (requestCurrent()) {
                    kernelRootVerified = verifyKernelRoot(next, receipt.succeeded) {
                        if (recoveredRoot != null && recoveredRoot.key == key && recoveredRoot.bootId == bootId &&
                            !Thread.currentThread().isInterrupted && !UltraIdentityRecovery.blocked(context) && requestCurrent()) {
                            0
                        } else {
                            val root = client.runRootCommand("/system/bin/id -u")
                            sdkChannelAvailable = sdkChannelAvailable || root.succeeded
                            kernelChannelAbsent = root.sdkError == "ERR_MODULE_NO_BOOT"
                            if (!root.succeeded) {
                                val command = root.obj("rootCommand")
                                Log.w(TAG, "Ultra Root probe failed sdkError=${root.sdkError} code=${root.sdkErrorCode}" +
                                    " phase=${command?.opt("phase")} systemError=${command?.opt("systemError")}" +
                                    " rootPhase=${command?.opt("rootPhase")} rootSystemError=${command?.opt("rootSystemError")}")
                            }
                            if (root.succeeded) client.decodeText(root.string("result"))?.trim()?.toIntOrNull() else null
                        }
                    }
                }
                sdkChannelAvailable = sdkChannelAvailable || kernelRootVerified
                if (receipt.succeeded) "state=$stateName${receipt.string("stateReason")?.let { " reason=$it" } ?: ""}"
                else "sdkError=${receipt.sdkError}${receipt.reason?.let { " reason=$it" } ?: ""}"
            } catch (error: Throwable) {
                next = State.Unknown
                Log.w(TAG, "Ultra environment state read failed", error)
                UltraSdkLogging.redact(error.toString())
            }
            return synchronized(lock) {
                if (revision != requestRevision || !requestCurrent()) return@synchronized State.Unknown
                val sameIdentity = snapshot.modeActivation === requestActivation && snapshotKey == key && snapshotBootId == bootId &&
                    (key != null || (ownerIdentity != null && snapshot.managerOwnerIdentity == ownerIdentity))
                val observed = stateAfterAdmission(snapshot.state, next, sdkError, sameIdentity)
                if (sdkError in ADMISSION_FAILURES && sameIdentity) {
                    // Preserve the original observation time; admission failure adds no helper evidence.
                    publishSnapshot(snapshot.copy(detail = detail,
                        kernelRootVerified = kernelRootVerified, kernelChannelAbsent = kernelChannelAbsent,
                        managerOwnerIdentity = ownerIdentity, sdkChannelAvailable = sdkChannelAvailable), requestActivation)
                    return@synchronized observed
                }
                snapshotKey = key
                snapshotBootId = bootId
                verifiedOwnerIdentity = ownerIdentity?.takeIf { key == null && !bootId.isNullOrBlank() }
                    ?.let { VerifiedOwnerIdentity(it, requireNotNull(bootId), requestActivation) }
                if (key != null && !bootId.isNullOrBlank() &&
                    (observed == State.Running || observed == State.Fault || kernelRootVerified)) {
                    verifiedInstalledIdentity = VerifiedIdentity(key, bootId)
                }
                Log.i(TAG, "Ultra environment probe -> $observed kernelRootVerified=$kernelRootVerified ($detail)")
                publish(observed, detail, kernelRootVerified, kernelChannelAbsent, ownerIdentity, requestActivation,
                    sdkChannelAvailable)
            }
        } catch (error: Throwable) {
            Log.w(TAG, "Ultra environment identity read failed", error)
            return synchronized(lock) {
                if (revision != requestRevision || !requestCurrent()) return@synchronized State.Unknown
                if (key == null) verifiedOwnerIdentity = null
                snapshotKey = key
                snapshotBootId = bootId
                publish(State.Unknown, UltraSdkLogging.redact(error.toString()), false, false, activation = requestActivation)
            }
        } finally { probeLock.unlock() }
    }

    internal fun verifyKernelRoot(state: State, receiptSucceeded: Boolean, rootUid: () -> Int?): Boolean =
        (receiptSucceeded || state == State.Unknown) &&
            (state == State.Running || state == State.Unknown || state == State.NotInstalled) &&
            runCatching(rootUid).getOrNull() == 0

    internal fun recoveryFingerprint(state: State, safeMode: Boolean, kernelRootVerified: Boolean = false,
                                     kernelChannelAbsent: Boolean = false): String? = when {
        state == State.Running -> "ultra:running"
        state == State.Fault && safeMode -> "ultra:fault"
        kernelRootVerified && (state == State.Unknown || state == State.NotInstalled) -> "ultra:kernel"
        state == State.Unknown && kernelChannelAbsent -> null
        // An unreadable environment is not a mode. Throwing here made every probe failure a hard
        // environment-check failure, which hides the install entry on a device that has no root at all.
        state == State.Unknown -> null
        state == State.NoKey -> throw IllegalStateException("ULTRA_RECOVERY_IDENTITY_UNKNOWN")
        else -> null
    }

    internal fun stateAfterAdmission(previous: State, next: State, sdkError: String?, sameIdentity: Boolean): State =
        if (sameIdentity && sdkError in ADMISSION_FAILURES) previous else next

    internal fun suEnabledState(state: State): Boolean? = when (state) {
        State.Running -> true
        State.Fault, State.NotInstalled -> false
        State.Unknown, State.NoKey -> null
    }

    internal fun publishSnapshot(observation: Snapshot, activation: ModeActivation = ModeRuntime.activation) = synchronized(lock) {
        if (activation === ModeRuntime.activation && ModeRuntime.active != WorkMode.KSU) {
            observation.managerOwnerIdentity?.let {
                ModuleWebUiSessions.observedOwner(ModuleWebUiSessions.OwnerScope(it.fullUid, it.epoch, it.hostInstance))
            }
        }
        snapshots.value = observation.copy(modeActivation = activation)
    }

    private fun publish(state: State, detail: String?, kernelRootVerified: Boolean,
                        kernelChannelAbsent: Boolean,
                        ownerIdentity: UltraRuntimeClient.ManagerOwnerIdentity? = null,
                        activation: ModeActivation = ModeRuntime.activation,
                        sdkChannelAvailable: Boolean = false): State {
        publishSnapshot(Snapshot(
            state = state,
            observedAtElapsedMs = SystemClock.elapsedRealtime(),
            observedAtWallClockMs = System.currentTimeMillis(),
            detail = detail,
            kernelRootVerified = kernelRootVerified,
            kernelChannelAbsent = kernelChannelAbsent,
            managerOwnerIdentity = ownerIdentity,
            sdkChannelAvailable = sdkChannelAvailable,
        ), activation)
        return state
    }
}
