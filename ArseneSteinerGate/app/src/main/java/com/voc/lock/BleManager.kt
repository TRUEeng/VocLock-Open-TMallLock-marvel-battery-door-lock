package com.voc.lock

import android.bluetooth.*
import android.bluetooth.le.*
import android.content.Context
import android.util.Log
import kotlinx.coroutines.*
import java.util.UUID

private const val TAG          = "VocBle"
private const val DEVICE_NAME  = "~vTmallLock"
private val SERVICE_UUID       = UUID.fromString("00002760-08c2-11e1-9073-0e8ac72e1001")
private val WRITE_UUID         = UUID.fromString("00002760-08c2-11e1-9073-0e8ac72e0001")
private val NOTIFY_UUID        = UUID.fromString("00002760-08c2-11e1-9073-0e8ac72e0002")
private val CCCD_UUID          = UUID.fromString("00002902-0000-1000-8000-00805f9b34fb")

sealed class UnlockState {
    object Idle                        : UnlockState()
    object Scanning                    : UnlockState()
    object Connecting                  : UnlockState()
    object Handshaking                 : UnlockState()
    object Unlocking                   : UnlockState()
    object Success                     : UnlockState()
    data class Failed(val reason: String) : UnlockState()
}

class BleManager(private val context: Context) {

    private val adapter = (context.getSystemService(Context.BLUETOOTH_SERVICE)
            as BluetoothManager).adapter

    private var gatt:       BluetoothGatt?       = null
    private var writeChar:  BluetoothGattCharacteristic? = null
    private var notifyChar: BluetoothGattCharacteristic? = null

    // 协程通信
    private var notifyBuffer   = mutableListOf<ByteArray>()
    private var notifyContinuation: CancellableContinuation<ByteArray>? = null

    // ── GATT回调 ──────────────────────────────────────

    private val gattCallback = object : BluetoothGattCallback() {

        override fun onConnectionStateChange(
            gatt: BluetoothGatt, status: Int, newState: Int
        ) {
            if (newState == BluetoothProfile.STATE_CONNECTED) {
                Log.d(TAG, "已连接，发现服务...")
                gatt.discoverServices()
            } else {
                Log.d(TAG, "连接断开 status=$status")
                connectContinuation?.resumeWith(Result.failure(
                    Exception("连接断开 status=$status")
                ))
                connectContinuation = null
            }
        }

        override fun onServicesDiscovered(gatt: BluetoothGatt, status: Int) {
            if (status != BluetoothGatt.GATT_SUCCESS) {
                connectContinuation?.resumeWith(Result.failure(
                    Exception("服务发现失败")
                ))
                connectContinuation = null
                return
            }

            // 找到写特征和通知特征
            val service = gatt.getService(SERVICE_UUID)
            writeChar   = service?.getCharacteristic(WRITE_UUID)
            notifyChar  = service?.getCharacteristic(NOTIFY_UUID)

            if (writeChar == null || notifyChar == null) {
                connectContinuation?.resumeWith(Result.failure(
                    Exception("找不到特征UUID")
                ))
                connectContinuation = null
                return
            }

            // 开启Notify
            gatt.setCharacteristicNotification(notifyChar!!, true)
            val descriptor = notifyChar!!.getDescriptor(CCCD_UUID)
            descriptor?.let {
                it.value = BluetoothGattDescriptor.ENABLE_NOTIFICATION_VALUE
                gatt.writeDescriptor(it)
            }
        }

        override fun onDescriptorWrite(
            gatt: BluetoothGatt,
            descriptor: BluetoothGattDescriptor,
            status: Int
        ) {
            // Notify开启完成，连接就绪
            Log.d(TAG, "Notify已启用，连接就绪")
            connectContinuation?.resumeWith(Result.success(Unit))
            connectContinuation = null
        }

        override fun onCharacteristicChanged(
            gatt: BluetoothGatt,
            characteristic: BluetoothGattCharacteristic,
            value: ByteArray
        ) {
            Log.d(TAG, "收到通知: ${Crypto.bytesToHex(value)}")
            notifyContinuation?.resumeWith(Result.success(value))
            notifyContinuation = null
        }

        // 兼容旧API
        @Deprecated("Deprecated in API 33")
        override fun onCharacteristicChanged(
            gatt: BluetoothGatt,
            characteristic: BluetoothGattCharacteristic
        ) {
            val value = characteristic.value ?: return
            Log.d(TAG, "收到通知(旧): ${Crypto.bytesToHex(value)}")
            notifyContinuation?.resumeWith(Result.success(value))
            notifyContinuation = null
        }
    }

    private var connectContinuation: CancellableContinuation<Unit>? = null

    // ── 扫描 ──────────────────────────────────────────

    suspend fun scanForLock(
        targetMac: String,
        timeoutMs: Long = 8000L
    ): BluetoothDevice? = withContext(Dispatchers.IO) {

        val scanner = adapter.bluetoothLeScanner
        var found: BluetoothDevice? = null
        var scanCallback: ScanCallback? = null

        val deferred = CompletableDeferred<BluetoothDevice?>()

        scanCallback = object : ScanCallback() {
            override fun onScanResult(callbackType: Int, result: ScanResult) {
                val name = result.device.name ?: return
                val mac  = result.device.address ?: return

                if (name == DEVICE_NAME &&
                    mac.uppercase() == targetMac.uppercase()) {
                    Log.d(TAG, "找到目标: $mac  RSSI:${result.rssi}")
                    found = result.device
                    scanner.stopScan(this)
                    deferred.complete(result.device)
                }
            }

            override fun onScanFailed(errorCode: Int) {
                deferred.complete(null)
            }
        }

        val filters = listOf(
            ScanFilter.Builder().setDeviceName(DEVICE_NAME).build()
        )
        val settings = ScanSettings.Builder()
            .setScanMode(ScanSettings.SCAN_MODE_LOW_LATENCY)
            .build()

        scanner.startScan(filters, settings, scanCallback)

        // 超时
        withContext(Dispatchers.Default) {
            delay(timeoutMs)
            if (!deferred.isCompleted) {
                scanner.stopScan(scanCallback)
                deferred.complete(null)
            }
        }

        deferred.await()
    }

    // ── 连接 ──────────────────────────────────────────

    suspend fun connect(device: BluetoothDevice): Unit =
        suspendCancellableCoroutine { cont ->
            connectContinuation = cont
            gatt = device.connectGatt(context, false, gattCallback,
                BluetoothDevice.TRANSPORT_LE)

            cont.invokeOnCancellation {
                gatt?.disconnect()
                gatt = null
            }
        }

    // ── 发送命令 ──────────────────────────────────────

    private suspend fun send(hexCmd: String) {
        val bytes = Crypto.hexToBytes(hexCmd)
        val char  = writeChar ?: throw Exception("未连接")

        withContext(Dispatchers.IO) {
            // 分包，每包20字节
            for (i in bytes.indices step 20) {
                val chunk = bytes.copyOfRange(i, minOf(i + 20, bytes.size))
                char.value = chunk
                gatt?.writeCharacteristic(char)
                if (i + 20 < bytes.size) delay(50)
            }
        }
    }

    // ── 等待通知响应 ──────────────────────────────────

    private suspend fun waitNotify(timeoutMs: Long = 2000L): String =
        withTimeout(timeoutMs) {
            suspendCancellableCoroutine { cont ->
                notifyContinuation = cont
            }
        }.let { Crypto.bytesToHex(it) }

    // ── 提取随机数 ────────────────────────────────────

    private fun extractRandom(response: String): String? {
        val r   = response.uppercase()
        val idx = r.indexOf("55AAFF0D0011")
        if (idx == -1) return null
        val start = idx + 14       // 12(帧头) + 2(标志位)
        val chunk = r.substring(start)
        return if (chunk.length >= 32) chunk.substring(0, 32) else null
    }

    // ── 完整开锁流程 ──────────────────────────────────

    suspend fun unlock(
        mac:           String,
        activationKey: String,
        onState:       (UnlockState) -> Unit
    ): Boolean {
        try {
            // 1. 扫描
            onState(UnlockState.Scanning)
            val device = scanForLock(mac)
                ?: run {
                    onState(UnlockState.Failed("扫描不到门锁，请靠近后重试"))
                    return false
                }

            // 2. 连接
            onState(UnlockState.Connecting)
            withTimeoutOrNull(10_000L) {
                connect(device)
            } ?: run {
                onState(UnlockState.Failed("连接超时，请重试"))
                disconnect()
                return false
            }

            delay(300)

            // 3. 请求随机数
            onState(UnlockState.Handshaking)
            send("55AAFF0D00000B")
            val randResp = runCatching { waitNotify() }.getOrNull()
                ?: run {
                    onState(UnlockState.Failed("握手无响应，请重试"))
                    disconnect()
                    return false
                }

            val random = extractRandom(randResp)
                ?: run {
                    onState(UnlockState.Failed("随机数提取失败（$randResp）"))
                    disconnect()
                    return false
                }

            // 4. 建立加密链接
            send("55AAFF13000011")
            runCatching { waitNotify() }

            val sessionKey = Crypto.xorKey(random, activationKey)

            // 5. 开锁
            onState(UnlockState.Unlocking)
            val packet = Crypto.buildUnlockPacket(random, activationKey)
            send(packet)
            val unlockResp = runCatching { waitNotify(3000L) }.getOrNull()
                ?: run {
                    onState(UnlockState.Failed("开锁无响应，请重试"))
                    disconnect()
                    return false
                }

            // 6. 验证结果
            val r   = unlockResp.uppercase()
            val idx = r.indexOf("55AA0010")
            var success = false

            if (idx != -1) {
                val cipher = r.substring(idx + 8, minOf(idx + 8 + 32, r.length))
                if (cipher.length == 32) {
                    val plain = Crypto.aesDecrypt(cipher, sessionKey)
                    success = plain.startsWith("FF0B0001000A")
                }
            }

            disconnect()

            if (success) {
                onState(UnlockState.Success)
            } else {
                onState(UnlockState.Failed("开锁失败，请重试"))
            }

            return success

        } catch (e: Exception) {
            Log.e(TAG, "开锁异常", e)
            onState(UnlockState.Failed("异常：${e.message}"))
            disconnect()
            return false
        }
    }

    // ── 断开连接 ──────────────────────────────────────

    fun disconnect() {
        gatt?.disconnect()
        gatt?.close()
        gatt        = null
        writeChar   = null
        notifyChar  = null
        notifyContinuation  = null
        connectContinuation = null
    }
}
