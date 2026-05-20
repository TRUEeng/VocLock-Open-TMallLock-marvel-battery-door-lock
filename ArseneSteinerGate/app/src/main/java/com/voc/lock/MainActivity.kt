package com.voc.lock

import android.Manifest
import android.bluetooth.BluetoothAdapter
import android.bluetooth.BluetoothManager
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.animation.*
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardCapitalization
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.core.content.ContextCompat
import androidx.lifecycle.lifecycleScope
import kotlinx.coroutines.launch

class MainActivity : ComponentActivity() {

    private lateinit var repo:       LockRepository
    private lateinit var bleManager: BleManager

    // 权限列表
    private val permissions = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
        arrayOf(
            Manifest.permission.BLUETOOTH_SCAN,
            Manifest.permission.BLUETOOTH_CONNECT,
            Manifest.permission.ACCESS_FINE_LOCATION
        )
    } else {
        arrayOf(
            Manifest.permission.BLUETOOTH,
            Manifest.permission.BLUETOOTH_ADMIN,
            Manifest.permission.ACCESS_FINE_LOCATION
        )
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        repo       = LockRepository(this)
        bleManager = BleManager(this)

        setContent {
            MaterialTheme(
                colorScheme = darkColorScheme()
            ) {
                Surface(
                    modifier = Modifier.fillMaxSize(),
                    color    = MaterialTheme.colorScheme.background
                ) {
                    VocLockApp(
                        repo       = repo,
                        onUnlock   = { mac, key, onState ->
                            checkPermissionsThenUnlock(mac, key, onState)
                        }
                    )
                }
            }
        }
    }

    private fun checkPermissionsThenUnlock(
        mac:     String,
        key:     String,
        onState: (UnlockState) -> Unit
    ) {
        // 检查蓝牙是否开启
        val btManager = getSystemService(Context.BLUETOOTH_SERVICE) as BluetoothManager
        if (!btManager.adapter.isEnabled) {
            startActivity(Intent(BluetoothAdapter.ACTION_REQUEST_ENABLE))
            onState(UnlockState.Failed("请先开启蓝牙"))
            return
        }

        // 检查权限
        val missing = permissions.filter {
            ContextCompat.checkSelfPermission(this, it) !=
                    PackageManager.PERMISSION_GRANTED
        }

        if (missing.isNotEmpty()) {
            permissionLauncher.launch(missing.toTypedArray())
            pendingMac     = mac
            pendingKey     = key
            pendingOnState = onState
            return
        }

        // 开始开锁
        lifecycleScope.launch {
            val success = bleManager.unlock(mac, key, onState)
            if (success) repo.recordUnlock()
        }
    }

    private var pendingMac:     String?                    = null
    private var pendingKey:     String?                    = null
    private var pendingOnState: ((UnlockState) -> Unit)?   = null

    private val permissionLauncher = registerForActivityResult(
        ActivityResultContracts.RequestMultiplePermissions()
    ) { results ->
        if (results.values.all { it }) {
            // 权限全部通过
            val mac     = pendingMac     ?: return@registerForActivityResult
            val key     = pendingKey     ?: return@registerForActivityResult
            val onState = pendingOnState ?: return@registerForActivityResult
            lifecycleScope.launch {
                val success = bleManager.unlock(mac, key, onState)
                if (success) repo.recordUnlock()
            }
        } else {
            pendingOnState?.invoke(UnlockState.Failed("需要蓝牙权限"))
        }
        pendingMac     = null
        pendingKey     = null
        pendingOnState = null
    }

    override fun onDestroy() {
        super.onDestroy()
        bleManager.disconnect()
    }
}


// ══════════════════════════════════════════════════
// UI
// ══════════════════════════════════════════════════

@Composable
fun VocLockApp(
    repo:     LockRepository,
    onUnlock: (String, String, (UnlockState) -> Unit) -> Unit
) {
    var lock        by remember { mutableStateOf(repo.getLock()) }
    var showAddDialog by remember { mutableStateOf(false) }
    var unlockState by remember { mutableStateOf<UnlockState>(UnlockState.Idle) }
    val isUnlocking  = unlockState is UnlockState.Scanning  ||
            unlockState is UnlockState.Connecting ||
            unlockState is UnlockState.Handshaking||
            unlockState is UnlockState.Unlocking

    Box(
        modifier        = Modifier.fillMaxSize(),
        contentAlignment = Alignment.Center
    ) {
        Column(
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.Center,
            modifier            = Modifier.padding(32.dp)
        ) {

            // 标题
            Text(
                text       = "🔒 门锁控制",
                fontSize   = 28.sp,
                fontWeight = FontWeight.Bold,
                color      = Color.White
            )

            Spacer(modifier = Modifier.height(8.dp))

            // 门锁名
            if (lock != null) {
                Text(
                    text     = lock!!.name,
                    fontSize = 16.sp,
                    color    = Color.Gray
                )
                Spacer(modifier = Modifier.height(4.dp))
                Text(
                    text     = "开锁 ${lock!!.unlockCount} 次  |  上次 ${lock!!.lastUnlock}",
                    fontSize = 13.sp,
                    color    = Color.DarkGray
                )
            }

            Spacer(modifier = Modifier.height(48.dp))

            // ── 主按钮 ──
            if (lock != null) {
                // 开锁大按钮
                Button(
                    onClick  = {
                        if (!isUnlocking) {
                            unlockState = UnlockState.Idle
                            onUnlock(lock!!.mac, lock!!.activationKey) { state ->
                                unlockState = state
                            }
                        }
                    },
                    enabled  = !isUnlocking,
                    modifier = Modifier
                        .fillMaxWidth()
                        .height(120.dp),
                    shape    = RoundedCornerShape(24.dp),
                    colors   = ButtonDefaults.buttonColors(
                        containerColor = when (unlockState) {
                            is UnlockState.Success -> Color(0xFF2E7D32)
                            is UnlockState.Failed  -> Color(0xFFC62828)
                            else                   -> Color(0xFF1565C0)
                        }
                    )
                ) {
                    Text(
                        text       = when (unlockState) {
                            UnlockState.Idle        -> "🔓\n开锁"
                            UnlockState.Scanning    -> "📡\n扫描中..."
                            UnlockState.Connecting  -> "🔗\n连接中..."
                            UnlockState.Handshaking -> "🤝\n握手中..."
                            UnlockState.Unlocking   -> "⚡\n开锁中..."
                            UnlockState.Success     -> "✅\n成功"
                            is UnlockState.Failed   -> "❌\n失败，点击重试"
                        },
                        fontSize    = 22.sp,
                        fontWeight  = FontWeight.Bold,
                        textAlign   = TextAlign.Center,
                        lineHeight  = 32.sp
                    )
                }

                // 失败原因
                AnimatedVisibility(visible = unlockState is UnlockState.Failed) {
                    val reason = (unlockState as? UnlockState.Failed)?.reason ?: ""
                    Spacer(modifier = Modifier.height(16.dp))
                    Text(
                        text      = reason,
                        color     = Color(0xFFEF9A9A),
                        fontSize  = 14.sp,
                        textAlign = TextAlign.Center
                    )
                }

            } else {
                // 添加门锁按钮（没有门锁时显示）
                OutlinedButton(
                    onClick  = { showAddDialog = true },
                    modifier = Modifier
                        .fillMaxWidth()
                        .height(80.dp),
                    shape    = RoundedCornerShape(16.dp)
                ) {
                    Text(
                        text     = "➕  添加门锁",
                        fontSize = 20.sp,
                        color    = Color.White
                    )
                }
            }

            // 长按删除（调试用，可以删掉）
            if (lock != null) {
                Spacer(modifier = Modifier.height(32.dp))
                TextButton(
                    onClick = {
                        repo.deleteLock()
                        lock        = null
                        unlockState = UnlockState.Idle
                    }
                ) {
                    Text(
                        text     = "删除门锁",
                        color    = Color.DarkGray,
                        fontSize = 12.sp
                    )
                }
            }
        }
    }

    // ── 添加门锁弹窗 ──
    if (showAddDialog) {
        AddLockDialog(
            onConfirm = { mac, key, name ->
                val info = LockInfo(
                    mac           = mac.uppercase().trim(),
                    activationKey = key.uppercase().trim(),
                    name          = name.ifBlank { "我的门锁" }
                )
                repo.saveLock(info)
                lock          = info
                showAddDialog = false
            },
            onDismiss = { showAddDialog = false }
        )
    }
}


@Composable
fun AddLockDialog(
    onConfirm: (mac: String, key: String, name: String) -> Unit,
    onDismiss: () -> Unit
) {
    var mac   by remember { mutableStateOf("") }
    var key   by remember { mutableStateOf("") }
    var name  by remember { mutableStateOf("") }
    var error by remember { mutableStateOf("") }

    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("添加门锁") },
        text  = {
            Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {

                OutlinedTextField(
                    value         = name,
                    onValueChange = { name = it },
                    label         = { Text("名称（如：宿舍门）") },
                    singleLine    = true,
                    modifier      = Modifier.fillMaxWidth()
                )

                OutlinedTextField(
                    value         = mac,
                    onValueChange = { mac = it },
                    label         = { Text("MAC地址") },
                    placeholder   = { Text("94:36:70:56:34:12") },
                    singleLine    = true,
                    keyboardOptions = KeyboardOptions(
                        capitalization = KeyboardCapitalization.Characters
                    ),
                    modifier      = Modifier.fillMaxWidth()
                )

                OutlinedTextField(
                    value         = key,
                    onValueChange = { key = it },
                    label         = { Text("activationKey（32位）") },
                    placeholder   = { Text("F17F24BCDC2A436B...") },
                    singleLine    = true,
                    keyboardOptions = KeyboardOptions(
                        capitalization = KeyboardCapitalization.Characters
                    ),
                    modifier      = Modifier.fillMaxWidth()
                )

                if (error.isNotEmpty()) {
                    Text(
                        text     = error,
                        color    = MaterialTheme.colorScheme.error,
                        fontSize = 13.sp
                    )
                }
            }
        },
        confirmButton = {
            TextButton(onClick = {
                // 验证
                val cleanMac = mac.trim()
                val cleanKey = key.trim().replace(" ", "")

                when {
                    cleanMac.isEmpty() -> error = "请输入MAC地址"
                    cleanKey.isEmpty() -> error = "请输入activationKey"
                    cleanKey.length != 32 -> error = "activationKey必须32位，当前${cleanKey.length}位"
                    runCatching { cleanKey.toLong(16) }.isFailure
                            && !cleanKey.all { it.isLetterOrDigit() } ->
                        error = "activationKey只能包含0-9和A-F"
                    else -> onConfirm(cleanMac, cleanKey, name)
                }
            }) {
                Text("确认")
            }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) {
                Text("取消")
            }
        }
    )
}
