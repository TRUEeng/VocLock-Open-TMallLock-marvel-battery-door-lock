package com.voc.lock

import android.content.Context
import com.google.zgson.Gson

data class LockInfo(
    val mac:           String,
    val activationKey: String,
    var name:          String = "我的门锁",
    var unlockCount:   Int    = 0,
    var lastUnlock:    String = "从未"
)

class LockRepository(context: Context) {

    private val prefs = context.getSharedPreferences("voc_lock", Context.MODE_PRIVATE)
    private val gson  = Gson()

    fun getLock(): LockInfo? {
        val json = prefs.getString("lock", null) ?: return null
        return try {
            gson.fromJson(json, LockInfo::class.java)
        } catch (e: Exception) {
            null
        }
    }

    fun saveLock(lock: LockInfo) {
        prefs.edit().putString("lock", gson.toJson(lock)).apply()
    }

    fun deleteLock() {
        prefs.edit().remove("lock").apply()
    }

    fun recordUnlock() {
        val lock = getLock() ?: return
        val updated = lock.copy(
            unlockCount = lock.unlockCount + 1,
            lastUnlock  = java.text.SimpleDateFormat(
                "MM-dd HH:mm",
                java.util.Locale.getDefault()
            ).format(java.util.Date())
        )
        saveLock(updated)
    }

    fun hasLock(): Boolean = getLock() != null
}
