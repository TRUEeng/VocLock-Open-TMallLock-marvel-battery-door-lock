#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
TMall校园门锁工具 v4.1
- MAC精确匹配
- 自动从logcat提取key
- 密钥本地存储管理
- 重试机制
"""

import asyncio
import sys
import json
import os
import re
import subprocess
import time
from datetime import datetime
from typing import Optional, List, Dict
from bleak import BleakScanner, BleakClient
from bleak.backends.device import BLEDevice
from bleak.backends.scanner import AdvertisementData
from Crypto.Cipher import AES


# ==================== 配置 ====================

KEYS_FILE    = "lock_keys.json"
DEVICE_NAME  = "~vTmallLock"
WRITE_UUID   = "00002760-08c2-11e1-9073-0e8ac72e0001"
NOTIFY_UUID  = "00002760-08c2-11e1-9073-0e8ac72e0002"
ADB_PATH     = r"C:\platform-tools\adb.exe"   # ← 按实际修改


# ==================== 密钥数据库 ====================

class KeyStore:

    def __init__(self, filepath: str = KEYS_FILE):
        self.filepath = filepath
        self.data = self._load()

    def _load(self) -> dict:
        if os.path.exists(self.filepath):
            try:
                with open(self.filepath, 'r', encoding='utf-8') as f:
                    return json.load(f)
            except Exception:
                pass
        return {"locks": {}}

    def _save(self):
        self.data["last_updated"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with open(self.filepath, 'w', encoding='utf-8') as f:
            json.dump(self.data, f, indent=2, ensure_ascii=False)

    def add_lock(self, mac: str, key: str, name: str = ""):
        mac = mac.upper()
        old = self.data["locks"].get(mac, {})
        self.data["locks"][mac] = {
            "activation_key": key.upper(),
            "name":           name or old.get("name", "未命名"),
            "added":          old.get("added", datetime.now().strftime("%Y-%m-%d %H:%M:%S")),
            "unlock_count":   old.get("unlock_count", 0),
            "last_unlock":    old.get("last_unlock", None),
        }
        self._save()
        print(f"[+] 已保存: {mac} → {self.data['locks'][mac]['name']}")

    def get_key(self, mac: str) -> Optional[str]:
        info = self.data["locks"].get(mac.upper())
        return info["activation_key"] if info else None

    def record_unlock(self, mac: str):
        mac = mac.upper()
        if mac in self.data["locks"]:
            self.data["locks"][mac]["unlock_count"] += 1
            self.data["locks"][mac]["last_unlock"] = \
                datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            self._save()

    def list_locks(self) -> Dict:
        return self.data["locks"]

    def remove_lock(self, mac: str):
        mac = mac.upper()
        if mac in self.data["locks"]:
            del self.data["locks"][mac]
            self._save()

    def rename_lock(self, mac: str, name: str):
        mac = mac.upper()
        if mac in self.data["locks"]:
            self.data["locks"][mac]["name"] = name
            self._save()


# ==================== 加密模块 ====================

class Crypto:

    @staticmethod
    def hex2bytes(h: str) -> bytes:
        return bytes.fromhex(h.replace(" ", "").replace(":", ""))

    @staticmethod
    def bytes2hex(b: bytes) -> str:
        return b.hex().upper()

    @staticmethod
    def crc8(hex_str: str) -> str:
        s = hex_str.replace(" ", "")
        total = sum(int(s[i:i+2], 16) for i in range(0, len(s), 2))
        return f"{total & 0xFF:02X}"

    @staticmethod
    def xor_key(random_hex: str, activation_hex: str) -> str:
        r = random_hex.upper()
        k = activation_hex.upper()
        return "".join(
            f"{int(r[i:i+2], 16) ^ int(k[i:i+2], 16):02X}"
            for i in range(0, 32, 2)
        )

    @staticmethod
    def aes_encrypt(plaintext_hex: str, key_hex: str) -> str:
        key  = Crypto.hex2bytes(key_hex)[:16]
        data = Crypto.hex2bytes(plaintext_hex)
        return Crypto.bytes2hex(AES.new(key, AES.MODE_ECB).encrypt(data))

    @staticmethod
    def aes_decrypt(ciphertext_hex: str, key_hex: str) -> str:
        key  = Crypto.hex2bytes(key_hex)[:16]
        data = Crypto.hex2bytes(ciphertext_hex)
        return Crypto.bytes2hex(AES.new(key, AES.MODE_ECB).decrypt(data))

    @staticmethod
    def build_packet(cmd_hex: str, session_key: str) -> str:
        """通用加密打包: 55AA + len(2B) + AES(plaintext) + CRC"""
        crc      = Crypto.crc8("55AA" + cmd_hex)
        plain    = (cmd_hex + crc).ljust(32, '0')
        cipher   = Crypto.aes_encrypt(plain, session_key)
        length   = f"{len(cipher) // 2:04X}"
        packet   = "55AA" + length + cipher
        return (packet + Crypto.crc8(packet)).upper()

    @staticmethod
    def build_unlock_packet(random_hex: str, activation_key: str) -> str:
        session_key = Crypto.xor_key(random_hex, activation_key)
        return Crypto.build_packet("FF0B0000", session_key)


# ==================== BLE 管理器 ====================

class BleManager:

    def __init__(self):
        self.client: Optional[BleakClient] = None
        self.buffer  = bytearray()
        self.event   = asyncio.Event()
        self._scan_results: Dict[str, dict] = {}

    # ── 扫描 ──────────────────────────────────────────

    def _on_adv(self, device: BLEDevice, adv: AdvertisementData):
        if device.name == DEVICE_NAME:
            self._scan_results[device.address.upper()] = {
                "address": device.address,
                "rssi":    adv.rssi,
            }

    async def scan(self, timeout: int = 8,
                   target: Optional[str] = None) -> List[dict]:
        """
        扫描门锁。
        target: 指定 BLE 地址，找到即刻返回（快速模式）。
        """
        self._scan_results.clear()

        if target:
            print(f"[*] 快速扫描 {target}（最多 {timeout}s）...")
        else:
            print(f"[*] 扫描所有门锁（{timeout}s）...")

        scanner = BleakScanner(detection_callback=self._on_adv)
        await scanner.start()

        deadline = time.time() + timeout
        while time.time() < deadline:
            await asyncio.sleep(0.3)
            if target and target.upper() in self._scan_results:
                break

        await scanner.stop()

        results = sorted(
            self._scan_results.values(),
            key=lambda x: x["rssi"], reverse=True
        )

        if results:
            print(f"[+] 发现 {len(results)} 个门锁:")
            for r in results:
                print(f"    {r['address']}  RSSI:{r['rssi']}dBm")
        else:
            print("[-] 未发现门锁")

        return results

    # ── 连接 ──────────────────────────────────────────

    async def connect(self, address: str, retries: int = 3) -> bool:
        for attempt in range(1, retries + 1):
            try:
                print(f"[*] 连接 {address}（第 {attempt} 次）...")
                self.client = BleakClient(address, timeout=12)
                await self.client.connect()

                # 启动 Notify
                try:
                    await self.client.start_notify(NOTIFY_UUID, self._on_notify)
                except Exception:
                    # 找到第一个 notify 特征
                    for svc in self.client.services:
                        for ch in svc.characteristics:
                            if "notify" in ch.properties:
                                await self.client.start_notify(ch.uuid, self._on_notify)
                                break

                print("[+] 连接成功")
                return True

            except Exception as e:
                print(f"[-] 连接失败: {e}")
                await self._safe_disconnect()
                if attempt < retries:
                    wait = attempt * 2
                    print(f"[*] {wait}s 后重试...")
                    await asyncio.sleep(wait)

        return False

    async def _safe_disconnect(self):
        if self.client:
            try:
                await self.client.disconnect()
            except Exception:
                pass
            self.client = None

    # ── 通知 ──────────────────────────────────────────

    def _on_notify(self, _sender, data: bytearray):
        self.buffer.extend(data)
        self.event.set()

    # ── 发送 / 接收 ───────────────────────────────────

    async def send(self, hex_cmd: str,
                   collect_ms: int = 800) -> Optional[str]:
        """
        发送命令（自动分包），等待 collect_ms 毫秒收集响应。
        返回收到的全部数据（hex 字符串），无响应返回 None。
        """
        if not self.client or not self.client.is_connected:
            print("[-] 未连接")
            return None

        self.buffer.clear()
        self.event.clear()

        raw = Crypto.hex2bytes(hex_cmd)

        # 写特征：先用已知 UUID，失败则自动查找
        async def write_chunk(chunk: bytes):
            try:
                await self.client.write_gatt_char(WRITE_UUID, chunk,
                                                  response=False)
            except Exception:
                for svc in self.client.services:
                    for ch in svc.characteristics:
                        if "write" in ch.properties or \
                           "write-without-response" in ch.properties:
                            await self.client.write_gatt_char(ch.uuid, chunk,
                                                              response=False)
                            return

        for i in range(0, len(raw), 20):
            await write_chunk(raw[i:i + 20])
            if i + 20 < len(raw):
                await asyncio.sleep(0.05)

        # 等待响应（最多 collect_ms，但每次收到数据后再等一段）
        deadline = time.time() + collect_ms / 1000
        while time.time() < deadline:
            self.event.clear()
            remaining = deadline - time.time()
            if remaining <= 0:
                break
            try:
                await asyncio.wait_for(self.event.wait(),
                                       timeout=min(remaining, 0.3))
                # 收到数据，延长等待以接收续帧
                deadline = max(deadline, time.time() + 0.3)
            except asyncio.TimeoutError:
                break

        if self.buffer:
            result = Crypto.bytes2hex(bytes(self.buffer))
            return result
        return None

    # ── 断开 ──────────────────────────────────────────

    async def disconnect(self):
        await self._safe_disconnect()
        print("[*] 已断开")


# ==================== Key 提取器 ====================

class KeyExtractor:

    @staticmethod
    def _adb(*args, timeout: int = 8):
        try:
            return subprocess.run(
                [ADB_PATH] + list(args),
                capture_output=True, text=True,
                encoding='utf-8', errors='replace',
                timeout=timeout
            )
        except FileNotFoundError:
            print(f"[-] 找不到 adb: {ADB_PATH}")
        except subprocess.TimeoutExpired:
            print(f"[-] adb 命令超时")
        return None

    @staticmethod
    def check_adb() -> bool:
        r = KeyExtractor._adb("devices")
        if r and r.returncode == 0:
            devs = [l for l in r.stdout.splitlines()[1:]
                    if l.strip() and "device" in l and "unauthorized" not in l]
            if devs:
                print(f"[+] ADB 设备: {devs[0].split()[0]}")
                return True
        print("[-] 未检测到设备，请确认 USB 调试已开启并已授权")
        return False

    # 正则：匹配 logcat 里的 unlock 行
    _PAT = re.compile(
        r'unlock[:\s]+macAddress[:\s]+([0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5})'
        r'[^\n]*?activationKey[:\s]+([0-9A-Fa-f]{32})',
        re.IGNORECASE
    )

    @classmethod
    def from_logcat(cls, duration: int = 60) -> List[dict]:
        print(f"\n{'='*50}")
        print("实时提取密钥")
        print(f"{'='*50}")
        print(f"[*] 监听 {duration}s，请在手机上逐一开锁，按 Ctrl+C 提前停止\n")

        if not cls.check_adb():
            return []

        # 清空缓存
        cls._adb("logcat", "-c", timeout=5)
        time.sleep(0.8)

        try:
            proc = subprocess.Popen(
                [ADB_PATH, "logcat", "-v", "brief",
                 "-s", "VocLockHelperV2:D"],
                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                text=True, encoding='utf-8', errors='replace'
            )
        except Exception as e:
            print(f"[-] 启动 logcat 失败: {e}")
            return []

        found, seen = [], set()
        t0 = time.time()
        last_tip = 0

        try:
            while time.time() - t0 < duration:
                if proc.poll() is not None:
                    print("[-] logcat 进程意外退出")
                    break

                line = proc.stdout.readline()
                if not line:
                    time.sleep(0.05)
                    continue

                m = cls._PAT.search(line)
                if m:
                    mac = m.group(1).upper()
                    key = m.group(2).upper()
                    if mac not in seen:
                        seen.add(mac)
                        found.append({"mac": mac, "key": key})
                        elapsed = time.time() - t0
                        print(f"  🔑 [{elapsed:.0f}s] MAC={mac}  Key={key}")

                # 每 15s 提示一次
                elapsed = int(time.time() - t0)
                if elapsed % 15 == 0 and elapsed != last_tip and elapsed > 0:
                    last_tip = elapsed
                    print(f"  ⏱  {elapsed}s / {duration}s  已发现 {len(found)} 个")

        except KeyboardInterrupt:
            print("\n[*] 用户中断")
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=3)
            except Exception:
                proc.kill()

        return found

    @classmethod
    def from_file(cls, filepath: str) -> List[dict]:
        print(f"[*] 从文件提取: {filepath}")
        found, seen = [], set()

        for enc in ('utf-8', 'utf-16', 'utf-16-le', 'gbk', 'latin-1'):
            try:
                with open(filepath, 'r', encoding=enc, errors='replace') as f:
                    for line in f:
                        m = cls._PAT.search(line)
                        if m:
                            mac = m.group(1).upper()
                            key = m.group(2).upper()
                            if mac not in seen:
                                seen.add(mac)
                                found.append({"mac": mac, "key": key})
                if found:
                    break
            except Exception:
                continue

        if found:
            for item in found:
                print(f"  🔑 MAC={item['mac']}  Key={item['key']}")
        else:
            print("[-] 未找到密钥")

        return found


# ==================== 开锁引擎 ====================

class UnlockEngine:

    def __init__(self, ble: BleManager, store: KeyStore):
        self.ble   = ble
        self.store = store

    # ── 随机数提取 ────────────────────────────────────

    @staticmethod
    def _extract_random(resp: str) -> Optional[str]:
        """
        从设备响应中提取 16 字节随机数（hex 32 位）。
        日志格式: 55AAFF0D0011 00 <16B随机数> [续帧...]
        """
        r = resp.upper().replace(" ", "")

        # 找到随机数帧头
        idx = r.find("55AAFF0D0011")
        if idx == -1:
            return None

        # 帧头(12) + 标志字节(2) = 偏移 14
        start = idx + 14
        chunk = r[start:]

        # 响应可能分两帧到达，把所有数据拼在一起后取前 32 位
        if len(chunk) >= 32:
            return chunk[:32]
        return None

    # ── 完整开锁流程 ──────────────────────────────────

    async def unlock(self, mac: str, activation_key: str) -> bool:
        print(f"\n{'='*50}")
        print(f"🔓  开锁目标: {mac}")
        print(f"{'='*50}")

        # 1. 扫描
        results = await self.ble.scan(timeout=8, target=mac)

        # 优先精确匹配 MAC
        target_addr = None
        for r in results:
            if r["address"].upper() == mac.upper():
                target_addr = r["address"]
                print(f"[+] 精确匹配: {target_addr}")
                break

        if not target_addr:
            if results:
                target_addr = results[0]["address"]
                print(f"[!] 未精确匹配，使用信号最强: {target_addr}")
            else:
                print("[-] 未扫描到任何门锁")
                return False

        # 2. 连接
        if not await self.ble.connect(target_addr):
            return False

        await asyncio.sleep(0.3)

        try:
            # ── 步骤 1：请求随机数 ──
            print("\n[1/3] 请求随机数...")
            resp = await self.ble.send("55AAFF0D00000B", collect_ms=1000)
            if not resp:
                print("[-] 无响应")
                return False
            print(f"    ← {resp}")

            rand = self._extract_random(resp)
            if not rand:
                print(f"[-] 提取随机数失败，原始: {resp}")
                return False
            print(f"    随机数: {rand}")

            # ── 步骤 2：建立加密链接 ──
            print("\n[2/3] 建立加密链接...")
            resp = await self.ble.send("55AAFF13000011", collect_ms=1000)
            if not resp:
                print("[-] 无响应")
                return False
            print(f"    ← {resp}")

            session_key = Crypto.xor_key(rand, activation_key)
            print(f"    会话密钥: {session_key}")

            # 验证握手响应
            r = resp.upper()
            idx = r.find("55AA0010")
            if idx != -1:
                cipher = r[idx + 8: idx + 8 + 32]
                if len(cipher) == 32:
                    plain = Crypto.aes_decrypt(cipher, session_key)
                    print(f"    解密: {plain}")
                    if plain.startswith("FF130001"):
                        print("    ✅ 链接建立成功")
                    else:
                        print("    [!] 链接响应异常，继续尝试...")

            # ── 步骤 3：发送开锁指令 ──
            print("\n[3/3] 发送开锁指令...")
            pkt = Crypto.build_unlock_packet(rand, activation_key)
            print(f"    → {pkt}")
            resp = await self.ble.send(pkt, collect_ms=1200)
            if not resp:
                print("[-] 无响应")
                return False
            print(f"    ← {resp}")

            # 解析结果
            success = False
            r = resp.upper()
            idx = r.find("55AA0010")
            if idx != -1:
                cipher = r[idx + 8: idx + 8 + 32]
                if len(cipher) == 32:
                    plain = Crypto.aes_decrypt(cipher, session_key)
                    print(f"    解密: {plain}")
                    # FF 0B 00 01 00 0A … → 开锁成功
                    if plain[:12] == "FF0B0001000A":
                        success = True

            if success:
                print("\n🎉🎉🎉  开锁成功！")
                self.store.record_unlock(mac)
            else:
                print("\n❌  开锁失败（响应异常）")

            return success

        finally:
            await self.ble.disconnect()


# ==================== 主界面 ====================

class App:

    def __init__(self):
        self.store  = KeyStore()
        self.ble    = BleManager()
        self.engine = UnlockEngine(self.ble, self.store)

    # ── 显示 ──────────────────────────────────────────

    @staticmethod
    def _banner():
        print("""
╔══════════════════════════════════════════════╗
║      天猫校园门锁工具  v4.1                  ║
║      MAC精确匹配 | 密钥管理 | 自动提取        ║
╚══════════════════════════════════════════════╝""")

    def _show_locks(self):
        locks = self.store.list_locks()
        if not locks:
            print("[*] 暂无保存的门锁\n")
            return
        print("\n已保存的门锁:")
        print("-" * 62)
        for i, (mac, info) in enumerate(locks.items(), 1):
            name  = info.get("name", "未命名")
            cnt   = info.get("unlock_count", 0)
            last  = info.get("last_unlock") or "从未"
            short = info["activation_key"][:8] + "..."
            print(f"  {i:2d}. [{mac}]  {name}")
            print(f"       Key:{short}  开锁{cnt}次  上次:{last}")
        print("-" * 62)

    @staticmethod
    def _menu():
        print("""
功能菜单:
  1. 🔓  快速开锁
  2. 🔑  实时提取密钥（USB）
  3. 📁  从日志文件提取密钥
  4. ✏️   手动添加门锁
  5. 📋  管理已保存的门锁
  6. 📡  扫描附近门锁
  7. 🧪  协议验证
  0. 退出""")

    # ── 功能 1：快速开锁 ──────────────────────────────

    async def _quick_unlock(self):
        locks = self.store.list_locks()
        if not locks:
            print("[-] 没有已保存的门锁")
            return

        self._show_locks()
        lock_list = list(locks.items())

        try:
            choice = int(input("选择编号 (0返回): ").strip())
        except (ValueError, KeyboardInterrupt):
            return

        if choice == 0:
            return
        if not (1 <= choice <= len(lock_list)):
            print("[-] 无效编号")
            return

        mac, info = lock_list[choice - 1]
        await self.engine.unlock(mac, info["activation_key"])

    # ── 功能 2：实时提取 ──────────────────────────────

    def _live_extract(self):
        print("\n说明: 手机 USB 连接电脑，对每扇门点一次开锁即可抓到 key")
        try:
            duration = int(input("监听时长（秒，默认 60）: ").strip() or "60")
        except Exception:
            duration = 60

        keys = KeyExtractor.from_logcat(duration)
        self._save_extracted(keys)

    # ── 功能 3：文件提取 ──────────────────────────────

    def _file_extract(self):
        path = input("日志文件路径（如 log.txt）: ").strip()
        if not os.path.exists(path):
            print(f"[-] 文件不存在: {path}")
            return
        keys = KeyExtractor.from_file(path)
        self._save_extracted(keys)

    def _save_extracted(self, keys: List[dict]):
        if not keys:
            return
        print(f"\n共提取 {len(keys)} 个密钥")
        ans = input("全部保存？(Y/n): ").strip().lower()
        if ans == 'n':
            return
        for item in keys:
            existing = self.store.get_key(item["mac"])
            if existing:
                print(f"  [{item['mac']}] 已存在 key:{existing[:8]}...")
                ans2 = input("  覆盖并重命名？(y/N): ").strip().lower()
                if ans2 != 'y':
                    continue
            name = input(f"  给 {item['mac']} 起个名字: ").strip()
            self.store.add_lock(item["mac"], item["key"], name)

    # ── 功能 4：手动添加 ──────────────────────────────

    def _manual_add(self):
        mac  = input("MAC 地址 (如 94:36:70:56:34:12): ").strip()
        key  = input("activationKey (32位 hex): ").strip().replace(" ", "")
        name = input("名称 (如 宿舍门): ").strip()

        if len(key) != 32:
            print("[-] 密钥长度必须为 32 位")
            return
        try:
            int(key, 16)
        except ValueError:
            print("[-] 密钥必须为十六进制")
            return

        self.store.add_lock(mac, key, name)

    # ── 功能 5：管理门锁 ──────────────────────────────

    def _manage(self):
        locks = self.store.list_locks()
        if not locks:
            print("[-] 暂无门锁")
            return

        self._show_locks()
        lock_list = list(locks.items())

        print("操作: d<编号>=删除  r<编号>=重命名  回车=返回")
        action = input("操作: ").strip().lower()

        if not action:
            return

        op  = action[0]
        num = action[1:]

        try:
            idx = int(num) - 1
            assert 0 <= idx < len(lock_list)
        except Exception:
            print("[-] 无效操作")
            return

        mac = lock_list[idx][0]

        if op == 'd':
            if input(f"确认删除 {mac}？(y/N): ").strip().lower() == 'y':
                self.store.remove_lock(mac)
                print("[+] 已删除")

        elif op == 'r':
            new_name = input("新名称: ").strip()
            if new_name:
                self.store.rename_lock(mac, new_name)
                print("[+] 已重命名")

    # ── 功能 6：扫描附近 ──────────────────────────────

    async def _scan_nearby(self):
        results = await self.ble.scan(timeout=10)
        if not results:
            return
        print()
        for i, r in enumerate(results, 1):
            addr  = r["address"]
            rssi  = r["rssi"]
            saved = self.store.get_key(addr)
            tag   = "✅ 已有密钥" if saved else "❓ 未知"
            print(f"  {i}. {addr}  RSSI:{rssi}dBm  {tag}")

    # ── 功能 7：协议验证 ──────────────────────────────

    @staticmethod
    def _verify():
        print(f"\n{'='*52}")
        print("协议验证（使用真实日志数据）")
        print(f"{'='*52}")

        AK = "F17F24BCDC2A436B0B746457C0DD0168"

        cases = [
            {
                "round": 1,
                "random":    "F0590B572FFC2F1A82EAA0F00C4D0E14",
                "build_log": "01262FEBF3D66C71899EC4A7CC900F7C",
                "ct_log":    "9D327C7CB4B4C642B6F12BD739A2DC23",
            },
            {
                "round": 2,
                "random":    "D783C8BFFD02808DE6304C29AA48675D",
                "build_log": "26FCEC032128C3E6ED44287E6A956635",
                "ct_log":    "693E7B653D6BBF56EB12C7EAEED14DC6",
            },
        ]

        all_ok = True
        for c in cases:
            rnd = c["random"]
            sk  = Crypto.xor_key(rnd, AK)
            print(f"\n── 第 {c['round']} 次 ──")
            print(f"  随机数:     {rnd}")
            print(f"  会话密钥:   {sk}")
            r1 = sk == c["build_log"]
            print(f"  build 匹配: {'✅' if r1 else '❌'} (日志: {c['build_log']})")

            content = "FF0B0000"
            crc     = Crypto.crc8("55AA" + content)
            pt      = (content + crc).ljust(32, '0')
            ct      = Crypto.aes_encrypt(pt, sk)
            r2 = ct == c["ct_log"]
            print(f"  密文:       {ct}")
            print(f"  密文匹配:   {'✅' if r2 else '❌'} (日志: {c['ct_log']})")

            if not (r1 and r2):
                all_ok = False

        print(f"\n{'='*52}")
        print(f"总结: {'✅ 全部通过，可以实战开锁！' if all_ok else '❌ 存在不匹配，请检查算法'}")
        print(f"{'='*52}")

    # ── 主循环 ────────────────────────────────────────

    async def run(self):
        self._banner()
        self._show_locks()

        # 检测到 log.txt 且无已保存数据时自动导入
        if os.path.exists("log.txt") and not self.store.list_locks():
            print("[*] 检测到 log.txt，尝试自动导入...")
            keys = KeyExtractor.from_file("log.txt")
            if keys:
                for item in keys:
                    name = input(f"  给 {item['mac']} 起个名字（回车跳过）: ").strip()
                    self.store.add_lock(item["mac"], item["key"], name or "自动导入")
                self._show_locks()

        while True:
            self._menu()
            try:
                choice = input("\n选择: ").strip()
            except (KeyboardInterrupt, EOFError):
                break

            if   choice == "0": break
            elif choice == "1": await self._quick_unlock()
            elif choice == "2": self._live_extract()
            elif choice == "3": self._file_extract()
            elif choice == "4": self._manual_add()
            elif choice == "5": self._manage()
            elif choice == "6": await self._scan_nearby()
            elif choice == "7": self._verify()
            else: print("[-] 无效选择")

        print("\n再见！")


# ==================== 入口 ====================

if __name__ == "__main__":
    if sys.platform == "win32":
        asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())
    asyncio.run(App().run())