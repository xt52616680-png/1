"""
demo_gui.py - Tkinter GUI 软件激活示例
=======================================

模拟一个带图形界面的桌面软件，包含：
  - 启动时检查激活态
  - 未激活时弹出激活对话框
  - 主界面显示授权信息
  - 后台周期性回调 keygen

适用场景：桌面应用、办公软件、专业工具

运行：
    cd /home/z/my-project/download/license-sdk-python/demos
    python demo_gui.py
"""

from __future__ import annotations

import os
import sys
import threading
import time
import tkinter as tk
from tkinter import messagebox

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from license_sdk import LicenseVerifier, LicenseConfig


class LicenseGuard:
    """集中管理授权验证逻辑。"""

    _instance = None

    def __init__(self):
        cfg = LicenseConfig(
            public_key_b64=os.environ.get(
                "LICENSE_ED25519_PUBKEY_B64",
                LicenseConfig().public_key_b64,
            ),
            keygen_url=os.environ.get("LICENSE_KEYGEN_URL", "http://localhost:3000"),
            software_version="demo-gui-1.0.0",
            refuse_in_vm=False,
        )
        self.verifier = LicenseVerifier(cfg)
        self._stop_event = threading.Event()

    @classmethod
    def instance(cls):
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    def preflight(self):
        return self.verifier.preflight()

    def status(self):
        return self.verifier.check_status()

    def activate(self, code: str):
        return self.verifier.activate(code)

    def start_callback_loop(self, on_event=None):
        def loop():
            while not self._stop_event.is_set():
                try:
                    result = self.verifier.do_callback()
                    if on_event:
                        on_event(result)
                    if result.status == "revoked":
                        if on_event:
                            on_event(None)
                        return
                except Exception as e:
                    if on_event:
                        on_event(e)
                self._stop_event.wait(6 * 3600)

        t = threading.Thread(target=loop, daemon=True)
        t.start()

    def stop(self):
        self._stop_event.set()


class ActivationDialog(tk.Toplevel):
    def __init__(self, parent, verifier_msg=""):
        super().__init__(parent)
        self.title("软件激活")
        self.geometry("560x420")
        self.resizable(False, False)
        self.transient(parent)
        self.grab_set()
        self.result = (False, "")
        self._build_ui(verifier_msg)
        self.protocol("WM_DELETE_WINDOW", self._on_cancel)

    def _build_ui(self, verifier_msg):
        header = tk.Frame(self, bg="#0f172a", height=80)
        header.pack(fill="x")
        tk.Label(header, text="DemoSoft Pro",
                 font=("Microsoft YaHei", 18, "bold"),
                 fg="#10b981", bg="#0f172a").pack(pady=20)

        body = tk.Frame(self, bg="white")
        body.pack(fill="both", expand=True, padx=24, pady=16)

        tk.Label(body, text="软件尚未激活",
                 font=("Microsoft YaHei", 14, "bold"),
                 fg="#1e293b", bg="white").pack(anchor="w")
        msg_text = f"原因: {verifier_msg}" if verifier_msg else "请输入您获得的激活码以解锁全部功能。"
        tk.Label(body, text=msg_text, font=("Microsoft YaHei", 9),
                 fg="#ef4444" if verifier_msg else "#64748b",
                 bg="white", wraplength=500, justify="left").pack(anchor="w", pady=(4, 12))

        tk.Label(body, text="激活码:", font=("Microsoft YaHei", 10),
                 fg="#475569", bg="white").pack(anchor="w")
        self.code_entry = tk.Text(body, height=4, font=("Consolas", 10),
                                   bg="#f8fafc", fg="#10b981",
                                   relief="solid", borderwidth=1, wrap="char")
        self.code_entry.pack(fill="x", pady=(4, 12))

        tk.Label(body, text="格式: XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-... (区分大小写)\n"
                            "支持卡类型: 时卡 / 月卡 / 季卡 / 年卡",
                 font=("Microsoft YaHei", 8),
                 fg="#94a3b8", bg="white", justify="left").pack(anchor="w")

        btns = tk.Frame(body, bg="white")
        btns.pack(fill="x", pady=(16, 0))
        tk.Button(btns, text="取消", width=10,
                  font=("Microsoft YaHei", 10), command=self._on_cancel).pack(side="right", padx=(8, 0))
        tk.Button(btns, text="激活", width=10,
                  font=("Microsoft YaHei", 10, "bold"),
                  bg="#10b981", fg="white",
                  activebackground="#059669", activeforeground="white",
                  relief="flat", command=self._on_activate).pack(side="right")

    def _on_activate(self):
        code = self.code_entry.get("1.0", "end").strip()
        if not code:
            messagebox.showwarning("提示", "请输入激活码", parent=self)
            return
        guard = LicenseGuard.instance()
        ok, msg = guard.activate(code)
        if ok:
            self.result = (True, msg)
            messagebox.showinfo("成功", f"激活成功!\n{msg}", parent=self)
            self.destroy()
        else:
            messagebox.showerror("激活失败", msg, parent=self)

    def _on_cancel(self):
        self.result = (False, "用户取消")
        self.destroy()


class MainWindow(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("DemoSoft Pro - 已授权")
        self.geometry("720x560")
        self.minsize(640, 480)
        self.configure(bg="#f8fafc")
        self._build_ui()
        self._refresh_status()
        LicenseGuard.instance().start_callback_loop(on_event=self._on_callback_event)

    def _build_ui(self):
        banner = tk.Frame(self, bg="#0f172a", height=80)
        banner.pack(fill="x")
        tk.Label(banner, text="DemoSoft Pro",
                 font=("Microsoft YaHei", 20, "bold"),
                 fg="#10b981", bg="#0f172a").pack(side="left", padx=24, pady=20)
        tk.Label(banner, text="Licensed ✓",
                 font=("Microsoft YaHei", 10),
                 fg="#94a3b8", bg="#0f172a").pack(side="right", padx=24)

        card = tk.Frame(self, bg="white", relief="solid", borderwidth=1)
        card.pack(fill="x", padx=24, pady=16)
        tk.Label(card, text="授权信息",
                 font=("Microsoft YaHei", 12, "bold"),
                 fg="#1e293b", bg="white").pack(anchor="w", padx=16, pady=(12, 4))
        self.status_label = tk.Label(card, text="加载中...",
                                      font=("Consolas", 9), fg="#475569", bg="white",
                                      justify="left", anchor="w")
        self.status_label.pack(anchor="w", padx=16, pady=(0, 12), fill="x")

        func_card = tk.Frame(self, bg="white", relief="solid", borderwidth=1)
        func_card.pack(fill="both", expand=True, padx=24, pady=(0, 16))
        tk.Label(func_card, text="软件功能",
                 font=("Microsoft YaHei", 12, "bold"),
                 fg="#1e293b", bg="white").pack(anchor="w", padx=16, pady=(12, 8))

        btns_frame = tk.Frame(func_card, bg="white")
        btns_frame.pack(fill="x", padx=16, pady=8)
        tk.Button(btns_frame, text="点击我",
                  font=("Microsoft YaHei", 10),
                  command=lambda: messagebox.showinfo("提示", "Hello from licensed software!")).pack(side="left", padx=(0, 8))
        tk.Button(btns_frame, text="刷新状态",
                  font=("Microsoft YaHei", 10),
                  command=self._refresh_status).pack(side="left", padx=(0, 8))
        tk.Button(btns_frame, text="测试回调",
                  font=("Microsoft YaHei", 10),
                  command=self._test_callback).pack(side="left", padx=(0, 8))
        tk.Button(btns_frame, text="撤销激活",
                  font=("Microsoft YaHei", 10), fg="#ef4444",
                  command=self._revoke).pack(side="left")

        log_frame = tk.Frame(func_card, bg="white")
        log_frame.pack(fill="both", expand=True, padx=16, pady=(8, 16))
        tk.Label(log_frame, text="日志:", font=("Microsoft YaHei", 9),
                 fg="#64748b", bg="white").pack(anchor="w")
        self.log_text = tk.Text(log_frame, height=10, font=("Consolas", 9),
                                 bg="#0f172a", fg="#e2e8f0",
                                 relief="flat", borderwidth=0)
        self.log_text.pack(fill="both", expand=True, pady=(4, 0))

        self.bottom_bar = tk.Frame(self, bg="#1e293b", height=24)
        self.bottom_bar.pack(fill="x", side="bottom")
        self.bottom_label = tk.Label(self.bottom_bar, text="就绪",
                                      font=("Microsoft YaHei", 8),
                                      fg="#94a3b8", bg="#1e293b")
        self.bottom_label.pack(side="left", padx=12)

    def _refresh_status(self):
        guard = LicenseGuard.instance()
        status = guard.status()
        if status.is_activated:
            info = (f"  激活码 ID : {status.code_id}\n"
                    f"  卡类型    : {status.card_type}\n"
                    f"  激活时间  : {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(status.activated_at))}\n"
                    f"  到期时间  : {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(status.expires_at))}\n"
                    f"  剩余天数  : {status.remaining_days} 天")
            self.status_label.config(text=info, fg="#10b981")
            self.bottom_label.config(text=f"✓ 已授权 · 剩余 {status.remaining_days} 天")
            self._log(f"状态已刷新: 剩余 {status.remaining_days} 天")
        else:
            self.status_label.config(text=f"未激活\n原因: {status.failure_reason}", fg="#ef4444")
            self.bottom_label.config(text="✗ 未授权")

    def _test_callback(self):
        self._log("正在执行回调...")
        guard = LicenseGuard.instance()
        try:
            result = guard.verifier.do_callback()
            self._log(f"回调结果: status={result.status}, "
                      f"server_time={result.server_time}, "
                      f"remaining={result.remaining_days}d, "
                      f"next_in={result.next_callback_in}s")
        except Exception as e:
            self._log(f"回调异常: {e}")

    def _revoke(self):
        if not messagebox.askyesno("确认", "确定要撤销本机激活吗？"):
            return
        guard = LicenseGuard.instance()
        ok, msg = guard.verifier.revoke()
        self._log(f"撤销: ok={ok}, msg={msg}")
        messagebox.showinfo("已撤销", msg)
        self.destroy()

    def _on_callback_event(self, event):
        if event is None:
            self.after(0, lambda: (messagebox.showerror("授权已吊销",
                "服务器返回 revoked 状态，软件即将退出。"), self.destroy()))
        elif isinstance(event, Exception):
            self.after(0, lambda: self._log(f"回调异常: {event}"))
        else:
            self.after(0, lambda: self._log(
                f"回调 {event.status}: {event.remaining_days}d 剩余"))

    def _log(self, msg: str):
        ts = time.strftime("%H:%M:%S")
        self.log_text.insert("end", f"[{ts}] {msg}\n")
        self.log_text.see("end")


def main():
    guard = LicenseGuard.instance()
    ok, reason = guard.preflight()
    if not ok:
        root = tk.Tk()
        root.withdraw()
        messagebox.showerror("安全检查失败",
            f"该软件不能在以下环境中运行:\n  {reason}\n\n请关闭调试器/虚拟机后重试。")
        sys.exit(10)

    status = guard.status()
    if not status.is_activated:
        root = tk.Tk()
        root.withdraw()
        dialog = ActivationDialog(root, status.failure_reason or "")
        root.wait_window(dialog)
        if not dialog.result[0]:
            messagebox.showerror("未激活", "软件需要激活才能运行。")
            sys.exit(11)
        root.destroy()

    app = MainWindow()
    try:
        app.mainloop()
    finally:
        guard.stop()


if __name__ == "__main__":
    main()
