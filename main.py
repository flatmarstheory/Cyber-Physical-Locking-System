import tkinter as tk
from tkinter.scrolledtext import ScrolledText
from PIL import Image, ImageTk
import qrcode
from qrcode.constants import ERROR_CORRECT_H
import time
import hmac
import hashlib
import secrets
import os
import datetime
import threading
import queue
import subprocess
import cv2

STREAM_URL = "http://192.168.100.131:81/stream"
SECRET_KEY = b"CHANGE_THIS_TO_A_LONG_RANDOM_SECRET_CHANGE_IT"

REFRESH_INTERVAL = 5
ALLOWED_STEP_DRIFT = 1
MISS_LIMIT = 3

# Smaller overlay-style window + translucency
WINDOW_W = 520
WINDOW_H = 620
ALPHA = 0.3
LOG_HEIGHT = 7

# QR tuned for distance (still reasonably large, but window smaller than before)
QR_SIZE = 420
QR_BOX_SIZE = 14
QR_BORDER = 4

LOCK_FILE = "SYSTEM_LOCKED.flag"

NO_QR_LOG_EVERY = 5
STREAM_FAIL_LOG_EVERY = 5
FRAME_READ_FAIL_LOG_EVERY = 3

# After a lock event, avoid immediately re-locking while user is returning
LOCK_COOLDOWN_SECONDS = 20

def now_str():
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def b36(n: int) -> str:
    chars = "0123456789abcdefghijklmnopqrstuvwxyz"
    if n == 0:
        return "0"
    out = []
    while n > 0:
        n, r = divmod(n, 36)
        out.append(chars[r])
    return "".join(reversed(out))

def current_step() -> int:
    return int(time.time() // REFRESH_INTERVAL)

def mac(step: int, nonce: str) -> str:
    msg = f"{step}|{nonce}".encode("utf-8")
    full = hmac.new(SECRET_KEY, msg, hashlib.sha256).hexdigest()
    return full[:16]

def make_token(step: int, nonce: str) -> str:
    return f"CPS1.{b36(step)}.{nonce}.{mac(step, nonce)}"

def parse_and_verify_token(token: str):
    try:
        parts = token.strip().split(".")
        if len(parts) != 4 or parts[0] != "CPS1":
            return (False, "bad_format", None, None, None)
        step_b36, nonce, sig = parts[1], parts[2], parts[3]
        step = int(step_b36, 36)
        expected = mac(step, nonce)
        sig_ok = hmac.compare_digest(expected, sig)
        drift = abs(current_step() - step)
        fresh_ok = drift <= ALLOWED_STEP_DRIFT
        ok = sig_ok and fresh_ok
        return (ok, "ok" if ok else "invalid", step, nonce, drift)
    except Exception as e:
        return (False, f"parse_error:{e}", None, None, None)

def generate_qr_image(token: str):
    qr = qrcode.QRCode(
        version=1,
        error_correction=ERROR_CORRECT_H,
        box_size=QR_BOX_SIZE,
        border=QR_BORDER,
    )
    qr.add_data(token)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    return img.resize((QR_SIZE, QR_SIZE))

def try_lock_windows():
    try:
        subprocess.run(["rundll32.exe", "user32.dll,LockWorkStation"], check=False)
        return True
    except Exception:
        return False

def try_logoff_windows():
    try:
        os.system("shutdown /l")
        return True
    except Exception:
        return False

class QRWatchdogApp:
    def __init__(self, root):
        self.root = root
        self.root.title("CPS QR Watchdog")
        self.root.geometry(f"{WINDOW_W}x{WINDOW_H}")
        self.root.resizable(False, False)

        self.root.attributes("-topmost", True)
        self.root.attributes("-alpha", ALPHA)
        self.root.protocol("WM_DELETE_WINDOW", self.disable_close)

        self.running = True
        self.log_q = queue.Queue()

        self.payload_lock = threading.Lock()
        self.current_token = None
        self.current_step_val = None
        self.current_seen_valid = False
        self.miss_count = 0

        self.locked = False
        self.lock_cooldown_until = 0.0

        # Reset any previous lock state so user returns to normal after relaunch/login
        if os.path.exists(LOCK_FILE):
            try:
                os.remove(LOCK_FILE)
            except Exception:
                pass

        self.root.configure(bg="white")

        self.qr_label = tk.Label(root, bg="white")
        self.qr_label.pack(padx=10, pady=(10, 6))

        self.status = tk.Label(root, text="SYSTEM ACTIVE", fg="green", bg="white", font=("Consolas", 14, "bold"))
        self.status.pack(pady=(0, 2))

        self.stream_status = tk.Label(root, text=f"STREAM: {STREAM_URL}", fg="gray25", bg="white", font=("Consolas", 9))
        self.stream_status.pack(pady=(0, 6))

        self.log_box = ScrolledText(root, height=LOG_HEIGHT, width=72, font=("Consolas", 9), state="disabled", wrap="word")
        self.log_box.pack(fill="both", expand=True, padx=10, pady=(0, 10))

        self.log("App started.")
        self.log(f"Topmost: ON | Alpha: {ALPHA} | Window: {WINDOW_W}x{WINDOW_H}")
        self.log(f"QR refresh: {REFRESH_INTERVAL}s | Miss limit: {MISS_LIMIT} | Drift: {ALLOWED_STEP_DRIFT} step(s)")
        self.log("Note: translucency can reduce QR readability; increase ALPHA if scanning is weak.")
        self.log(f"ESP32-CAM stream: {STREAM_URL}")
        self.log("Short QR payload for distance: CPS1.<step>.<nonce>.<mac16>")

        self.root.after(100, self.drain_logs)
        self.root.after(1500, self.enforce_topmost)

        self.scan_thread = threading.Thread(target=self.scan_stream_loop, daemon=True)
        self.scan_thread.start()

        self.schedule_refresh(first=True)

    def disable_close(self):
        self.log("Close attempt blocked (window close disabled).")

    def enforce_topmost(self):
        try:
            self.root.attributes("-topmost", True)
        except Exception:
            pass
        if self.running:
            self.root.after(1500, self.enforce_topmost)

    def log(self, msg: str):
        self.log_q.put(f"[{now_str()}] {msg}")

    def append_log_ui(self, line: str):
        self.log_box.configure(state="normal")
        self.log_box.insert("end", line + "\n")
        self.log_box.see("end")
        self.log_box.configure(state="disabled")

    def drain_logs(self):
        try:
            while True:
                line = self.log_q.get_nowait()
                self.append_log_ui(line)
        except queue.Empty:
            pass
        if self.running:
            self.root.after(100, self.drain_logs)

    def set_stream_status(self, text: str, color: str):
        def _set():
            self.stream_status.configure(text=text, fg=color)
        self.root.after(0, _set)

    def set_system_status(self, text: str, fg: str, bg: str):
        def _set():
            self.status.configure(text=text, fg=fg, bg=bg)
            self.root.configure(bg=bg)
            self.qr_label.configure(bg=bg)
            self.stream_status.configure(bg=bg)
        self.root.after(0, _set)

    def reset_scanning_state(self):
        with self.payload_lock:
            self.current_seen_valid = False
        self.miss_count = 0
        self.locked = False
        self.log("RESET: scanning state cleared (miss_count=0, locked=FALSE).")

    def trigger_lock(self, reason: str):
        if self.locked:
            return
        self.locked = True
        self.lock_cooldown_until = time.time() + LOCK_COOLDOWN_SECONDS

        self.log(f"LOCK TRIGGERED: {reason} (cooldown {LOCK_COOLDOWN_SECONDS}s)")
        try:
            with open(LOCK_FILE, "w", encoding="utf-8") as f:
                f.write(f"LOCKED: {reason}\n{now_str()}\n")
        except Exception as e:
            self.log(f"Lock file write failed: {e}")

        self.set_system_status(f"LOCKED ({reason})", "white", "red")

        # Let the UI paint red first, then lock/logoff, then reset counters so user returns normal after unlock/login.
        self.root.after(250, lambda: self._do_lock_actions(reason))

    def _do_lock_actions(self, reason: str):
        # Reset counters BEFORE/AFTER lock attempt so session returns normal on return
        self.miss_count = 0
        with self.payload_lock:
            self.current_seen_valid = False
        self.log("RESET (pre-lock): miss_count cleared so user can return normal after unlock/login.")

        locked_ok = try_lock_windows()
        self.log(f"Windows LockWorkStation attempt: {'sent' if locked_ok else 'failed'}")

        if not locked_ok:
            logoff_ok = try_logoff_windows()
            self.log(f"Windows logoff attempt: {'sent' if logoff_ok else 'failed'}")

        # Resume normal operation after cooldown (app may be paused by OS during lock/logoff; this still helps on return).
        self.root.after(int(LOCK_COOLDOWN_SECONDS * 1000), self._resume_after_lock)

    def _resume_after_lock(self):
        self.locked = False
        self.set_system_status("SYSTEM ACTIVE (POST-LOCK)", "green", "white")
        self.log("POST-LOCK: resuming normal scanning and QR rotation.")
        # Ensure next cycle starts clean
        self.miss_count = 0
        with self.payload_lock:
            self.current_seen_valid = False

    def evaluate_previous_miss(self):
        if self.current_step_val is None:
            return
        if time.time() < self.lock_cooldown_until:
            self.log("Cooldown active: miss evaluation skipped.")
            return
        if self.current_seen_valid:
            if self.miss_count != 0:
                self.log(f"Scan OK -> miss_count reset (was {self.miss_count}).")
            self.miss_count = 0
            return
        self.miss_count += 1
        self.log(f"MISS: no valid scan for step={self.current_step_val} (miss_count={self.miss_count}/{MISS_LIMIT}).")
        if self.miss_count >= MISS_LIMIT:
            self.trigger_lock(f"{MISS_LIMIT}_misses")

    def update_qr(self):
        if self.locked:
            return

        self.evaluate_previous_miss()

        step = current_step()
        nonce = secrets.token_hex(2)  # short nonce for simpler token
        token = make_token(step, nonce)

        img = generate_qr_image(token)
        self.tk_img = ImageTk.PhotoImage(img)
        self.qr_label.configure(image=self.tk_img)

        with self.payload_lock:
            self.current_token = token
            self.current_step_val = step
            self.current_seen_valid = False

        self.log(f"NEW QR: step={step} token='{token}'")

    def schedule_refresh(self, first=False):
        if first:
            self.log("Generating first QR now...")
        self.update_qr()
        self.root.after(REFRESH_INTERVAL * 1000, self.schedule_refresh)

    def scan_stream_loop(self):
        detector = cv2.QRCodeDetector()
        last_data = None

        last_noqr_log = 0.0
        last_stream_fail_log = 0.0
        last_frame_fail_log = 0.0

        while self.running:
            cap = cv2.VideoCapture(STREAM_URL)

            if not cap.isOpened():
                now = time.time()
                if now - last_stream_fail_log >= STREAM_FAIL_LOG_EVERY:
                    self.log("STREAM ERROR: cannot open ESP32-CAM stream (retrying).")
                    last_stream_fail_log = now
                self.set_stream_status("STREAM: DISCONNECTED (retrying...)", "red")
                time.sleep(1.5)
                continue

            self.set_stream_status("STREAM: CONNECTED (scanning...)", "green")
            self.log("STREAM CONNECTED: decoding frames.")

            while self.running and cap.isOpened():
                ret, frame = cap.read()
                if not ret or frame is None:
                    now = time.time()
                    if now - last_frame_fail_log >= FRAME_READ_FAIL_LOG_EVERY:
                        self.log("FRAME READ FAIL: no frame received (continuing).")
                        last_frame_fail_log = now
                    time.sleep(0.1)
                    continue

                data, _, _ = detector.detectAndDecode(frame)

                if data:
                    if data != last_data:
                        raw_preview = data if len(data) <= 200 else data[:200] + "...(truncated)"
                        self.log(f"ESP32CAM SCAN (decoded): {raw_preview}")

                        ok, why, step, nonce, drift = parse_and_verify_token(data)
                        with self.payload_lock:
                            cur_step = self.current_step_val
                            cur_token = self.current_token
                        matches_current = (cur_token == data)

                        if ok:
                            self.log(f"SCAN VERIFIED: step={step} drift={drift} matches_current_display={matches_current}")
                            if matches_current and cur_step == step and time.time() >= self.lock_cooldown_until:
                                with self.payload_lock:
                                    self.current_seen_valid = True
                            self.set_system_status("SYSTEM ACTIVE (SCAN OK)", "green", "white")
                        else:
                            self.log(f"SCAN FAILED: reason={why} step={step} drift={drift} matches_current_display={matches_current}")
                            # keep normal bg; only lock makes bg red
                            if time.time() >= self.lock_cooldown_until:
                                self.set_system_status("SYSTEM RISK (SCAN FAIL)", "orange", "white")

                        last_data = data
                else:
                    now = time.time()
                    if now - last_noqr_log >= NO_QR_LOG_EVERY:
                        self.log("ESP32CAM SCAN: no QR detected in view.")
                        last_noqr_log = now

                time.sleep(0.05)

            cap.release()
            self.set_stream_status("STREAM: DISCONNECTED (retrying...)", "red")
            self.log("STREAM DISCONNECTED: reconnecting.")
            time.sleep(1.0)

if __name__ == "__main__":
    # pip install qrcode[pil] pillow opencv-python
    root = tk.Tk()
    app = QRWatchdogApp(root)
    root.mainloop()
