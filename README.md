# Cyber-Physical "Liveness Lock" System

[![Project Status](https://img.shields.io/badge/Status-Active-success)](https://github.com/YOUR_USERNAME/cps-qr-lock)
[![Hardware](https://img.shields.io/badge/Hardware-ESP32--CAM-orange)](https://www.espressif.com/en/products/modules/esp32)
[![Language](https://img.shields.io/badge/Language-Python_/_Arduino-blue)](https://www.python.org/)
[![License: Unlicense](https://img.shields.io/badge/License-Unlicense-lightgrey.svg)](https://unlicense.org/)

A cybersecurity-focused "Stay Unlocked Only If Present" mechanism. This system uses an ESP32-CAM to continuously watch a computer screen, verifying a rotating, cryptographically signed QR code to ensure the user is physically present. If the camera loses sight of the code, the computer automatically locks the session.

## 📺 Project Demo
Click the image below to watch the full project walkthrough and live demonstration:

[![Cyber-Physical Locking System Demo](https://img.youtube.com/vi/mASB8XZ9sDI/0.jpg)](https://www.youtube.com/watch?v=mASB8XZ9sDI)

### 📑 Video Chapters
* **0:00** - What this build does (QR liveness lock overview)
* **0:20** - How the system stays “safe” and when it locks
* **0:38** - Hardware overview: ESP32-CAM watching the laptop screen
* **0:55** - Software overview: Windows overlay app + camera stream scanner
* **1:15** - QR token design: time-steps, nonces, and secret stamps

---

## 🚀 Key Features
* **Time-Stepped QR Rotation:** Generates a new QR token every 5 seconds using a TOTP-like mechanism.
* **Cryptographic Signing (HMAC-SHA256):** Prevents replay attacks; each code contains a timestamp, a random nonce, and a signature derived from a shared secret.
* **Live Video Analytics:** The Python client decodes the ESP32-CAM's MJPEG stream in real-time using OpenCV.
* **Automated Fail-Safe:** Attempts to trigger Windows `LockWorkStation` or Logoff if the valid QR is missed 3 times in a row.
* **Translucent Overlay:** A topmost, semi-transparent window that sits in the corner of your screen without blocking your workflow.

## 🛠️ System Architecture

### 1. Hardware Sensor (ESP32-CAM)
The ESP32-CAM acts as a dedicated liveness sensor. It runs a basic camera server that streams live video over the local network.
* **Resolution:** UXGA (initially drops to QVGA for performance).
* **Protocol:** HTTP MJPEG Stream.

### 2. Desktop Watchdog (Python)
The `main.py` application performs three primary roles:
1.  **Generation:** Creates a unique token in the format `CPS1.<step>.<nonce>.<mac16>`.
2.  **Verification:** Validates that the scanned QR matches the current display token and falls within the allowed drift.
3.  **Action:** Tracks the "Miss Count" and triggers system lock functions upon reaching the threshold.

## 📥 Installation & Setup

### 1. Hardware Preparation
* Connect an **ESP32-CAM** to your PC using an FTDI adapter.
* Open `esp32_firmware/CameraWebServer.ino`.
* Set your Wi-Fi credentials:
  ```cpp
  const char *ssid = "Your_SSID";
  const char *password = "Your_Password";
  ```

* Select your camera model in `board_config.h` and Flash the code.

### 2. Software Setup

1. **Dependencies:** Install the required Python libraries:
```bash
pip install qrcode[pil] pillow opencv-python

```


2. **Configuration:** Update the `STREAM_URL` and `SECRET_KEY` in `main.py` to match your ESP32's IP address and a secure random string.
3. **Run:**
```bash
python desktop_client/main.py

```



## 🔐 Cybersecurity Principles

* **Zero Trust:** Assumes the system is untrusted unless physical presence is verified via the camera.
* **Replay Protection:** Short 5-second rotation windows ensure that old QR codes cannot be used to keep the system open.
* **Hardware-Assisted Security:** Combines software-based logic with physical hardware (ESP32-CAM) for a multi-factor proximity check.

## 📜 License

This project is dedicated to the public domain under **The Unlicense**. You are free to copy, modify, and distribute it for any purpose.

---

*Developed by Rai Bahadur Singh.*
