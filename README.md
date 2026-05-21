# Intruder Detector

Linux background security daemon that watches your webcam **only while the lockscreen is active**, recognizes your face, and securely records evidence when someone else appears.

Built for real desktop use on Arch and other systemd-based distros — with encrypted storage, multi-pose enrollment, and a local history viewer.

## What is this?

**Intruder Detector** protects a locked Linux machine by:

1. Detecting when your lockscreen is active (Hyprlock, swaylock, i3lock, loginctl, DBus, etc.)
2. Turning on the webcam only during that time
3. Comparing faces in view to **your** enrolled face profile
4. If the face is **not** you → capturing several photos, **encrypting** them immediately, and logging an incident

It does **not** stream video anywhere. Everything stays on your machine under `~/.local/share/intruder-detector/`.

Typical use case: laptop left locked at home or office; you want to know if someone sat down in front of it.

---

## How it works

```
Login session
    │
    ├─► intruder-detector unlock     (vault key → tmpfs, see Quirks)
    │
    └─► daemon runs in background
            │
            ├─ Lockscreen OFF  → camera closed, idle
            │
            └─ Lockscreen ON   → camera on
                    │
                    ├─ Motion detected? (optional gate, saves CPU)
                    │
                    ├─ RetinaFace finds face → ArcFace embedding
                    │
                    ├─ Match enrolled profile?
                    │     YES → ignore (it's you unlocking / walking by)
                    │     NO  → burst 4 JPEGs → AES-256-GCM encrypt → SQLite log
                    │
                    └─ Unlock → camera off again
```

**Enrollment** (first run): you set a vault password and capture several head poses (front, left, right, up, down). Blur and lighting are checked so the profile is usable at the lockscreen.

**Recognition**: cosine similarity between live embeddings and your stored samples. Thresholds are tuned to favor **low false positives** (unknown people flagged rather than silently ignored).

---

## What it uses

| Layer | Technology |
|--------|------------|
| Face detection | [InsightFace](https://github.com/deepinsight/insightface) **RetinaFace** (`buffalo_l` ONNX pack) |
| Face recognition | **ArcFace** 512-d embeddings (same InsightFace pack) |
| Fallback detector | MediaPipe (if InsightFace fails to load) |
| Video | OpenCV + V4L2 webcam |
| Encryption | AES-256-GCM, PBKDF2-SHA256 (600k iterations) |
| Event index | SQLite (SQLAlchemy) |
| Lockscreen | `loginctl`, DBus ScreenSaver, process names |
| Dashboard | FastAPI + Uvicorn (local only) |
| CLI | Click + Rich |
| Service | systemd user unit |

Python **3.10+** recommended. Tested with 3.11–3.14; some optional deps may vary on bleeding-edge Python — use a venv if unsure.

---

## Requirements

### Hardware & OS

- Linux with **systemd / logind** (Arch, Fedora, Ubuntu, etc.)
- A **webcam** (`/dev/video0` or configurable index)
- Enough disk for InsightFace models (~500 MB first run, cached under `~/.insightface/`)

### System packages (Arch example)

```bash
sudo pacman -S python python-pip base-devel
sudo usermod -aG video $USER   # webcam access — log out and back in
```

### Python packages

Installed automatically via `pip install -e .` (see [requirements.txt](requirements.txt)).

Optional for better lockscreen detection on X11/Wayland:

```bash
pip install dbus-python
# or: pip install intruder-detector[linux]
```

---

## Download & install

### Clone from GitHub

```bash
git clone https://github.com/Just-Utkarsh/intruder.git
cd intruder-detector
```

Replace `YOUR_USERNAME` with your GitHub username when you publish the repo.

### Install (recommended: virtualenv)

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e .
```

Or use the helper script:

```bash
chmod +x scripts/install.sh
./scripts/install.sh
```

### Verify commands exist

```bash
intruder-detector --help
intruder-setup --help
intruder-history --help
```

---

## Quick start

### 1. First-time setup (password + face)

```bash
intruder-setup
```

Follow prompts: vault password (min 10 chars), then guided poses at the webcam.

### 2. Unlock vault each login session

The daemon needs a **session key** in RAM (not your password sitting in a file under home):

```bash
intruder-detector unlock
```

Add to compositor autostart (Hyprland example):

```bash
exec-once = intruder-detector unlock
```

### 3. Run the daemon

Foreground test:

```bash
intruder-detector daemon
```

Or enable systemd user service (after install script copies the unit):

```bash
systemctl --user enable --now intruder-detector
journalctl --user -u intruder-detector -f
```

### 4. Trigger a test (optional)

Lock the screen, let someone other than the enrolled user face the camera (or temporarily lower `similarity_threshold` in config for testing). Then:

```bash
intruder-history list
```

---

## Where data is stored

All persistent data:

```
~/.local/share/intruder-detector/
├── auth/
│   ├── master.salt          # KDF salt (not secret alone)
│   └── verifier.json        # password verifier hash
├── profile/
│   ├── profile.enc          # encrypted face embeddings
│   └── profile_meta.json    # non-sensitive metadata
├── incidents/
│   └── <uuid>/
│       ├── img_00.enc …     # encrypted JPEGs (never plaintext on disk)
│       └── meta.enc         # encrypted incident metadata
├── events.db                # SQLite index (IDs, times, confidence)
├── logs/
│   └── daemon.log
└── temp/                    # wiped after CLI view operations
```

Config overrides:

```
~/.config/intruder-detector/config.yaml
```

Session key (tmpfs, cleared on reboot / `intruder-detector lock`):

```
$XDG_RUNTIME_DIR/intruder-detector/session.key
```

---

## Using the dashboard

Local web UI to browse incidents and view decrypted images **in the browser only** (not written to disk).

```bash
cd intruder-detector
source .venv/bin/activate
python -c "from dashboard.app import run_dashboard; run_dashboard()"
```

Open: **http://127.0.0.1:8765**

1. Enter your **vault password** (same as setup).
2. Click **Load events**.
3. Click **View images** on an incident.

API docs: http://127.0.0.1:8765/api/docs

Alternative without activating venv paths:

```bash
python -m intruder_detector.cli.main --help   # main CLI
# Dashboard still needs:
python -c "from dashboard.app import run_dashboard; run_dashboard()"
```

---

## Commands reference

| Command | Purpose |
|---------|---------|
| `intruder-setup` | First-time password + face enrollment |
| `intruder-detector unlock` | Derive session key into tmpfs (required before daemon) |
| `intruder-detector lock` | Remove session key |
| `intruder-detector daemon` | Run monitoring loop |
| `intruder-history list` | List incidents |
| `intruder-history view <uuid>` | Decrypt & show images temporarily in terminal |
| `intruder-history delete <uuid>` | Delete incident + encrypted files |
| `intruder-profile add-samples --pose front` | Add more face samples (password required) |
| `intruder-profile reset` | Clear face profile (password required) |

Module form (if entry scripts break):

```bash
python -m intruder_detector unlock      # same as intruder-detector unlock
python -m intruder_detector.cli.setup   # setup
```


## Configuration

Copy defaults after install:

```bash
mkdir -p ~/.config/intruder-detector
cp configs/default.yaml ~/.config/intruder-detector/config.yaml
```

Useful knobs:

```yaml
recognition:
  similarity_threshold: 0.42   # higher = stricter “this is me”

intruder:
  burst_count: 4
  cooldown_between_incidents_sec: 30

lockscreen:
  process_names:
    - hyprlock
    - swaylock
    - i3lock
```

---

## Quirks & limitations

1. **`unlock` every session**  
   The daemon cannot prompt for your password in the background. You must run `intruder-detector unlock` after login (or via autostart). The derived key lives in **tmpfs** only.

2. **InsightFace model download**  
   First run downloads ONNX models (~500 MB). Needs network once.

3. **Lockscreen detection is heuristic**  
   Different compositors behave differently. If the daemon never arms, add your locker binary to `lockscreen.process_names` in config.

4. **Not a liveness / anti-spoof system**  
   Hooks exist for future anti-spoofing; a photo of your face could fool embedding match. Treat this as deterrent + evidence, not banking-grade auth.

5. **CPU use**  
   Motion gating helps, but face inference on CPU still costs power. Lower `camera.fps` or disable motion requirement only if needed.

6. **systemd `ExecStartPre=unlock` is commented out**  
   Unlock is interactive (password). Use compositor autostart or a login script instead.

7. **Dashboard password in query string**  
   Fine for `127.0.0.1` only; do not expose the dashboard to the network without HTTPS and a proper auth redesign.

8. **Python 3.14 / global `pip install`**  
   Prefer a project **venv** to avoid mismatched entry points and site-packages (see troubleshooting below).

---

## Troubleshooting

### `ModuleNotFoundError: No module named 'main'`

**Symptom** (after `pip install`):

```text
intruder-detector unlock
Traceback ...
ModuleNotFoundError: No module named 'main'
```

**Cause:** Older installs pointed the console script at `main:main`, but `main.py` is not an installed package module.

**Fix:** Reinstall from a current clone:

```bash
cd intruder-detector
pip install -e --force-reinstall .
```

Entry point is now `intruder_detector.cli.main:main`. Verify:

```bash
grep intruder-detector "$(python -c 'import sys; print(sys.prefix)')/lib/python*/site-packages/*.dist-info/entry_points.txt" 2>/dev/null || \
python -c "import importlib.metadata as m; print(m.entry_points(group='console_scripts'))"
```

**Workaround** without reinstalling scripts:

```bash
python -m intruder_detector unlock
python -m intruder_detector.cli.main unlock
```

---

### Camera permission denied

```bash
sudo usermod -aG video $USER
# log out completely, then back in
ls -l /dev/video0
```

---

### `Vault locked. Run: intruder-detector unlock`

Daemon started before unlock. Run `intruder-detector unlock`, then restart the daemon.

---

### No incidents in history

- Confirm lockscreen is detected (`journalctl --user -u intruder-detector -f`).
- Face must differ enough from enrolled profile (or adjust thresholds for testing).
- Motion gate may delay detection — set `intruder.require_motion_first: false` to test.

---

### False alarms (you flagged as intruder)

Raise `recognition.similarity_threshold` to `0.45`–`0.50` and add samples:

```bash
intruder-profile add-samples --pose front
```

---

### InsightFace / ONNX errors

```bash
pip install --upgrade insightface onnxruntime
```

Ensure `~/.insightface/models/` downloaded (rerun `intruder-setup` or any face command once with network).

---

## Contributing

Issues and PRs welcome on GitHub. Please do not commit real incident images or vault passwords.
