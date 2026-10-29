<div align="center">
  <h1>⚡ CAOP</h1>
  <p><strong>CYFARE's Android Optimizer Plus</strong></p>
  <p>Make Android feel faster, cleaner, and more private — no root required.</p>

  <a href="https://www.python.org/"><img src="https://img.shields.io/badge/Python-3.8%2B-3776AB?logo=python&logoColor=white" alt="Python 3.8+"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-MIT-green" alt="MIT license"></a>
  <img src="https://img.shields.io/badge/Root-Not%20Required-blueviolet" alt="No root required">
</div>

<br>

**CAOP** is a single-file Android optimization CLI powered by ADB. It combines sensible profiles, verified changes, rollback journals, ART compilation, responsiveness tuning, and an optional AI agent — with **zero Python dependencies**.

> [!IMPORTANT]
> Always review a `--dry-run` first. CAOP never uninstalls apps, clears app data, factory-resets, or gives an AI model shell access.

## ✨ Why CAOP?

| Feature | What you get |
|---|---|
| 🛡️ **Safety by default** | Allowlisted actions, protected-package checks, and verified writes |
| ↩️ **Rollback journals** | JSON records for restoring supported changes |
| 🔋 **Battery & privacy** | Reduce background scanning, telemetry, and unnecessary vendor features |
| 🚀 **Real responsiveness** | Animation, standby, freezer, cache, and ART/dex2oat controls |
| 🧠 **Optional AI agent** | Guardrailed automation with cloud or local LLMs — never a shell |
| 🌍 **Broad OEM support** | OnePlus, Samsung, Xiaomi, Huawei, Vivo, Motorola, Pixel, and more |
| 📦 **Clone & run** | Python standard library only; no `pip install` needed |

## 🚀 Quick start

**You need:** Python 3.8+, [Android platform-tools](https://developer.android.com/tools/releases/platform-tools), and USB debugging enabled.

```bash
git clone https://github.com/CYFARE/CAOP.git
cd CAOP

# 1. Connect and inspect your device
adb devices -l
python3 caop.py doctor
python3 caop.py scan

# 2. Preview the balanced profile
python3 caop.py optimize --profile balanced --dry-run

# 3. Apply only when the plan looks right
python3 caop.py optimize --profile balanced --yes
```

On Windows, use `python` instead of `python3`. If `adb` is not on your `PATH`, pass `--adb /path/to/adb`.

## 🎛️ Commands

| Command | Purpose |
|---|---|
| `doctor` | Check ADB, device state, and supported operations |
| `scan` | Inspect storage, memory, packages, settings, and thermals |
| `optimize` | Apply a conservative, balanced, or aggressive profile |
| `compile` | Batch-compile apps with ART/dex2oat and thermal safeguards |
| `boost` | Trade battery for maximum responsiveness |
| `kernel` | Audit tunables; optionally tune governors on rooted devices |
| `agent` | Let a guardrailed LLM choose from validated actions |
| `rollback` | List journals or restore supported changes |
| `providers` | Show supported AI providers and environment variables |
| `profiles` | List built-in vendor profiles |

Explore every option with:

```bash
python3 caop.py COMMAND --help
```

## 🎯 Optimization profiles

| Profile | Best for | Notes |
|---|---|---|
| `conservative` | A safe first pass | Telemetry, diagnostics, logging, and setup leftovers |
| `balanced` | Everyday use | Conservative plus optional vendor and Google features |
| `aggressive` | Advanced users | Adds riskier optional packages; requires `--allow-risky` |

User-installed apps are not touched unless you explicitly pass `--allow-user-apps`. Critical apps and known communication apps are protected.

## 🧠 Optional AI mode

Run locally with Ollama:

```bash
python3 caop.py agent --provider ollama --model qwen2.5:7b --dry-run
```

Or use a cloud provider:

```bash
export OPENAI_API_KEY="your-key"
python3 caop.py agent --provider openai --model gpt-4o-mini --dry-run
```

CAOP supports OpenAI, OpenRouter, Anthropic, Gemini, DeepSeek, Ollama, LM Studio, llama.cpp, and other OpenAI-compatible endpoints. Run `python3 caop.py providers` for the full catalogue.

## ↩️ Reports & rollback

Reports and journals are saved to `caop-reports/` by default.

```bash
python3 caop.py rollback --list
python3 caop.py rollback --latest --dry-run
python3 caop.py rollback --latest --yes
```

Package, setting, app-op, standby, Doze, and governor changes can be restored from their journals. Cache trims and ART compilation are reported but cannot be rolled back automatically.

## 📱 Compatibility

CAOP probes device capabilities instead of assuming them, with best-effort support from Android 4.x onward. It has been tested on a OnePlus device running Android 16 (API 36), without root. OEM and ROM behavior varies; `doctor` and `--dry-run` are the safest place to start.

## 🤝 Contribute

Bug reports, device compatibility results, and pull requests are welcome. See [Contributing](CONTRIBUTING.md) and the [full user guide](docs/USER_GUIDE.md).

## ⚠️ Disclaimer

Android optimization is device-specific. Review every plan, keep your journals, and back up important data. You are responsible for changes made to your device.

## 📄 License

Released under the [MIT License](LICENSE).

<div align="center">
  <strong>If CAOP improves your Android experience, please ⭐ the repository and share it!</strong>
</div>
