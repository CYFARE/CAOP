# CAOP User Guide

**CAOP — CYFARE's Android Optimizer Plus** is a single-file, no-root Android optimizer
driven entirely through ADB, plus an optional LLM agent that can inspect the device and
choose from a small, validated action set.

It **never uninstalls apps, never clears app data, never factory-resets, and never runs
arbitrary shell commands**. Supported reversible changes are recorded in a JSON journal.

Tested against a OnePlus CPH2767 running Android 16 (API 36), no root, with the
`shell` UID (the normal ADB user). It is designed to degrade gracefully on older
Android versions and on ROMs that block specific commands.

---

## Requirements

- Python **3.8+**. No `pip install` is required; the script uses only the standard library.
- Android platform-tools (`adb`) on `PATH`, or pass `--adb /path/to/adb`.
- USB debugging enabled and the RSA prompt accepted on the phone.
- Linux, macOS, or Windows. On Windows, use `python` instead of `python3`.

Check the connection first:

```bash
adb devices -l
python3 caop.py doctor
```

`doctor` prints the Android version, SDK, root state, storage, memory, default
launcher/SMS/dialer, and which operations the shell UID is actually allowed to perform.

---

## Quick start

Always start with a dry run:

```bash
python3 caop.py scan
python3 caop.py optimize --profile balanced --dry-run
```

Apply the safe baseline when the plan looks right:

```bash
python3 caop.py optimize --profile balanced --yes
```

See the advanced app-compilation plan, the kernel audit, and the responsiveness plan:

```bash
python3 caop.py compile --mode speed-profile --scope third_party --dry-run
python3 caop.py kernel
python3 caop.py boost --profile fast --dry-run
```

Then optionally use the agent for adaptive decisions:

```bash
export OPENAI_API_KEY="sk-..."
python3 caop.py agent --provider openai --model gpt-4o-mini --yes
```

Or, fully local:

```bash
ollama serve                     # in another terminal, if not already running
python3 caop.py agent --provider ollama --model qwen2.5:7b --dry-run
```

Roll back the newest run:

```bash
python3 caop.py rollback --latest --dry-run
python3 caop.py rollback --latest --yes
```

---

## What the optimizer does

### Profiles

Profiles are cumulative:

| Profile | Risk | Contents |
|---|---|---|
| `conservative` | safe | Telemetry, logging, diagnostics, engineering menus, setup leftovers. |
| `balanced` | moderate | Conservative + optional vendor UI features, themes, app stores, accessory apps, optional Google apps. |
| `aggressive` | risky | Balanced + AI features, extra managers, test tools, some preinstalled third-party apps. Requires `--allow-risky`. |

Built-in vendor profiles cover:

- OnePlus / OPPO / Realme (ColorOS, OxygenOS, Realme UI)
- Samsung (One UI)
- Xiaomi / Redmi / POCO (MIUI, HyperOS)
- Huawei / Honor (EMUI, MagicOS)
- Vivo / iQOO (Funtouch OS, OriginOS)
- Tecno / Infinix / itel (Transsion)
- Motorola
- Google Pixel / stock Android
- Generic Android / unknown OEM

The package lists are explicit and reviewed. Packages are only disabled if they are
installed, enabled, not a critical role, and (by default) owned by the system. User
apps are never touched unless `--allow-user-apps` is passed.

Add your own lists with `--profiles-file`:

```json
{
  "vendors": {
    "oneplus": {
      "conservative": ["com.example.telemetry"],
      "balanced": ["com.example.optionalapp"],
      "aggressive": []
    }
  }
}
```

### Settings

Only allowlisted keys can be written, and each write is verified:

- `screen_off_timeout`: reduced when it is unusually high (default target 60 s).
- Window/transition/animator animation scales: `0.0`.
- `wifi_scan_always_enabled`, `wifi_wakeup_enabled`, `ble_scan_always_enabled`,
  `network_recommendations_enabled`: `0` where the key exists.
- `mobile_data_always_active`: `0`.
- `cached_apps_freezer`: `enabled` on Android 11+.
- `adaptive_sleep`: `0` on Android 10+ (camera-based screen attention).
- `long_press_timeout`: `300` ms.
- `app_standby_enabled`: `1`.
- Optional Private DNS: `--private-dns off|opportunistic|hostname --private-dns-host HOST`.

### Other actions

- **Package disabling** via `pm disable-user --user 0`. The resulting state is always
  re-read with `dumpsys package`; the exit code alone is not trusted.
- **Protected-package fallback**: some ROMs return success while refusing to disable a
  package. For telemetry-like protected packages, the script may use `pm suspend`
  (reversible with `pm unsuspend`) and `am force-stop`. UI packages are never suspended.
- **Doze whitelist cleanup**: removes disabled or telemetry packages from the Doze
  whitelist. It never removes messaging/communication apps.
- **Cache trim** via `pm trim-caches`. No app data is removed.
- **Optional AOT compile** of the default launcher and keyboard (`--compile speed`).
- **Optional background dexopt** (`--dexopt`; can heat the phone).
- **Batch ART compilation** of user/system apps via the separate `compile` command.
- **Kernel audit** always; **root-only CPU/GPU governor changes** through `kernel --apply`.
- **Responsiveness boost** (`boost`) using freezer, app standby, cached-process limit,
  adaptive power saver and optional `fstrim` — with explicit battery/heat trade-offs.
- **Optional unused-app standby restriction** (`--restrict-unused`). This uses Android's
  usage-stats window, which is often only 24 hours; review it before relying on it.

### Advanced: ART / dex2oat batch compilation

Recompile apps ahead-of-time with ART's `dex2oat` through `cmd package compile`.

```bash
# Show what would be compiled, without changing anything
python3 caop.py compile --mode speed-profile --scope third_party --dry-run

# Profile-guided compilation of 10 apps
python3 caop.py compile --mode speed-profile --limit 10 --yes

# Full AOT for all user apps (large, hot, slower; review the dry run first)
python3 caop.py compile --mode speed --scope third_party --full --yes

# One specific app, even if ART already considers it optimized
python3 caop.py compile --include com.example.app --mode speed-profile --force --yes
```

How it works:

- Reads per-package state from `dumpsys package dexopt` (`status=verify`,
  `speed-profile`, `speed`, `run-from-apk`, `unknown`, ...).
- Skips packages already at or above the requested filter unless `--force`.
- Defaults to third-party apps; `--scope system|all` is available, and critical
  packages are always skipped.
- Compiles sequentially with `cmd package compile -m MODE -p PRIORITY -f`, and
  verifies the resulting state with `dumpsys package <pkg>`.
- Refuses to run when the battery is below `--min-battery` (default 25%), the
  battery is hotter than `--max-battery-temp` (default 40 C), or thermal status
  exceeds `--max-thermal` (default 2). It rechecks every few apps and stops if
  conditions become unsafe.
- Per-app timeout is `--compile-timeout` (default 300 s); `--max-minutes` imposes
  an overall budget.
- `speed-profile` is profile-guided and can fall back to `verify` when the app
  has no usable profile. That is reported, not hidden.
- `speed` is full AOT: maximum runtime performance, but more storage, longer
  compile time and more heat. Use it deliberately.
- `--reset` discards existing AOT compilation and leaves the package at verify
  state. `--force --mode verify` can similarly downgrade an app; both print a
  warning.

Compilation state is **not automatically rollbackable** to the previous OAT
layout. The journal records what happened, but rollback only warns for compile
entries. You can always recompile or reset a package later.

### Advanced: kernel audit and root-only governor tuning

```bash
# Always safe: audit what this device exposes and whether writes are possible
python3 caop.py kernel

# Rooted devices only; explicit opt-in
python3 caop.py kernel --apply --profile balanced --allow-kernel --yes
```

What it does:

- Audits CPU governors (current + available), GPU devfreq governors, I/O
  schedulers, VM tunables, SELinux, verified boot and bootloader lock state.
- On a rooted device, can set **only** allowlisted CPU/GPU governor files:
  `.../cpufreq/scaling_governor` and `.../devfreq/governor`.
- Profiles: `balanced` (schedutil/walt), `performance` (performance), `battery`
  (powersave/schedutil), chosen only if the kernel advertises that governor.
- Every write is validated, verified by reading back, journaled, and can be
  restored by `rollback` while root is available.
- VM and I/O tunables are **reported only**. They are vendor/kernel-specific and
  are not changed automatically, because that is where most "kernel optimizer"
  scripts cause instability.

Without root, the audit is usually the whole story for kernel tuning: production ROMs
normally prevent the shell UID from writing governor, swappiness, and scheduler files,
and `kernel --apply` refuses to run. App-layer ART compilation, caches, Doze, standby,
and settings remain available where the ROM supports them.

### Advanced: boost / maximum responsiveness

`boost` trades battery life for responsiveness using real framework switches. It is
separate from `optimize`, which is battery-balanced.

```bash
python3 caop.py boost --profile fast --dry-run
python3 caop.py boost --profile fast --yes
python3 caop.py boost --profile max --fstrim --yes
```

What it changes (all reversible through the journal):

- `cached_apps_freezer=disabled` — cached apps are less aggressively frozen, so
  resumes are faster.
- `app_standby_enabled=0` — disables app standby restrictions.
- `device_config activity_manager max_cached_processes=N` — raises the cached
  process limit using a RAM-based default (`fast` 48 / `max` 64 on a 12 GB phone).
- `cmd power set-adaptive-power-saver-enabled false` — disables adaptive battery
  saver.
- Ensures low-power mode is off, animations are zero, Wi-Fi/mobile scan and adaptive
  sleep are off, and long-press timeout is 300 ms.
- Optional `sm fstrim` for storage maintenance.

Trade-offs: higher battery drain, more background activity and more RAM held by
cached apps. `optimize --profile balanced` restores the battery-friendly freezer
and standby values. Roll back with the normal journal command.

What `boost` deliberately does **not** do:

- It does not disable thermal throttling, fake thermal status, or override the
  thermal service. Those are hardware-protection mechanisms, not performance wins.
- It does not force GPU governors or bypass ROM display refresh-rate restrictions.
  GPU governor changes are available only through the root-only `kernel --apply` path,
  and only if the kernel actually exposes a writable governor.
- It does not assume fixed-performance or refresh-rate commands work. These interfaces
  are OEM-specific and are not relied upon without an observable state change.

### What it will not do

- Uninstall packages (`pm uninstall`), clear app data (`pm clear`), reboot, wipe, or
  execute an arbitrary shell command.
- Disable the default launcher, dialer, SMS app, keyboard, SystemUI, Settings,
  telephony, Google Play services, or the Play Store.
- Change background restrictions or Doze status for known messaging/social apps.
- Touch user-installed apps unless explicitly allowed.

---

## Agent mode

The agent can use these tools only:

`scan`, `list_packages`, `inspect_package`, `get_setting`, `apply_profile`,
`disable_package`, `enable_package`, `force_stop`, `set_setting`,
`set_standby_bucket`, `appops_set`, `doze_whitelist_remove`, `compile_package`,
`trim_caches`, `finish`.

Each call is validated by the harness: package names, allowlisted settings, risk
limits, critical packages, and communication apps. The model never receives a shell.
It returns JSON actions; the harness executes them and feeds back observations.
If the model returns invalid JSON, the harness asks for a repair; after two failures
it aborts rather than guessing.

Risk is capped with `--agent-max-risk safe|moderate|risky` (default `moderate`).
`--allow-risky` raises the cap to `risky` and is required for risky tools. `--dry-run`
records planned actions without changing the device.

### Provider examples

```bash
# OpenAI
export OPENAI_API_KEY="sk-..."
python3 caop.py agent --provider openai --model gpt-4o-mini --yes

# OpenRouter
export OPENROUTER_API_KEY="sk-or-..."
python3 caop.py agent --provider openrouter --model openai/gpt-4o-mini --yes

# DeepSeek
export DEEPSEEK_API_KEY="..."
python3 caop.py agent --provider deepseek --model deepseek-chat --yes

# Anthropic
export ANTHROPIC_API_KEY="..."
python3 caop.py agent --provider anthropic --model claude-3-5-sonnet-latest --yes

# Gemini
export GEMINI_API_KEY="..."
python3 caop.py agent --provider gemini --model gemini-2.0-flash --yes

# Ollama (OpenAI-compatible endpoint)
python3 caop.py agent --provider ollama --model qwen2.5:7b --yes

# llama.cpp server (start it with --host 127.0.0.1 --port 8080)
python3 caop.py agent --provider llamacpp --model local-model --yes

# LM Studio
python3 caop.py agent --provider lmstudio --yes

# Any OpenAI-compatible endpoint (vLLM, LiteLLM, etc.)
python3 caop.py agent --provider custom --base-url http://127.0.0.1:8000/v1 \
  --model my-model --yes
```

`--provider auto` picks the first provider whose environment key is set. If no key is
set, it can fall back to `OLLAMA_HOST`, `LLAMACPP_HOST`, or `LMSTUDIO_HOST`.

Environment variables:

`OPENAI_API_KEY`, `OPENROUTER_API_KEY`, `DEEPSEEK_API_KEY`, `GROQ_API_KEY`,
`TOGETHER_API_KEY`, `MISTRAL_API_KEY`, `XAI_API_KEY`, `PERPLEXITY_API_KEY`,
`FIREWORKS_API_KEY`, `ANTHROPIC_API_KEY`, `GEMINI_API_KEY`, `OLLAMA_HOST`,
`LLAMACPP_HOST`, `LMSTUDIO_HOST`, `CUSTOM_API_KEY`.

Prefer environment variables or `--api-key-file` over `--api-key` so the key does not
end up in shell history. Keys are redacted from logs and transcripts.

List the catalogue:

```bash
python3 caop.py providers
```

---

## Reports, journals, and rollback

Reports and journals are written to `caop-reports/` by default:

```text
<serial>-<timestamp>-optimize.json            # full plan + results
<serial>-<timestamp>-optimize-journal.json    # reversible changes
<serial>-<timestamp>-agent-transcript.json    # full agent transcript
<serial>-<timestamp>-agent.json               # agent result
```

Rollback:

```bash
python3 caop.py rollback --list
python3 caop.py rollback --latest --dry-run
python3 caop.py rollback --latest --yes
python3 caop.py rollback --journal caop-reports/...-journal.json --yes
```

Rollback restores:

- packages that were enabled before the run (`pm enable`);
- suspended packages (`pm unsuspend`);
- allowlisted settings (including deleting keys that were previously unset);
- app-op modes and standby buckets where they were changed;
- Doze whitelist entries removed by the run.

Cache trims, compiles, and dexopt jobs are not reversible; they do not delete app data
and caches rebuild automatically. If you pass `--force`, a journal from another device
serial can be used, but this is almost never what you want.

---

## Android 4.x compatibility

The script probes capabilities rather than assuming them:

- `settings` may be absent on very old builds; settings changes are skipped.
- `cmd` does not exist before API 24; appops/standby/deviceidle operations are skipped.
- `pm disable-user --user` falls back to `pm disable-user`/`pm disable`.
- `dumpsys package` `enabled=true/false` is understood alongside numeric states.
- The default launcher is detected from `cmd role`, `settings`, `cmd package`, or
  `dumpsys activity` as available.
- Usage stats, process lists, thermal data, and diskstats are optional; missing data
  produces warnings instead of failures.
- Cache trimming and package disabling are attempted where the ROM supports them.

No script can guarantee every OEM/ROM combination. Always run `--dry-run` first, and
keep the journal so you can roll back.

---

## Tests

Pure-Python unit tests cover profile tiers, risk classification, critical-package
protection, JSON extraction, dexopt-state parsing, compile options, kernel path
allowlisting and safety validation. They do not need a device:

```bash
python3 -m unittest discover -s tests -v
```

---

## Troubleshooting

**`no authorized device found`** — unlock the phone, enable USB debugging, accept the
RSA prompt, and check `adb devices -l`.

**`multiple devices are connected`** — pass `--serial SERIAL`.

**`device is unauthorized`** — accept the debugging prompt; if it does not appear,
revoke USB debugging authorizations in Developer options and reconnect.

**`the shell UID does not have MANAGE_APP_OPS_MODES`** — normal on many production
ROMs. The script detects this during `doctor` and skips app-op writes.

**Protected packages** — some OEM packages ignore `pm disable-user` while returning
exit code 0. The script verifies state and reports them as `protected`; it may suspend
telemetry-like packages instead.

**Agent cannot connect to Ollama/llama.cpp** — start the server and check the base URL.
Ollama defaults to `http://127.0.0.1:11434/v1`; llama.cpp defaults to
`http://127.0.0.1:8080/v1`. If the model name is omitted, the script asks `/v1/models`
and picks the first advertised model.

**A command is not permitted** — run `python3 caop.py doctor` to see the
capability matrix. The script does not use root and does not attempt privilege
escalation.

---

## Disclaimer

Android optimization is device- and ROM-specific. Disabling a system package can remove
a feature you use. The tool is deliberately conservative and reversible, but you are
responsible for reviewing the dry-run plan and keeping a rollback journal. It is not a
substitute for a backup of important data.
