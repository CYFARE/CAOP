#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CAOP - CYFARE's Android Optimizer Plus
======================================

A portable, no-root Android optimizer driven entirely through ADB.

Design goals
------------
* Never uninstalls apps, never clears app data, never factory-resets.
* Works from Android 4.x (API 14) to current Android releases by probing
  capabilities instead of assuming a command exists.
* Supported reversible mutations are recorded in a JSON journal.
* Package disables are verified after the command because several ROMs
  (including ColorOS/OxygenOS on Android 16) return exit code 0 while
  silently leaving a protected package enabled.
* Optional agent mode works with OpenAI-compatible APIs, Anthropic, Gemini,
  Ollama, llama.cpp and LM Studio. The model can only call a small,
  validated tool surface; it never gets a shell.

Typical usage
-------------
    python3 caop.py doctor
    python3 caop.py scan
    python3 caop.py optimize --profile balanced --dry-run
    python3 caop.py optimize --profile balanced --yes
    python3 caop.py agent --provider ollama --model qwen2.5:7b --yes
    python3 caop.py rollback --latest --yes

The script has no third-party dependencies.
"""

from __future__ import annotations

import argparse
import dataclasses
import datetime as _dt
import json
import logging
import os
import random
import re
import shlex
import shutil
import subprocess
import sys
import socket
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence, Set, Tuple

VERSION = "1.0.0"
JOURNAL_VERSION = 1
DEFAULT_REPORTS_DIR = "caop-reports"
DEFAULT_SCREEN_TIMEOUT_MS = 60_000
DEFAULT_CACHE_TRIM = "999G"
MAX_AGENT_STEPS = 6
MAX_ACTIONS_PER_STEP = 8
MAX_TOTAL_AGENT_ACTIONS = 40

RISK_ORDER: Dict[str, int] = {"safe": 0, "moderate": 1, "risky": 2}
PROFILE_RISK: Dict[str, str] = {
    "conservative": "safe",
    "balanced": "moderate",
    "aggressive": "risky",
}
PROFILE_TIERS: Dict[str, List[str]] = {
    "conservative": ["conservative"],
    "balanced": ["conservative", "balanced"],
    "aggressive": ["conservative", "balanced", "aggressive"],
}

# ---------------------------------------------------------------------------
# Package profiles
# ---------------------------------------------------------------------------
# These are deliberately explicit lists rather than broad wildcards.  Wildcards
# on OEM package names are how debloat scripts break a phone.  Every package is
# still checked for installation, enabled state, system/user ownership and
# critical role before anything is changed.

UNIVERSAL_PROFILES: Dict[str, List[str]] = {
    "conservative": [
        # Google setup leftovers and diagnostics that are safe to disable after
        # the device is provisioned.
        "com.google.android.feedback",
        "com.google.android.partnersetup",
        "com.google.android.onetimeinitializer",
        "com.google.android.apps.setupwizard.searchselector",
        "com.google.android.printservice.recommendation",
        "com.google.android.federatedcompute",
        "com.google.android.apps.work.clouddpc",
        "com.google.android.apps.restore",
        "com.google.android.apps.safetyhub",
        "com.google.android.devicelockcontroller",
        "com.google.android.gms.supervision",
    ],
    "balanced": [
        # Optional Google apps/services.  No account, sync, telephony or payment
        # component is included here.
        "com.google.android.apps.bard",
        "com.google.android.apps.tachyon",
        "com.google.android.apps.wellbeing",
        "com.google.android.projection.gearhead",
        "com.google.android.hotspot2.osulogin",
        "com.google.android.healthconnect.controller",
        "com.google.android.health.connect.backuprestore",
        "com.google.android.gms.location.history",
        "com.google.android.ondevicepersonalization.services",
        "com.android.hotwordenrollment.okgoogle",
        "com.android.hotwordenrollment.xgoogle",
    ],
    "aggressive": [
        "com.google.android.apps.nbu.files",
        "com.google.android.adservices.api",
        "com.google.android.accessibility.switchaccess",
        "com.android.virtualization.terminal",
        "com.google.android.virtualization.terminal",
    ],
}

VENDOR_PROFILES: Dict[str, Dict[str, Any]] = {
    "oneplus": {
        "name": "OnePlus / OPPO / Realme (ColorOS, OxygenOS, Realme UI)",
        "match": ["oneplus", "oppo", "realme", "cph", "pht", "rmx"],
        "conservative": [
            # Telemetry, logging, diagnostics, engineering menus.
            "com.oplus.pantanal.ums",
            "com.oplus.statistics.rom",
            "com.oplus.onetrace",
            "com.oplus.logkit",
            "com.oplus.olc",
            "com.oplus.postmanservice",
            "com.oplus.remotecontrol",
            "com.oplus.engineercamera",
            "com.oplus.engineermode",
            "com.oplus.engineernetwork",
            "com.oplus.nfcengineertest",
            "com.oplus.bttestmode",
            "com.coloros.operationManual",
            "com.oplus.dmp",
            "com.heytap.htms",
        ],
        "balanced": [
            # Optional ColorOS/OxygenOS UI and convenience features.
            "com.coloros.assistantscreen",
            "com.coloros.smartsidebar",
            "com.coloros.floatassistant",
            "com.coloros.scenemode",
            "com.coloros.sceneservice",
            "com.coloros.systemclone",
            "com.coloros.video",
            "com.oplus.trafficmonitor",
            "com.oplus.cast",
            "com.oplus.screenrecorder",
            "com.oplus.wallpapers",
            "com.oplus.multiapp",
            "com.oplus.nearcomm",
            "com.oplus.pscanvas",
            "com.oplus.apprecover",
            "com.oplus.upgradeguide",
            "com.heytap.mydevices",
            "com.heytap.accessory",
            "com.oneplus.colorx",
            "com.oppo.quicksearchbox",
            "com.oplus.melody",
            "com.oplus.linker",
            "com.oplus.beaconlink",
            "com.oplus.wifibackuprestore",
            "com.heytap.market",
            "com.heytap.market.overlay",
            "com.heytap.cloud",
            "com.heytap.browser",
            "com.oplus.themestore",
            "com.oplus.games",
            "com.oplus.aimemory",
            "com.oplus.customize.coreapp",
            "com.oneplus.oshare",
            "com.oneplus.membership",
            "net.oneplus.weather",
            "com.microsoft.appmanager",
            "com.facebook.system",
            "com.facebook.appmanager",
            "com.facebook.services",
            "com.google.ambient.streaming",
            "com.coloros.compass2",
        ],
        "aggressive": [
            # AI features, extra managers and test/engineering extras.
            "com.oplus.aiunit",
            "com.oplus.aiwriter",
            "com.oplus.aicall",
            "com.oplus.omoji",
            "com.oplus.phonemanager",
            "com.oplus.qualityprotect",
            "com.oplus.vdc",
            "com.oplus.nhs",
            "com.oplus.stdsp",
            "com.oplus.owkservice",
            "com.oplus.lfeh",
            "com.oplus.atlas",
            "com.oplus.appsense",
            "com.coloros.ocrscanner",
            "com.coloros.lockassistant",
            "com.coloros.colordirectservice",
            "com.coloros.childrenspace",
        ],
    },
    "samsung": {
        "name": "Samsung (One UI)",
        "match": ["samsung", "sm-", "sec"],
        "conservative": [
            "com.samsung.android.dqagent",
            "com.sec.android.log",
            "com.sec.android.app.safetyassurance",
            "com.samsung.android.app.tips",
            "com.samsung.android.dlp",
            "com.samsung.android.mdm",
        ],
        "balanced": [
            "com.samsung.android.app.spage",
            "com.samsung.android.app.social",
            "com.samsung.android.voc",
            "com.samsung.android.scloud",
            "com.samsung.android.app.reminder",
            "com.samsung.android.app.shealth",
            "com.samsung.android.mateagent",
            "com.samsung.android.app.watchmanagerstub",
            "com.samsung.android.game.gamehome",
            "com.samsung.android.app.sharelive",
            "com.samsung.android.beaconmanager",
            "com.samsung.android.app.smartthings",
            "com.samsung.android.oneconnect",
            "com.samsung.android.app.withtv",
            "com.samsung.android.smartmirroring",
            "com.samsung.android.app.screenrecorder",
            "com.samsung.android.app.ve",
            "com.sec.android.easyMoverAgent",
            "com.sec.android.easyMover",
            "com.samsung.android.app.smartswitchassistant",
            "com.samsung.android.app.cocktailbarservice",
            "com.samsung.android.app.appsedge",
            "com.samsung.android.app.taskedge",
            "com.samsung.android.service.peoplestripe",
            "com.samsung.android.app.clipboardedge",
            "com.samsung.android.forest",
        ],
        "aggressive": [
            "com.samsung.android.bixby.agent",
            "com.samsung.android.bixby.wakeup",
            "com.samsung.android.bixby.service",
            "com.samsung.android.app.settings.bixby",
            "com.samsung.android.visionintelligence",
            "com.samsung.android.bixbyvision.framework",
            "com.samsung.android.game.gametools",
            "com.samsung.android.game.gos",
            "com.samsung.android.aremoji",
            "com.samsung.android.arzone",
            "com.samsung.android.kidsinstaller",
            "com.samsung.android.app.dressroom",
            "com.samsung.android.themestore",
            "com.samsung.android.themecenter",
            "com.samsung.android.app.camera.sticker.facearavatar.preload",
            "com.samsung.android.app.vrsetupwizard",
            "com.samsung.android.app.arvr",
            "com.samsung.android.hmt.vrsvc",
            "com.sec.android.app.samsungapps",
            "com.microsoft.skydrive",
            "com.netflix.mediaclient",
            "com.spotify.music",
            "com.amazon.appmanager",
            "com.amazon.venezia",
        ],
    },
    "xiaomi": {
        "name": "Xiaomi / Redmi / POCO (MIUI, HyperOS)",
        "match": ["xiaomi", "redmi", "poco", "mi "],
        "conservative": [
            "com.miui.analytics",
            "com.miui.bugreport",
            "com.miui.miservice",
            "com.xiaomi.discover",
        ],
        "balanced": [
            "com.miui.msa.global",
            "com.miui.systemAdSolution",
            "com.xiaomi.mipicks",
            "com.xiaomi.discover",
            "com.xiaomi.midrop",
            "com.xiaomi.scanner",
            "com.xiaomi.glgm",
            "com.miui.videoplayer",
            "com.miui.player",
            "com.miui.weather2",
            "com.miui.compass",
            "com.miui.fm",
            "com.miui.screenrecorder",
            "com.miui.cloudservice",
            "com.miui.cloudbackup",
            "com.miui.backup",
            "com.xiaomi.market",
            "com.miui.miwallpaper",
            "com.xiaomi.shop",
            "com.xiaomi.mirecycle",
            "com.miui.tsmclient",
            "com.xiaomi.smarthome",
            "com.xiaomi.router",
            "com.xiaomi.wearable",
            "com.xiaomi.hm.health",
            "com.xiaomi.youpin",
            "com.xiaomi.mirror",
        ],
        "aggressive": [
            "com.miui.virtualsim",
            "com.miui.hybrid",
            "com.miui.hybrid.accessory",
            "com.miui.contentcatcher",
            "com.miui.securityadd",
            "com.miui.cleanmaster",
            "com.miui.voiceassist",
            "com.miui.voicetrigger",
            "com.xiaomi.mico",
            "com.xiaomi.aiasst.vision",
            "com.xiaomi.aiasst.service",
            "com.miui.cit",
        ],
    },
    "huawei": {
        "name": "Huawei / Honor (EMUI, MagicOS)",
        "match": ["huawei", "honor", "hihonor"],
        "conservative": [
            "com.huawei.hwanalytics",
            "com.huawei.hwlog",
            "com.huawei.hwddmp",
            "com.huawei.imonitor",
            "com.hihonor.hwanalytics",
            "com.hihonor.hwlog",
            "com.hihonor.hwddmp",
            "com.hihonor.imonitor",
        ],
        "balanced": [
            "com.huawei.appmarket",
            "com.huawei.phoneservice",
            "com.huawei.health",
            "com.huawei.video",
            "com.huawei.music",
            "com.huawei.browser",
            "com.huawei.hwread",
            "com.huawei.hwvplayer",
            "com.huawei.gameassistant",
            "com.huawei.parentcontrol",
            "com.huawei.smarthome",
            "com.huawei.wearable",
            "com.huawei.audioaccessorymanager",
            "com.huawei.hiboard",
            "com.huawei.hwcloudservice",
            "com.huawei.hwdetectrepair",
            "com.hihonor.appmarket",
            "com.hihonor.phoneservice",
            "com.hihonor.health",
            "com.hihonor.video",
            "com.hihonor.music",
            "com.hihonor.browser",
            "com.hihonor.hiboard",
            "com.hihonor.smarthome",
            "com.hihonor.wearable",
            "com.hihonor.gameassistant",
            "com.hihonor.parentcontrol",
        ],
        "aggressive": [
            "com.huawei.vassistant",
            "com.huawei.hicare",
            "com.huawei.tips",
            "com.huawei.magazine",
            "com.hihonor.vassistant",
            "com.hihonor.hicare",
            "com.hihonor.tips",
            "com.hihonor.magazine",
        ],
    },
    "vivo": {
        "name": "Vivo / iQOO (Funtouch OS, OriginOS)",
        "match": ["vivo", "iqoo"],
        "conservative": [
            "com.vivo.bugreport",
            "com.vivo.log",
            "com.vivo.analytics",
            "com.vivo.diagnostics",
        ],
        "balanced": [
            "com.vivo.appstore",
            "com.vivo.browser",
            "com.vivo.music",
            "com.vivo.video",
            "com.vivo.weather",
            "com.vivo.easyshare",
            "com.vivo.game",
            "com.vivo.health",
            "com.vivo.wearable",
            "com.vivo.share",
            "com.vivo.cloudservice",
            "com.vivo.fm",
            "com.vivo.compass",
            "com.vivo.recorder",
            "com.vivo.email",
        ],
        "aggressive": [
            "com.vivo.assistant",
            "com.vivo.voiceassist",
            "com.vivo.ai",
            "com.vivo.smartvoice",
            "com.vivo.gamepad",
        ],
    },
    "transsion": {
        "name": "Tecno / Infinix / itel (Transsion)",
        "match": ["tecno", "infinix", "itel", "transsion"],
        "conservative": [
            "com.transsion.telemetry",
            "com.transsion.log",
            "com.transsion.diagnostics",
            "com.transsion.bugreport",
            "com.transsion.analytics",
            "com.transsion.survey",
        ],
        "balanced": [
            "com.transsion.phonemaster",
            "com.transsion.appstore",
            "com.transsion.game",
            "com.transsion.videoplayer",
            "com.transsion.music",
            "com.transsion.weather",
            "com.transsion.browser",
            "com.transsion.news",
            "com.transsion.magazine",
        ],
        "aggressive": [
            "com.transsion.voiceassist",
            "com.transsion.ai",
            "com.transsion.gameboost",
        ],
    },
    "motorola": {
        "name": "Motorola",
        "match": ["motorola", "moto "],
        "conservative": [
            "com.motorola.demo",
            "com.motorola.bug2go",
        ],
        "balanced": [
            "com.motorola.motocare",
            "com.motorola.help",
            "com.motorola.timeweatherwidget",
            "com.motorola.fmplayer",
            "com.motorola.weather",
        ],
        "aggressive": [
            "com.motorola.gamemode",
            "com.motorola.motog",
        ],
    },
    "pixel": {
        "name": "Google Pixel / stock Android",
        "match": ["google", "pixel"],
        "conservative": [],
        "balanced": [],
        "aggressive": [
            "com.google.android.apps.turbo",
        ],
    },
    "generic": {
        "name": "Generic Android / unknown OEM",
        "match": [],
        "conservative": [],
        "balanced": [
            "com.facebook.appmanager",
            "com.facebook.services",
            "com.facebook.system",
        ],
        "aggressive": [],
    },
}

CRITICAL_EXACT: Set[str] = {
    "com.android.systemui",
    "com.android.settings",
    "com.android.phone",
    "com.android.incallui",
    "com.android.telecom",
    "com.android.server.telecom",
    "com.android.providers.telephony",
    "com.android.providers.contacts",
    "com.android.providers.media",
    "com.android.providers.settings",
    "com.android.providers.downloads",
    "com.android.providers.calendar",
    "com.android.mms.service",
    "com.android.bluetooth",
    "com.android.nfc",
    "com.android.se",
    "com.android.stk",
    "com.android.emergency",
    "com.android.cellbroadcastreceiver",
    "com.android.cellbroadcastservice",
    "com.android.keychain",
    "com.android.certinstaller",
    "com.android.packageinstaller",
    "com.android.permissioncontroller",
    "com.android.networkstack",
    "com.android.networkstack.tethering",
    "com.android.wifi",
    "com.android.connectivity",
    "com.android.shell",
    "com.android.managedprovisioning",
    "com.google.android.gms",
    "com.google.android.gsf",
    "com.android.vending",
    "com.google.android.packageinstaller",
    "com.google.android.permissioncontroller",
    "com.google.android.networkstack",
    "com.google.android.networkstack.tethering",
    "com.google.android.wifi",
    "com.google.android.connectivity",
    "com.google.android.cellbroadcastreceiver",
    "com.google.android.cellbroadcastservice",
    "com.google.android.emergency",
    "com.google.android.dialer",
    "com.google.android.contacts",
    "com.google.android.apps.messaging",
    "com.google.android.inputmethod.latin",
    "com.android.inputmethod.latin",
    "com.samsung.android.honeyboard",
    "com.samsung.android.dialer",
    "com.samsung.android.messaging",
    "com.samsung.android.incallui",
    "com.samsung.android.app.contacts",
    "com.samsung.android.telephony",
    "com.miui.home",
    "com.miui.securitycenter",
    "com.miui.phone",
    "com.miui.contacts",
    "com.miui.mms",
    "com.huawei.android.launcher",
    "com.huawei.contacts",
    "com.huawei.mms",
    "com.huawei.dialer",
    "com.huawei.systemmanager",
    "com.vivo.launcher",
    "com.vivo.contacts",
    "com.vivo.mms",
    "com.vivo.dialer",
    "com.transsion.hilauncher",
    "com.transsion.contacts",
    "com.transsion.mms",
    "com.transsion.dialer",
}

CRITICAL_PATTERNS: List[re.Pattern] = [
    re.compile(r"^com\.android\.launcher"),
    re.compile(r"^com\.oneplus\.launcher"),
    re.compile(r"^com\.oppo\.launcher"),
    re.compile(r"^com\.coloros\.launcher"),
    re.compile(r"^com\.samsung\.android\.launcher"),
    re.compile(r"^com\.sec\.android\.app\.launcher"),
    re.compile(r"^com\.motorola\.launcher"),
    re.compile(r"^com\.lg\.launcher"),
    re.compile(r"^com\.asus\.launcher"),
    re.compile(r"^com\.sony\.launcher"),
    re.compile(r"^com\.zte\.launcher"),
    re.compile(r"^com\.nubia\.launcher"),
    re.compile(r"^com\.android\.settings"),
    re.compile(r"^com\.android\.systemui"),
    re.compile(r"^com\.android\.phone"),
    re.compile(r"^com\.android\.incallui"),
    re.compile(r"^com\.android\.telecom"),
    re.compile(r"^com\.android\.server\.telecom"),
    re.compile(r"^com\.android\.providers\.(telephony|contacts|media|settings)"),
    re.compile(r"^com\.android\.(mms|messaging|contacts|bluetooth|nfc|cellbroadcast|emergency|keychain|certinstaller|packageinstaller|permissioncontroller|networkstack|wifi|connectivity)"),
    re.compile(r"^com\.google\.android\.(gms|gsf|packageinstaller|permissioncontroller|networkstack|wifi|connectivity|cellbroadcast|emergency)"),
    re.compile(r"^com\.android\.vending$"),
    re.compile(r"^com\.google\.android\.inputmethod\.latin"),
    re.compile(r"^com\.samsung\.android\.(honeyboard|dialer|messaging|incallui|telephony)"),
    re.compile(r"^com\.samsung\.android\.app\.contacts"),
    re.compile(r"^com\.miui\.(home|securitycenter|phone|contacts|mms)"),
    re.compile(r"^com\.huawei\.(android\.launcher|contacts|mms|dialer|systemmanager)"),
    re.compile(r"^com\.vivo\.(launcher|contacts|mms|dialer)"),
    re.compile(r"^com\.transsion\.(hilauncher|contacts|mms|dialer|xoslauncher|xosdialer|xoscontacts|xosmms)"),
    # Vendor security/permission centres are user-facing safety surfaces.
    re.compile(r"^com\.oplus\.(safecenter|securityguard|securitypermission|securitykeyboard)"),
    re.compile(r"^com\.coloros\.(safecenter|security)"),
]

COMMUNICATION_PATTERNS: List[re.Pattern] = [
    re.compile(r"(whatsapp|telegram|signal|messenger|orca|facebook|instagram|snapchat|viber|line\.android|wechat|kakaotalk|discord|slack|teams|zoom|element|threema|zalo|imo\.im|truecaller|skype|textnow|google\.android\.apps\.messaging|android\.mms|android\.contacts|android\.dialer|android\.phone|android\.incallui|android\.telecom)"),
]

TELEMETRY_PATTERNS: List[re.Pattern] = [
    re.compile(r"(telemetry|analytics|statistics|stats|onetrace|logkit|diagnostic|bugreport|feedback|survey|metrics|postman|remotecontrol|pantanal|olc|dmp|hwlog|hwanalytics|imonitor|dqagent|safetyassurance|audit|crashlytics)"),
]

# ---------------------------------------------------------------------------
# Settings catalogue
# ---------------------------------------------------------------------------
# Only these keys may ever be written.  Values are validated and clamped.
SETTINGS_SPEC: Dict[Tuple[str, str], Dict[str, Any]] = {
    ("system", "screen_off_timeout"): {
        "type": "int",
        "default": DEFAULT_SCREEN_TIMEOUT_MS,
        "minimum": 15_000,
        "maximum": 1_800_000,
        "min_sdk": 14,
        "risk": "safe",
        "description": "Reduce screen-off timeout when it is unusually high.",
    },
    ("global", "window_animation_scale"): {
        "type": "float",
        "default": 0.0,
        "min_sdk": 17,
        "risk": "safe",
        "description": "Disable window animations for snappier UI.",
    },
    ("global", "transition_animation_scale"): {
        "type": "float",
        "default": 0.0,
        "min_sdk": 17,
        "risk": "safe",
        "description": "Disable transition animations.",
    },
    ("global", "animator_duration_scale"): {
        "type": "float",
        "default": 0.0,
        "min_sdk": 17,
        "risk": "safe",
        "description": "Disable animator durations.",
    },
    ("global", "wifi_scan_always_enabled"): {
        "type": "int",
        "default": 0,
        "min_sdk": 18,
        "risk": "safe",
        "description": "Stop Wi-Fi scanning while Wi-Fi is off.",
    },
    ("global", "wifi_wakeup_enabled"): {
        "type": "int",
        "default": 0,
        "min_sdk": 18,
        "risk": "safe",
        "description": "Stop Wi-Fi wakeups where the key exists.",
    },
    ("global", "ble_scan_always_enabled"): {
        "type": "int",
        "default": 0,
        "min_sdk": 18,
        "risk": "safe",
        "description": "Stop always-on Bluetooth LE scanning.",
    },
    ("global", "network_recommendations_enabled"): {
        "type": "int",
        "default": 0,
        "min_sdk": 18,
        "risk": "safe",
        "description": "Disable network recommendation scans.",
    },
    ("global", "mobile_data_always_active"): {
        "type": "int",
        "default": 0,
        "min_sdk": 21,
        "risk": "safe",
        "description": "Do not keep mobile data active for faster switching.",
    },
    ("global", "cached_apps_freezer"): {
        "type": "enum",
        "default": "enabled",
        "allowed": ["enabled", "disabled", "device_default"],
        "min_sdk": 30,
        "risk": "safe",
        "description": "Enable the cached-app freezer on Android 11+.",
    },
    ("secure", "adaptive_sleep"): {
        "type": "int",
        "default": 0,
        "min_sdk": 29,
        "risk": "safe",
        "description": "Disable camera-based screen attention.",
    },
    ("secure", "long_press_timeout"): {
        "type": "int",
        "default": 300,
        "minimum": 200,
        "maximum": 1_500,
        "min_sdk": 21,
        "risk": "safe",
        "description": "Slightly faster long-press recognition.",
    },
    ("global", "app_standby_enabled"): {
        "type": "int",
        "default": 1,
        "min_sdk": 28,
        "risk": "safe",
        "description": "Ensure app standby buckets are enabled.",
    },
}

PRIVATE_DNS_SPEC = {
    "mode": ("global", "private_dns_mode"),
    "hostname": ("global", "private_dns_specifier"),
}

# Kernel writes are deliberately limited to governor files.  VM and I/O
# scheduler tuning is audited but not changed automatically: it is highly
# vendor/kernel-specific and can make a device unstable.
KERNEL_WRITE_PATTERNS: List[re.Pattern] = [
    re.compile(r"^/sys/devices/system/cpu/cpu[0-9]+/cpufreq/scaling_governor$"),
    re.compile(r"^/sys/class/kgsl/kgsl-3d0/devfreq/governor$"),
    re.compile(r"^/sys/class/devfreq/[A-Za-z0-9_.-]+/governor$"),
]
KERNEL_SAFE_PATH_RE = re.compile(r"^/(sys|proc)/[A-Za-z0-9_./:-]+$")
KERNEL_VALUE_RE = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")

DEXOPT_STATUS_RANK: Dict[str, int] = {
    "run-from-apk": 0,
    "unknown": 0,
    "error": 0,
    "verify": 1,
    "quicken": 1,
    "speed-profile": 2,
    "speed": 3,
}

# ---------------------------------------------------------------------------
# LLM provider catalogue
# ---------------------------------------------------------------------------
PROVIDERS: Dict[str, Dict[str, Any]] = {
    "openai": {
        "base": "https://api.openai.com/v1",
        "env": "OPENAI_API_KEY",
        "model": "gpt-4o-mini",
        "style": "openai",
    },
    "openrouter": {
        "base": "https://openrouter.ai/api/v1",
        "env": "OPENROUTER_API_KEY",
        "model": "openai/gpt-4o-mini",
        "style": "openai",
        "headers": {"X-Title": "CAOP - CYFARE's Android Optimizer Plus"},
    },
    "deepseek": {
        "base": "https://api.deepseek.com/v1",
        "env": "DEEPSEEK_API_KEY",
        "model": "deepseek-chat",
        "style": "openai",
    },
    "groq": {
        "base": "https://api.groq.com/openai/v1",
        "env": "GROQ_API_KEY",
        "model": "llama-3.3-70b-versatile",
        "style": "openai",
    },
    "together": {
        "base": "https://api.together.xyz/v1",
        "env": "TOGETHER_API_KEY",
        "model": "meta-llama/Llama-3.3-70B-Instruct-Turbo",
        "style": "openai",
    },
    "mistral": {
        "base": "https://api.mistral.ai/v1",
        "env": "MISTRAL_API_KEY",
        "model": "mistral-small-latest",
        "style": "openai",
    },
    "xai": {
        "base": "https://api.x.ai/v1",
        "env": "XAI_API_KEY",
        "model": "grok-2-latest",
        "style": "openai",
    },
    "perplexity": {
        "base": "https://api.perplexity.ai",
        "env": "PERPLEXITY_API_KEY",
        "model": "sonar",
        "style": "openai",
    },
    "fireworks": {
        "base": "https://api.fireworks.ai/inference/v1",
        "env": "FIREWORKS_API_KEY",
        "model": "accounts/fireworks/models/llama-v3p3-70b-instruct",
        "style": "openai",
    },
    "anthropic": {
        "base": "https://api.anthropic.com",
        "env": "ANTHROPIC_API_KEY",
        "model": "claude-3-5-sonnet-latest",
        "style": "anthropic",
    },
    "gemini": {
        "base": "https://generativelanguage.googleapis.com",
        "env": "GEMINI_API_KEY",
        "model": "gemini-2.0-flash",
        "style": "gemini",
    },
    "ollama": {
        "base": "http://127.0.0.1:11434/v1",
        "env": "OLLAMA_API_KEY",
        "model": "llama3.1",
        "style": "openai",
        "local": True,
    },
    "llamacpp": {
        "base": "http://127.0.0.1:8080/v1",
        "env": "LLAMACPP_API_KEY",
        "model": "local-model",
        "style": "openai",
        "local": True,
    },
    "lmstudio": {
        "base": "http://127.0.0.1:1234/v1",
        "env": "LMSTUDIO_API_KEY",
        "model": "local-model",
        "style": "openai",
        "local": True,
    },
    "custom": {
        "base": "",
        "env": "CUSTOM_API_KEY",
        "model": "local-model",
        "style": "openai",
    },
}

# ---------------------------------------------------------------------------
# Core utilities
# ---------------------------------------------------------------------------

PACKAGE_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_]*(\.[A-Za-z0-9_]+)+$")
SAFE_VALUE_RE = re.compile(r"^[A-Za-z0-9._:/-]{1,255}$")
HOSTNAME_RE = re.compile(r"^(?=.{1,253}$)([A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)*[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")
SIZE_RE = re.compile(r"^[0-9]{1,6}[KMG]?$", re.IGNORECASE)


def now_iso() -> str:
    return _dt.datetime.now(_dt.timezone.utc).replace(microsecond=0).isoformat()


def human_bytes(value: Optional[float]) -> str:
    if value is None:
        return "unknown"
    value = float(value)
    units = ["B", "KB", "MB", "GB", "TB"]
    idx = 0
    while abs(value) >= 1024.0 and idx < len(units) - 1:
        value /= 1024.0
        idx += 1
    if idx == 0:
        return "%d %s" % (int(value), units[idx])
    return "%.1f %s" % (value, units[idx])


def safe_int(value: Any, default: Optional[int] = None) -> Optional[int]:
    try:
        text = str(value).strip()
        if not text or text.lower() in ("null", "none", "unknown"):
            return default
        return int(float(text))
    except (TypeError, ValueError):
        return default


def safe_float(value: Any, default: Optional[float] = None) -> Optional[float]:
    try:
        text = str(value).strip()
        if not text or text.lower() in ("null", "none", "unknown"):
            return default
        return float(text)
    except (TypeError, ValueError):
        return default


def dedupe(items: Iterable[str]) -> List[str]:
    seen: Set[str] = set()
    result: List[str] = []
    for item in items:
        if item not in seen:
            seen.add(item)
            result.append(item)
    return result


def compact_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True)


def pretty_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True)


def write_json(path: Path, value: Any, mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    text = json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    path.write_text(text, encoding="utf-8")
    try:
        os.chmod(str(path), mode)
    except OSError:
        pass


def read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def redact_secrets(text: str, secrets: Sequence[Optional[str]] = ()) -> str:
    result = text
    for secret in secrets:
        if secret and len(secret) >= 6:
            result = result.replace(secret, "***REDACTED***")
    result = re.sub(r"(?i)(authorization\s*[:=]\s*bearer\s+)[^\s\"']+", r"\1***REDACTED***", result)
    result = re.sub(r"(?i)(api[_-]?key\s*[:=]\s*)[^\s\"']+", r"\1***REDACTED***", result)
    return result


def extract_json_object(text: str) -> Dict[str, Any]:
    """Extract one JSON object from an LLM response, tolerating markdown fences."""
    if not text or not text.strip():
        raise ValidationError("empty model response")
    cleaned = text.strip()
    cleaned = re.sub(r"^```(?:json)?\s*", "", cleaned, flags=re.IGNORECASE)
    cleaned = re.sub(r"\s*```$", "", cleaned)
    try:
        value = json.loads(cleaned)
        if isinstance(value, dict):
            return value
    except (ValueError, TypeError):
        pass
    decoder = json.JSONDecoder()
    positions = [i for i, ch in enumerate(cleaned) if ch == "{"]
    for pos in positions:
        try:
            value, _end = decoder.raw_decode(cleaned[pos:])
            if isinstance(value, dict):
                return value
        except (ValueError, TypeError):
            continue
    if "{" in cleaned and "}" in cleaned:
        snippet = cleaned[cleaned.find("{"): cleaned.rfind("}") + 1]
        try:
            value = json.loads(snippet)
            if isinstance(value, dict):
                return value
        except (ValueError, TypeError):
            pass
    raise ValidationError("model response did not contain a valid JSON object")


def normalize_setting(value: Optional[str]) -> Optional[str]:
    if value is None:
        return None
    text = str(value).strip()
    if text.lower() in ("", "null", "none", "unknown"):
        return None
    return text


def parse_bool(value: Any) -> bool:
    return str(value).strip().lower() in ("1", "true", "yes", "on", "enabled")


class OptimizerError(Exception):
    """Base class for expected, user-facing failures."""


class AdbError(OptimizerError):
    pass


class DeviceError(OptimizerError):
    pass


class ProviderError(OptimizerError):
    pass


class SafetyError(OptimizerError):
    pass


class ValidationError(OptimizerError):
    pass


class JournalError(OptimizerError):
    pass


# ---------------------------------------------------------------------------
# Colours and logging
# ---------------------------------------------------------------------------

class Colors:
    def __init__(self, enabled: bool = True) -> None:
        self.enabled = enabled
        self.reset = "\033[0m" if enabled else ""
        self.bold = "\033[1m" if enabled else ""
        self.dim = "\033[2m" if enabled else ""
        self.red = "\033[31m" if enabled else ""
        self.green = "\033[32m" if enabled else ""
        self.yellow = "\033[33m" if enabled else ""
        self.blue = "\033[34m" if enabled else ""
        self.magenta = "\033[35m" if enabled else ""
        self.cyan = "\033[36m" if enabled else ""


_COLORS = Colors(False)


def setup_logging(verbose: bool = False, no_color: bool = False) -> None:
    global _COLORS
    use_color = (not no_color) and sys.stderr.isatty() and os.environ.get("NO_COLOR") is None
    _COLORS = Colors(use_color)
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(message)s",
        stream=sys.stderr,
        force=True,
    )


def log_debug(message: str) -> None:
    logging.getLogger("optimizer").debug(_COLORS.dim + "[debug] " + message + _COLORS.reset)


def log_info(message: str) -> None:
    logging.getLogger("optimizer").info(_COLORS.cyan + "[*] " + _COLORS.reset + message)


def log_ok(message: str) -> None:
    logging.getLogger("optimizer").info(_COLORS.green + "[ok] " + _COLORS.reset + message)


def log_warn(message: str) -> None:
    logging.getLogger("optimizer").warning(_COLORS.yellow + "[!] " + _COLORS.reset + message)


def log_error(message: str) -> None:
    logging.getLogger("optimizer").error(_COLORS.red + "[x] " + _COLORS.reset + message)


def confirm(question: str, assume_yes: bool = False) -> bool:
    if assume_yes:
        return True
    if not sys.stdin.isatty():
        return False
    try:
        answer = input(question + " [y/N] ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        return False
    return answer in ("y", "yes")


# ---------------------------------------------------------------------------
# ADB wrapper
# ---------------------------------------------------------------------------

@dataclasses.dataclass
class CmdResult:
    args: List[str]
    returncode: int
    stdout: str
    stderr: str
    duration: float
    timed_out: bool = False

    @property
    def ok(self) -> bool:
        return self.returncode == 0 and not self.timed_out

    @property
    def combined(self) -> str:
        return (self.stdout or "") + (("\n" + self.stderr) if self.stderr else "")

    def summary(self, limit: int = 500) -> str:
        text = re.sub(r"\s+", " ", self.combined).strip()
        return text[:limit]


@dataclasses.dataclass
class AppState:
    package: str
    installed: bool = False
    enabled: Optional[int] = None
    suspended: bool = False
    hidden: bool = False
    stopped: bool = False
    is_system: bool = False
    version_name: Optional[str] = None
    raw_line: str = ""

    @property
    def disabled(self) -> bool:
        return self.enabled in (2, 3, 4)

    @property
    def enabled_state(self) -> str:
        mapping = {0: "default", 1: "enabled", 2: "disabled", 3: "disabled-user", 4: "disabled-until-used"}
        return mapping.get(self.enabled, "unknown")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "package": self.package,
            "installed": self.installed,
            "enabled": self.enabled,
            "enabled_state": self.enabled_state,
            "disabled": self.disabled,
            "suspended": self.suspended,
            "hidden": self.hidden,
            "stopped": self.stopped,
            "is_system": self.is_system,
            "version_name": self.version_name,
        }


def parse_dexopt_state(text: str) -> Dict[str, Dict[str, Any]]:
    """Parse `dumpsys package dexopt` into {package: primary status}."""
    state: Dict[str, Dict[str, Any]] = {}
    current: Optional[str] = None
    in_secondary = False
    for raw_line in text.splitlines():
        line = raw_line.rstrip()
        header = re.match(r"^  \[([^\]]+)\]\s*$", line)
        if header:
            current = header.group(1).strip()
            in_secondary = False
            continue
        if not current:
            continue
        if "known secondary dex files" in line:
            in_secondary = True
            continue
        path_match = re.match(r"^\s*path:\s+(.+)$", line)
        if path_match:
            state.setdefault(current, {}).setdefault("path", path_match.group(1).strip())
            continue
        status_match = re.match(
            r"^\s+([A-Za-z0-9_]+):\s+\[status=([^\]]+)\]\s+\[reason=([^\]]+)\]\s*(.*)$",
            line,
        )
        if not status_match or in_secondary:
            continue
        abi, status, reason, rest = status_match.groups()
        primary = "primary-abi" in rest
        entry = {
            "abi": abi,
            "status": status,
            "reason": reason,
            "primary_abi": primary,
        }
        previous = state.get(current)
        if previous is None or not previous.get("status"):
            state[current] = dict(previous or {}, **entry)
        elif primary and not previous.get("primary_abi"):
            state[current] = dict(previous, **entry)
        elif primary and previous.get("primary_abi"):
            # Keep the worst rank across primary dex files; that is the
            # conservative choice for deciding whether compilation helps.
            if DEXOPT_STATUS_RANK.get(status, 0) < DEXOPT_STATUS_RANK.get(previous.get("status", "unknown"), 0):
                state[current] = dict(previous, **entry)
    return state


def parse_package_dexopt(text: str) -> Optional[Dict[str, Any]]:
    """Parse the Dexopt state block from `dumpsys package <pkg>`."""
    in_block = False
    best: Optional[Dict[str, Any]] = None
    for line in text.splitlines():
        if line.strip() == "Dexopt state:":
            in_block = True
            continue
        if not in_block:
            continue
        match = re.match(r"^\s+([A-Za-z0-9_]+):\s+\[status=([^\]]+)\]\s+\[reason=([^\]]+)\]\s*(.*)$", line)
        if not match:
            continue
        abi, status, reason, rest = match.groups()
        entry = {"abi": abi, "status": status, "reason": reason, "primary_abi": "primary-abi" in rest}
        if best is None:
            best = entry
        elif entry["primary_abi"] and not best.get("primary_abi"):
            best = entry
        elif entry["primary_abi"] and best.get("primary_abi"):
            if DEXOPT_STATUS_RANK.get(status, 0) < DEXOPT_STATUS_RANK.get(best.get("status", "unknown"), 0):
                best = entry
    return best


def dexopt_at_least(current: Optional[str], target: str) -> bool:
    """Return True when current compilation is at least as good as target."""
    current_rank = DEXOPT_STATUS_RANK.get(current or "unknown", 0)
    if target == "verify":
        return current_rank >= 1
    if target == "quicken":
        return current in ("quicken", "speed-profile", "speed")
    if target == "speed-profile":
        return current_rank >= 2
    if target == "speed":
        return current_rank >= 3
    return False


class AdbClient:
    """Thin, retrying wrapper around the adb executable."""

    def __init__(self, adb: Optional[str] = None, serial: Optional[str] = None,
                 timeout: int = 60, retries: int = 1, user: int = 0) -> None:
        self.adb = adb or shutil.which("adb") or "adb"
        self.serial = serial
        self.timeout = max(5, int(timeout))
        self.retries = max(0, int(retries))
        self.user = int(user)
        self._props: Optional[Dict[str, str]] = None
        self._system_packages: Optional[Set[str]] = None
        self._third_party_packages: Optional[Set[str]] = None
        self._disabled_packages: Optional[Set[str]] = None

    # -- low level ---------------------------------------------------------
    def _base_args(self) -> List[str]:
        args = [self.adb]
        if self.serial:
            args.extend(["-s", self.serial])
        return args

    def run_adb(self, args: Sequence[str], timeout: Optional[int] = None,
                retries: Optional[int] = None) -> CmdResult:
        timeout = self.timeout if timeout is None else max(5, int(timeout))
        attempts = self.retries if retries is None else max(0, int(retries))
        cmd = self._base_args() + [str(a) for a in args]
        last_result: Optional[CmdResult] = None
        for attempt in range(attempts + 1):
            started = time.monotonic()
            try:
                proc = subprocess.run(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    stdin=subprocess.DEVNULL,
                    timeout=timeout,
                    encoding="utf-8",
                    errors="replace",
                )
                result = CmdResult(cmd, proc.returncode, proc.stdout or "", proc.stderr or "", time.monotonic() - started)
            except subprocess.TimeoutExpired as exc:
                out = exc.stdout or ""
                err = exc.stderr or ""
                if isinstance(out, bytes):
                    out = out.decode("utf-8", "replace")
                if isinstance(err, bytes):
                    err = err.decode("utf-8", "replace")
                result = CmdResult(cmd, 124, out, err, time.monotonic() - started, timed_out=True)
            except FileNotFoundError as exc:
                raise AdbError("adb was not found (%s). Install Android platform-tools or pass --adb PATH." % exc)
            except OSError as exc:
                raise AdbError("could not execute adb: %s" % exc)
            last_result = result
            if result.ok or attempt >= attempts:
                return result
            combined = result.combined.lower()
            transient = any(token in combined for token in ("device offline", "protocol fault", "connection reset", "closed", "broken pipe"))
            if not transient:
                return result
            time.sleep(0.4 * (attempt + 1))
        assert last_result is not None
        return last_result

    def shell(self, command: str, timeout: Optional[int] = None,
              retries: Optional[int] = None) -> CmdResult:
        return self.run_adb(["shell", command], timeout=timeout, retries=retries)

    def shell_args(self, *args: Any, timeout: Optional[int] = None,
                   retries: Optional[int] = None) -> CmdResult:
        command = " ".join(shlex.quote(str(a)) for a in args)
        return self.shell(command, timeout=timeout, retries=retries)

    # -- device selection --------------------------------------------------
    def devices(self) -> List[Dict[str, str]]:
        result = self.run_adb(["devices", "-l"], timeout=20, retries=0)
        if not result.ok:
            raise DeviceError("adb devices failed: %s" % result.summary())
        devices: List[Dict[str, str]] = []
        for line in result.stdout.splitlines():
            line = line.strip()
            if not line or line.startswith("List of devices") or line.startswith("*"):
                continue
            parts = line.split()
            if len(parts) < 2:
                continue
            item = {"serial": parts[0], "state": parts[1]}
            for token in parts[2:]:
                if ":" in token:
                    key, value = token.split(":", 1)
                    item[key] = value
            devices.append(item)
        return devices

    def ensure_device(self) -> Dict[str, str]:
        devices = self.devices()
        chosen: Optional[Dict[str, str]] = None
        if self.serial:
            for device in devices:
                if device.get("serial") == self.serial:
                    chosen = device
                    break
            if chosen is None:
                raise DeviceError("device %r is not attached. Attached: %s" % (self.serial, self._device_list_text(devices)))
        else:
            ready = [d for d in devices if d.get("state") == "device"]
            if not ready:
                raise DeviceError("no authorized device found. %s\nEnable USB debugging and accept the RSA prompt on the phone." % self._device_list_text(devices))
            if len(ready) > 1:
                serials = ", ".join(d.get("serial", "?") for d in ready)
                raise DeviceError("multiple devices are connected (%s). Re-run with --serial SERIAL." % serials)
            chosen = ready[0]
            self.serial = chosen.get("serial")
        state = chosen.get("state")
        if state != "device":
            hint = ""
            if state == "unauthorized":
                hint = " Accept the USB debugging authorization prompt on the phone."
            elif state == "offline":
                hint = " Try reconnecting the cable or run 'adb reconnect'."
            raise DeviceError("device %s is %s.%s" % (chosen.get("serial"), state, hint))
        return chosen

    @staticmethod
    def _device_list_text(devices: Sequence[Dict[str, str]]) -> str:
        if not devices:
            return "(none)"
        return "; ".join("%s [%s]" % (d.get("serial"), d.get("state")) for d in devices)

    # -- properties --------------------------------------------------------
    def get_props(self, refresh: bool = False) -> Dict[str, str]:
        if self._props is not None and not refresh:
            return self._props
        result = self.shell("getprop", timeout=20)
        props: Dict[str, str] = {}
        for line in result.stdout.splitlines():
            match = re.match(r"^\[(.+?)\]:\s*\[(.*)\]\s*$", line)
            if match:
                props[match.group(1)] = match.group(2)
        self._props = props
        return props

    def getprop(self, key: str, default: str = "") -> str:
        props = self.get_props()
        if key in props:
            return props.get(key, default)
        result = self.shell_args("getprop", key, timeout=15)
        return result.stdout.strip() if result.ok else default

    # -- settings ----------------------------------------------------------
    def settings_get(self, namespace: str, key: str) -> Optional[str]:
        result = self.shell_args("settings", "get", namespace, key, timeout=20)
        if not result.ok:
            return None
        return normalize_setting(result.stdout)

    def settings_put(self, namespace: str, key: str, value: str) -> CmdResult:
        return self.shell_args("settings", "put", namespace, key, value, timeout=20)

    def settings_delete(self, namespace: str, key: str) -> CmdResult:
        return self.shell_args("settings", "delete", namespace, key, timeout=20)

    # -- packages ----------------------------------------------------------
    def pm_list(self, flags: Sequence[str]) -> Tuple[Set[str], CmdResult]:
        result = self.shell_args("pm", "list", "packages", *flags, timeout=45)
        packages: Set[str] = set()
        for line in result.stdout.splitlines():
            line = line.strip()
            if line.startswith("package:"):
                packages.add(line[len("package:"):].strip())
        return packages, result

    def package_inventory(self) -> Dict[str, Any]:
        warnings: List[str] = []
        system, sys_result = self.pm_list(["-s"])
        third, third_result = self.pm_list(["-3"])
        disabled, disabled_result = self.pm_list(["-d"])
        enabled, enabled_result = self.pm_list(["-e"])
        if not system and not sys_result.ok:
            warnings.append("could not list system packages: %s" % sys_result.summary(160))
        if not third and not third_result.ok:
            warnings.append("could not list third-party packages: %s" % third_result.summary(160))
        if not disabled and not disabled_result.ok:
            warnings.append("could not list disabled packages; per-package verification will be used")
        self._system_packages = system
        self._third_party_packages = third
        self._disabled_packages = disabled
        return {
            "system": system,
            "third_party": third,
            "disabled": disabled,
            "enabled": enabled,
            "counts": {
                "system": len(system),
                "third_party": len(third),
                "disabled": len(disabled),
                "enabled": len(enabled),
            },
            "warnings": warnings,
        }

    def app_state(self, package: str) -> AppState:
        if not PACKAGE_RE.match(package):
            raise ValidationError("invalid package name: %r" % package)
        state = AppState(package=package)
        result = self.shell_args("dumpsys", "package", package, timeout=30)
        text = result.stdout if result.ok or result.stdout else ""
        if result.ok and not text:
            text = result.stderr
        if text:
            lines = text.splitlines()
            user_line = ""
            for line in lines:
                if re.search(r"\bUser\s+%d:" % self.user, line):
                    user_line = line
                    break
            if not user_line:
                for line in lines:
                    if "enabled=" in line and "installed=" in line:
                        user_line = line
                        break
            state.raw_line = user_line.strip()
            enabled_match = re.search(r"\benabled=(\d+|true|false|default)", user_line or text)
            if enabled_match:
                raw_enabled = enabled_match.group(1).lower()
                if raw_enabled == "true":
                    state.enabled = 1
                elif raw_enabled == "false":
                    state.enabled = 2
                elif raw_enabled == "default":
                    state.enabled = 0
                else:
                    state.enabled = safe_int(raw_enabled)
            state.suspended = bool(re.search(r"\bsuspended=true\b", user_line or text))
            state.hidden = bool(re.search(r"\bhidden=true\b", user_line or text))
            state.stopped = bool(re.search(r"\bstopped=true\b", user_line or text))
            state.installed = bool(re.search(r"\binstalled=true\b", text))
            version_match = re.search(r"\bversionName=(\S+)", text)
            if version_match:
                state.version_name = version_match.group(1)
            flags_match = re.search(r"\bpkgFlags=\[([^\]]*)\]", text)
            if flags_match and "SYSTEM" in flags_match.group(1):
                state.is_system = True
        if not state.installed:
            path = self.shell_args("pm", "path", package, timeout=15)
            state.installed = path.ok and "package:" in path.stdout
        if state.enabled is None and state.installed:
            # Android 4.x dumpsys formats vary; use the package lists as a
            # last-resort source of truth for the enabled bit.
            disabled_result = self.shell_args("pm", "list", "packages", "-d", package, timeout=20)
            if "package:" in disabled_result.stdout:
                state.enabled = 3
            else:
                enabled_result = self.shell_args("pm", "list", "packages", "-e", package, timeout=20)
                if "package:" in enabled_result.stdout:
                    state.enabled = 1
        if self._system_packages is not None:
            state.is_system = state.is_system or package in self._system_packages
        return state

    def disable_package(self, package: str, state: Optional[AppState] = None) -> Dict[str, Any]:
        if not PACKAGE_RE.match(package):
            raise ValidationError("invalid package name: %r" % package)
        before = state or self.app_state(package)
        if not before.installed:
            return {"ok": False, "result": "not-installed", "before": before.to_dict(), "after": before.to_dict(), "detail": "package is not installed"}
        if before.disabled:
            return {"ok": True, "result": "already-disabled", "before": before.to_dict(), "after": before.to_dict(), "detail": "already disabled"}
        if before.suspended:
            return {"ok": True, "result": "already-suspended", "before": before.to_dict(), "after": before.to_dict(), "detail": "already suspended"}
        attempts = [
            ["pm", "disable-user", "--user", str(self.user), package],
            ["pm", "disable-user", package],
            ["pm", "disable", package],
        ]
        last: Optional[CmdResult] = None
        after = before
        for attempt in attempts:
            last = self.shell_args(*attempt, timeout=30)
            time.sleep(0.15)
            after = self.app_state(package)
            if after.disabled:
                return {"ok": True, "result": "disabled", "before": before.to_dict(), "after": after.to_dict(), "detail": last.summary(240)}
        # Some ROMs return 0 while silently leaving the package at its default
        # state.  The resulting state, not the exit code, is authoritative.
        protected = after.enabled in (0, 1, None)
        return {
            "ok": False,
            "result": "protected" if protected else "failed",
            "before": before.to_dict(),
            "after": after.to_dict(),
            "detail": (last.summary(400) if last else "command failed"),
        }

    def enable_package(self, package: str) -> Dict[str, Any]:
        if not PACKAGE_RE.match(package):
            raise ValidationError("invalid package name: %r" % package)
        before = self.app_state(package)
        if not before.installed:
            return {"ok": False, "result": "not-installed", "before": before.to_dict(), "after": before.to_dict()}
        attempts = [
            ["pm", "enable", "--user", str(self.user), package],
            ["pm", "enable", package],
        ]
        last: Optional[CmdResult] = None
        after = before
        for attempt in attempts:
            last = self.shell_args(*attempt, timeout=30)
            time.sleep(0.15)
            after = self.app_state(package)
            if not after.disabled and not after.suspended:
                return {"ok": True, "result": "enabled", "before": before.to_dict(), "after": after.to_dict(), "detail": last.summary(240)}
        return {"ok": False, "result": "failed", "before": before.to_dict(), "after": after.to_dict(), "detail": (last.summary(300) if last else "command failed")}

    def suspend_package(self, package: str) -> Dict[str, Any]:
        before = self.app_state(package)
        if before.suspended:
            return {"ok": True, "result": "already-suspended", "before": before.to_dict(), "after": before.to_dict()}
        result = self.shell_args("pm", "suspend", "--user", str(self.user), package, timeout=30)
        after = self.app_state(package)
        if after.suspended:
            return {"ok": True, "result": "suspended", "before": before.to_dict(), "after": after.to_dict(), "detail": result.summary(240)}
        return {"ok": False, "result": "failed", "before": before.to_dict(), "after": after.to_dict(), "detail": result.summary(300)}

    def unsuspend_package(self, package: str) -> Dict[str, Any]:
        before = self.app_state(package)
        result = self.shell_args("pm", "unsuspend", "--user", str(self.user), package, timeout=30)
        after = self.app_state(package)
        if not after.suspended:
            return {"ok": True, "result": "unsuspended", "before": before.to_dict(), "after": after.to_dict(), "detail": result.summary(240)}
        return {"ok": False, "result": "failed", "before": before.to_dict(), "after": after.to_dict(), "detail": result.summary(300)}

    def force_stop(self, package: str) -> CmdResult:
        if not PACKAGE_RE.match(package):
            raise ValidationError("invalid package name: %r" % package)
        return self.shell_args("am", "force-stop", package, timeout=20)

    # -- storage / memory --------------------------------------------------
    def get_storage(self) -> Dict[str, Any]:
        result = self.shell("df -k /data", timeout=20)
        data: Dict[str, Any] = {"total": None, "used": None, "available": None, "percent": None, "app_size": None, "app_cache": None, "source": None}
        if result.ok:
            for line in result.stdout.splitlines():
                line = line.strip()
                if not line or line.lower().startswith("filesystem"):
                    continue
                parts = line.split()
                if len(parts) < 6:
                    continue
                if parts[-1] in ("/data", "/data/user/0") or "/data" in parts[-1]:
                    total = safe_int(parts[1])
                    used = safe_int(parts[2])
                    available = safe_int(parts[3])
                    if total is not None and used is not None and available is not None:
                        data.update({
                            "total": total * 1024,
                            "used": used * 1024,
                            "available": available * 1024,
                            "percent": parts[4] if len(parts) > 4 else None,
                            "source": "df",
                        })
                    break
        disk = self.shell("dumpsys diskstats", timeout=20)
        if disk.ok:
            free_match = re.search(r"Data-Free:\s*(\d+)K\s*/\s*(\d+)K", disk.stdout)
            if free_match and data["total"] is None:
                available = int(free_match.group(1)) * 1024
                total = int(free_match.group(2)) * 1024
                data.update({"available": available, "total": total, "used": max(0, total - available), "source": "diskstats"})
            app_match = re.search(r"App Size:\s*(\d+)", disk.stdout)
            cache_match = re.search(r"App Cache Size:\s*(\d+)", disk.stdout)
            if app_match:
                data["app_size"] = int(app_match.group(1))
            if cache_match:
                data["app_cache"] = int(cache_match.group(1))
        return data

    def get_memory(self) -> Dict[str, Any]:
        result = self.shell("cat /proc/meminfo", timeout=20)
        data: Dict[str, Any] = {"total": None, "free": None, "available": None, "swap_total": None, "swap_free": None}
        if result.ok:
            for line in result.stdout.splitlines():
                match = re.match(r"^(\w+):\s+(\d+)\s*kB", line.strip())
                if not match:
                    continue
                key = match.group(1)
                value = int(match.group(2)) * 1024
                if key == "MemTotal":
                    data["total"] = value
                elif key == "MemFree":
                    data["free"] = value
                elif key == "MemAvailable":
                    data["available"] = value
                elif key == "SwapTotal":
                    data["swap_total"] = value
                elif key == "SwapFree":
                    data["swap_free"] = value
        cores = self.shell("nproc", timeout=10)
        data["cores"] = safe_int(cores.stdout, None) if cores.ok else None
        load = self.shell("cat /proc/loadavg", timeout=10)
        data["load"] = None
        if load.ok:
            parts = load.stdout.split()
            if len(parts) >= 3:
                data["load"] = [safe_float(parts[0]), safe_float(parts[1]), safe_float(parts[2])]
        return data

    def get_battery(self) -> Dict[str, Any]:
        result = self.shell("dumpsys battery", timeout=20)
        data: Dict[str, Any] = {"level": None, "status": None, "health": None, "temperature_c": None, "voltage_mv": None}
        if result.ok:
            for line in result.stdout.splitlines():
                line = line.strip()
                level = re.match(r"level:\s*(\d+)", line)
                if level and data["level"] is None:
                    data["level"] = int(level.group(1))
                status = re.match(r"status:\s*(\d+)", line)
                if status and data["status"] is None:
                    data["status"] = int(status.group(1))
                health = re.match(r"health:\s*(\d+)", line)
                if health and data["health"] is None:
                    data["health"] = int(health.group(1))
                temp = re.match(r"temperature:\s*(-?\d+)", line)
                if temp and data["temperature_c"] is None:
                    data["temperature_c"] = int(temp.group(1)) / 10.0
                voltage = re.match(r"voltage:\s*(\d+)", line)
                if voltage and data["voltage_mv"] is None:
                    data["voltage_mv"] = int(voltage.group(1))
        return data

    def get_thermal(self) -> Dict[str, Any]:
        result = self.shell("dumpsys thermalservice", timeout=20)
        data: Dict[str, Any] = {"status": None, "max_cpu_c": None}
        if not result.ok:
            return data
        status = re.search(r"Thermal Status:\s*(\d+)", result.stdout)
        if status:
            data["status"] = int(status.group(1))
        temps = [float(x) for x in re.findall(r"mValue=([0-9.]+)", result.stdout)]
        if temps:
            data["max_cpu_c"] = round(max(temps), 1)
        return data

    # -- users / roles -----------------------------------------------------
    def get_users(self) -> List[Dict[str, Any]]:
        result = self.shell("pm list users", timeout=20)
        users: List[Dict[str, Any]] = []
        if result.ok:
            for line in result.stdout.splitlines():
                match = re.search(r"UserInfo\{(\d+):([^:]+):([^}]*)\}", line)
                if match:
                    users.append({
                        "id": int(match.group(1)),
                        "name": match.group(2),
                        "running": "running" in line,
                    })
        if not users:
            users = [{"id": 0, "name": "Owner", "running": True}]
        return users

    def _role_holder(self, role: str) -> Optional[str]:
        result = self.shell_args("cmd", "role", "get-role-holders", role, timeout=20)
        if not result.ok:
            return None
        for line in result.stdout.splitlines():
            candidate = line.strip()
            if not candidate or candidate.lower().startswith(("error", "failed", "unknown")):
                continue
            if PACKAGE_RE.match(candidate.split("/")[0]):
                return candidate
        return None

    def get_defaults(self) -> Dict[str, Optional[str]]:
        defaults: Dict[str, Optional[str]] = {}
        defaults["launcher"] = self._role_holder("android.app.role.HOME")
        defaults["sms"] = self._role_holder("android.app.role.SMS")
        defaults["dialer"] = self._role_holder("android.app.role.DIALER")
        if not defaults["sms"]:
            defaults["sms"] = self.settings_get("secure", "sms_default_application")
        if not defaults["dialer"]:
            defaults["dialer"] = self.settings_get("secure", "dialer_default_application")
        if not defaults["launcher"]:
            result = self.shell("cmd package resolve-activity --brief -a android.intent.action.MAIN -c android.intent.category.HOME", timeout=20)
            if result.ok:
                for line in reversed(result.stdout.splitlines()):
                    line = line.strip()
                    if "/" in line and PACKAGE_RE.match(line.split("/")[0]):
                        defaults["launcher"] = line
                        break
        if not defaults["launcher"]:
            # Android 4.x fallback.  mHomeProcess usually contains the
            # launcher package even when there is no role/package command.
            activity = self.shell("dumpsys activity activities", timeout=30)
            if not activity.ok or not activity.stdout:
                activity = self.shell("dumpsys activity", timeout=30)
            if activity.ok:
                for line in activity.stdout.splitlines():
                    if "mHomeProcess" in line or "mResumedActivity" in line:
                        match = re.search(r"([A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z0-9_]+)+)/", line)
                        if match and PACKAGE_RE.match(match.group(1)):
                            defaults["launcher"] = match.group(1)
                            break
        defaults["assistant"] = self.settings_get("secure", "assistant")
        defaults["ime"] = self.settings_get("secure", "default_input_method")
        return defaults

    # -- appops / standby / doze ------------------------------------------
    def appops_write_capable(self, sdk: int) -> bool:
        op = "RUN_ANY_IN_BACKGROUND" if sdk >= 26 else "RUN_IN_BACKGROUND"
        result = self.shell_args("cmd", "appops", "set", "com.android.shell", op, "default", timeout=15)
        if result.ok and "SecurityException" not in result.combined and "Access denied" not in result.combined:
            return True
        result = self.shell_args("appops", "set", "com.android.shell", op, "default", timeout=15)
        return result.ok and "SecurityException" not in result.combined and "Access denied" not in result.combined

    def appops_get(self, package: str, op: str) -> Optional[str]:
        prefixes = [["cmd", "appops"]] if self._cmd_available() else [["appops"]]
        for prefix in prefixes:
            result = self.shell_args(*prefix, "get", "--user", str(self.user), package, op, timeout=20)
            if result.ok:
                text = result.stdout.strip()
                if "No operations" in text:
                    return "default"
                match = re.search(r"%s\s*[:=]\s*(\w+)" % re.escape(op), text)
                if match:
                    return match.group(1).lower()
                match = re.search(r"Default mode:\s*(\w+)", text)
                if match:
                    return match.group(1).lower()
        return None

    def appops_set(self, package: str, op: str, mode: str) -> CmdResult:
        prefixes = [["cmd", "appops"]] if self._cmd_available() else [["appops"]]
        result: Optional[CmdResult] = None
        for prefix in prefixes:
            result = self.shell_args(*prefix, "set", "--user", str(self.user), package, op, mode, timeout=20)
            if result.ok and "SecurityException" not in result.combined:
                return result
        return result or self.shell_args("false", timeout=5)

    def standby_capable(self) -> bool:
        help_result = self.shell("am help", timeout=20)
        return help_result.ok and "set-standby-bucket" in help_result.stdout

    def get_standby_bucket(self, package: str) -> Optional[int]:
        result = self.shell_args("am", "get-standby-bucket", package, timeout=20)
        if not result.ok:
            return None
        match = re.search(r"\b(\d+)\b", result.stdout)
        return int(match.group(1)) if match else None

    def set_standby_bucket(self, package: str, bucket: str) -> Dict[str, Any]:
        before = self.get_standby_bucket(package)
        result = self.shell_args("am", "set-standby-bucket", package, bucket, timeout=20)
        after = self.get_standby_bucket(package)
        expected = {"exempted": 5, "active": 10, "working_set": 20, "frequent": 30, "rare": 40, "restricted": 45, "never": 50}.get(bucket)
        ok = result.ok and (expected is None or after == expected)
        return {"ok": ok, "before": before, "after": after, "detail": result.summary(240)}

    def doze_capable(self) -> bool:
        result = self.shell("dumpsys deviceidle", timeout=20)
        return result.ok and ("mState=" in result.stdout or "Device idle" in result.stdout)

    def get_doze_whitelist(self) -> List[str]:
        """Return user-removable Doze whitelist entries.

        Android reports three kinds of entries: user, system and system-excidle.
        The shell UID can remove user entries; system/system-excidle entries are
        protected and would otherwise look like repeated failures.
        """
        result = None
        if self._cmd_available():
            result = self.shell_args("cmd", "deviceidle", "whitelist", timeout=20)
        if result is None or not result.ok or not result.stdout.strip():
            result = self.shell("dumpsys deviceidle whitelist", timeout=20)
        packages: Set[str] = set()
        if result.ok:
            for line in result.stdout.splitlines():
                parts = [p.strip() for p in line.split(",") if p.strip()]
                if not parts:
                    continue
                if len(parts) >= 2 and parts[0] == "user":
                    package = parts[1]
                elif len(parts) == 1 and PACKAGE_RE.match(parts[0]):
                    # Older output formats list only the package name.
                    package = parts[0]
                else:
                    continue
                if PACKAGE_RE.match(package):
                    packages.add(package)
        return sorted(packages)

    def doze_whitelist_remove(self, package: str) -> CmdResult:
        if self._cmd_available():
            return self.shell_args("cmd", "deviceidle", "whitelist", "-" + package, timeout=20)
        return self.shell_args("dumpsys", "deviceidle", "whitelist", "-" + package, timeout=20)

    def doze_whitelist_add(self, package: str) -> CmdResult:
        if self._cmd_available():
            return self.shell_args("cmd", "deviceidle", "whitelist", "+" + package, timeout=20)
        return self.shell_args("dumpsys", "deviceidle", "whitelist", "+" + package, timeout=20)

    # -- compile / cache ---------------------------------------------------
    def compile_capable(self) -> bool:
        if self._cmd_available():
            result = self.shell_args("cmd", "package", "help", timeout=20)
            if result.ok and "compile" in result.stdout:
                return True
        result = self.shell("pm help", timeout=20)
        return result.ok and "compile" in result.stdout

    def compile_package(self, package: str, mode: str = "speed") -> CmdResult:
        if self._cmd_available():
            result = self.shell_args("cmd", "package", "compile", "-m", mode, "-f", package, timeout=240)
            if result.ok:
                return result
        return self.shell_args("pm", "compile", "-m", mode, "-f", package, timeout=240)

    def compile_package_advanced(self, package: str, mode: str = "speed-profile",
                                 priority: str = "PRIORITY_BACKGROUND",
                                 full: bool = False, reset: bool = False,
                                 timeout: int = 300) -> CmdResult:
        """Compile one package with the modern cmd package options."""
        if self._cmd_available():
            args: List[str] = ["cmd", "package", "compile"]
            if reset:
                args.extend(["--reset", package])
            else:
                args.extend(["-m", mode, "-p", priority, "-f"])
                if full:
                    args.append("--full")
                args.append(package)
            return self.shell_args(*args, timeout=timeout)
        if reset:
            return CmdResult(["pm", "compile", "--reset", package], 1, "", "--reset requires Android 7+ (cmd package)", 0.0)
        # Legacy fallback: no priority/full scope support.
        return self.shell_args("pm", "compile", "-m", mode, "-f", package, timeout=timeout)

    def get_dexopt_state(self) -> Dict[str, Dict[str, Any]]:
        result = self.shell_args("dumpsys", "package", "dexopt", timeout=120)
        if not result.ok:
            return {}
        return parse_dexopt_state(result.stdout)

    def get_package_dexopt_status(self, package: str) -> Optional[Dict[str, Any]]:
        result = self.shell_args("dumpsys", "package", package, timeout=30)
        if not result.ok:
            return None
        return parse_package_dexopt(result.stdout)

    # -- privileged kernel access (root only) ------------------------------
    def root_mode(self) -> Optional[str]:
        if hasattr(self, "_root_mode_cache"):
            return self._root_mode_cache
        self._root_mode_cache = None
        uid = self.shell("id -u", timeout=10)
        if uid.ok and uid.stdout.strip() == "0":
            self._root_mode_cache = "adb"
            return self._root_mode_cache
        su = self.shell_args("su", "-c", "id", timeout=15)
        if "uid=0" in su.combined:
            self._root_mode_cache = "su"
        return self._root_mode_cache

    def root_available(self) -> bool:
        return self.root_mode() is not None

    def root_shell(self, command: str, timeout: int = 30) -> CmdResult:
        mode = self.root_mode()
        if mode == "adb":
            return self.shell(command, timeout=timeout)
        if mode == "su":
            return self.shell_args("su", "-c", command, timeout=timeout)
        return CmdResult(["root"], 126, "", "root is not available", 0.0)

    def kernel_read(self, path: str, root: bool = False) -> Optional[str]:
        if not KERNEL_SAFE_PATH_RE.match(path) or ".." in path:
            return None
        result = self.root_shell("cat " + shlex.quote(path), timeout=15) if root else self.shell_args("cat", path, timeout=15)
        if not result.ok:
            return None
        value = result.stdout.strip()
        return value or None

    def kernel_write(self, path: str, value: str) -> Dict[str, Any]:
        before = self.kernel_read(path, root=True)
        if not any(pattern.match(path) for pattern in KERNEL_WRITE_PATTERNS):
            return {"ok": False, "error": "kernel path is not allowlisted", "before": before}
        if not KERNEL_VALUE_RE.match(value):
            return {"ok": False, "error": "kernel value is not safe", "before": before}
        if not self.root_available():
            return {"ok": False, "error": "root is required for kernel writes", "before": before}
        # Use a single printf format so values containing % are not interpreted.
        command = "printf '%%s' %s > %s" % (shlex.quote(value), shlex.quote(path))
        result = self.root_shell(command, timeout=15)
        after = self.kernel_read(path, root=True)
        ok = result.ok and after == value
        return {
            "ok": ok,
            "before": before,
            "after": after,
            "detail": result.summary(300),
        }

    def device_config_get(self, namespace: str, key: str) -> Optional[str]:
        result = self.shell_args("device_config", "get", namespace, key, timeout=20)
        if not result.ok:
            return None
        value = normalize_setting(result.stdout)
        return None if value == "null" else value

    def device_config_put(self, namespace: str, key: str, value: str) -> CmdResult:
        return self.shell_args("device_config", "put", namespace, key, value, timeout=20)

    def device_config_delete(self, namespace: str, key: str) -> CmdResult:
        return self.shell_args("device_config", "delete", namespace, key, timeout=20)

    def adaptive_power_saver_state(self) -> Optional[bool]:
        result = self.shell("dumpsys power", timeout=25)
        if not result.ok:
            return None
        matches = re.findall(r"\badaptive=(true|false)\b", result.stdout)
        if matches:
            return matches[-1] == "true"
        return None

    def set_adaptive_power_saver(self, enabled: bool) -> Dict[str, Any]:
        before = self.adaptive_power_saver_state()
        result = self.shell_args("cmd", "power", "set-adaptive-power-saver-enabled", "true" if enabled else "false", timeout=20)
        after = self.adaptive_power_saver_state()
        return {"ok": result.ok and (after is None or after == enabled), "before": before, "after": after, "detail": result.summary(240)}

    def fstrim(self) -> CmdResult:
        return self.shell_args("sm", "fstrim", timeout=180)

    def bg_dexopt(self) -> CmdResult:
        if self._cmd_available():
            result = self.shell_args("cmd", "package", "bg-dexopt-job", timeout=30)
            if result.ok:
                return result
        return self.shell_args("pm", "bg-dexopt-job", timeout=30)

    def trim_caches(self, size: str = DEFAULT_CACHE_TRIM) -> CmdResult:
        result = self.shell_args("pm", "trim-caches", size, timeout=300)
        if result.ok:
            return result
        fallback = "999999M" if size != "999999M" else "512M"
        result = self.shell_args("pm", "trim-caches", fallback, timeout=300)
        if result.ok:
            return result
        if self._cmd_available():
            result = self.shell_args("cmd", "package", "trim-caches", size, timeout=300)
        return result

    def suspend_capable(self) -> bool:
        result = self.shell("pm help", timeout=20)
        return result.ok and "suspend" in result.stdout

    def _cmd_available(self) -> bool:
        if not hasattr(self, "_cmd_cache"):
            result = self.shell("cmd -l", timeout=15)
            self._cmd_cache = result.ok and "package" in result.stdout
        return bool(self._cmd_cache)

    # -- capability probe --------------------------------------------------
    def probe_capabilities(self, sdk: int) -> Dict[str, Any]:
        caps: Dict[str, Any] = {}
        settings_probe = self.shell_args("settings", "get", "global", "window_animation_scale", timeout=15)
        caps["settings"] = bool(settings_probe.ok and "not found" not in settings_probe.combined.lower())
        caps["cmd"] = self._cmd_available()
        caps["appops_read"] = bool(caps["cmd"] or self.shell_args("appops", "help", timeout=15).ok)
        caps["appops_write"] = self.appops_write_capable(sdk) if caps["appops_read"] else False
        caps["deviceidle"] = self.doze_capable()
        caps["standby"] = self.standby_capable()
        caps["compile"] = self.compile_capable()
        caps["suspend"] = self.suspend_capable()
        pm_help = self.shell("pm help", timeout=20)
        caps["trim"] = bool(pm_help.ok and "trim-caches" in pm_help.stdout)
        caps["users"] = self.shell("pm list users", timeout=15).ok
        caps["roles"] = bool(caps["cmd"] and self.shell("cmd -l", timeout=15).stdout.find("role") >= 0)
        caps["wm"] = self.shell("wm size", timeout=15).ok
        caps["diskstats"] = "Data-Free" in self.shell("dumpsys diskstats", timeout=15).stdout
        caps["usage"] = self.shell("dumpsys usagestats", timeout=30).ok
        caps["root"] = self.shell("id -u", timeout=10).stdout.strip() == "0"
        caps["sdk"] = sdk
        return caps

    def quick_status(self) -> Dict[str, Any]:
        disabled, _ = self.pm_list(["-d"])
        enabled, _ = self.pm_list(["-e"])
        storage = self.get_storage()
        memory = self.get_memory()
        battery = self.get_battery()
        return {
            "disabled_count": len(disabled),
            "enabled_count": len(enabled),
            "storage": storage,
            "memory": memory,
            "battery": battery,
        }

# ---------------------------------------------------------------------------
# Device profile collection
# ---------------------------------------------------------------------------

def detect_vendor(props: Dict[str, str]) -> str:
    manufacturer = props.get("ro.product.manufacturer", "").lower()
    brand = props.get("ro.product.brand", "").lower()
    model = props.get("ro.product.model", "").lower()
    device = props.get("ro.product.device", "").lower()
    fingerprint = props.get("ro.build.fingerprint", "").lower()
    text = " ".join([manufacturer, brand, model, device, fingerprint])
    # Order matters: OnePlus fingerprints can contain OPPO strings.
    checks: List[Tuple[str, List[str]]] = [
        ("samsung", ["samsung"]),
        ("xiaomi", ["xiaomi", "redmi", "poco"]),
        ("huawei", ["huawei", "honor", "hihonor"]),
        ("vivo", ["vivo", "iqoo"]),
        ("transsion", ["tecno", "infinix", "itel", "transsion"]),
        ("motorola", ["motorola", "moto "]),
        ("oneplus", ["oneplus", "oppo", "realme", "cph", "pht", "rmx"]),
        ("pixel", ["google", "pixel"]),
    ]
    for key, tokens in checks:
        if any(token in text for token in tokens):
            return key
    return "generic"


def _vendor_data(vendor: str, extra: Optional[Dict[str, Dict[str, Any]]] = None) -> Dict[str, Any]:
    base = VENDOR_PROFILES.get(vendor, VENDOR_PROFILES["generic"])
    if not extra or vendor not in extra:
        return base
    # Extend, do not replace, built-in lists.
    merged = dict(base)
    for tier in ("conservative", "balanced", "aggressive"):
        merged[tier] = dedupe(list(base.get(tier, [])) + list(extra[vendor].get(tier, [])))
    return merged


def tier_packages(vendor: str, tier: str,
                  extra: Optional[Dict[str, Dict[str, Any]]] = None) -> List[str]:
    """Packages belonging to exactly one tier (not cumulative)."""
    packages = list(UNIVERSAL_PROFILES.get(tier, []))
    packages.extend(_vendor_data(vendor, extra).get(tier, []))
    return dedupe(packages)


def profile_packages(vendor: str, profile: str,
                     extra: Optional[Dict[str, Dict[str, Any]]] = None) -> List[str]:
    tiers = PROFILE_TIERS.get(profile, ["conservative", "balanced"])
    packages: List[str] = []
    for tier in tiers:
        packages.extend(tier_packages(vendor, tier, extra))
    return dedupe(packages)


def all_profile_packages(vendor: str, extra: Optional[Dict[str, Dict[str, Any]]] = None) -> Dict[str, List[str]]:
    return {tier: tier_packages(vendor, tier, extra) for tier in ("conservative", "balanced", "aggressive")}


def package_tier_risk(package: str, vendor: str,
                      extra: Optional[Dict[str, Dict[str, Any]]] = None) -> Tuple[str, str]:
    """Return (all matching tiers, lowest/least-risky tier's risk).

    If a package appears in both conservative and aggressive, disabling it is
    as safe as the conservative entry.  Only packages that appear solely in a
    higher tier inherit that higher risk.
    """
    found: List[str] = []
    for tier in ("conservative", "balanced", "aggressive"):
        if package in tier_packages(vendor, tier, extra):
            found.append(tier)
    if not found:
        return "unknown", "moderate"
    risk = "risky"
    for tier in found:
        tier_risk = {"conservative": "safe", "balanced": "moderate", "aggressive": "risky"}[tier]
        if RISK_ORDER[tier_risk] < RISK_ORDER[risk]:
            risk = tier_risk
    return ",".join(found), risk


def package_from_component(value: Optional[str]) -> Optional[str]:
    if not value:
        return None
    package = value.split("/")[0].strip()
    return package if PACKAGE_RE.match(package) else None


def build_critical_set(defaults: Dict[str, Optional[str]]) -> Set[str]:
    critical = set(CRITICAL_EXACT)
    for key in ("launcher", "sms", "dialer", "ime", "assistant"):
        package = package_from_component(defaults.get(key))
        if package:
            critical.add(package)
    return critical


def is_critical_package(package: str, critical: Set[str]) -> bool:
    if package in critical or package in CRITICAL_EXACT:
        return True
    return any(pattern.search(package) for pattern in CRITICAL_PATTERNS)


def is_communication_package(package: str) -> bool:
    lowered = package.lower()
    return any(pattern.search(lowered) for pattern in COMMUNICATION_PATTERNS)


def is_telemetry_package(package: str) -> bool:
    lowered = package.lower()
    return any(pattern.search(lowered) for pattern in TELEMETRY_PATTERNS)


def collect_settings(client: AdbClient, caps: Dict[str, Any], sdk: int,
                     warnings: List[str]) -> Dict[str, Optional[str]]:
    values: Dict[str, Optional[str]] = {}
    if not caps.get("settings"):
        warnings.append("the 'settings' shell command is unavailable; settings were not read or changed")
        return values
    keys = list(SETTINGS_SPEC.keys()) + [PRIVATE_DNS_SPEC["mode"], PRIVATE_DNS_SPEC["hostname"]]
    for namespace, key in keys:
        spec = SETTINGS_SPEC.get((namespace, key), {})
        min_sdk = spec.get("min_sdk", 0)
        if sdk and min_sdk and sdk < min_sdk:
            continue
        values[namespace + "." + key] = client.settings_get(namespace, key)
    return values


def collect_usage(client: AdbClient, caps: Dict[str, Any], warnings: List[str]) -> Dict[str, Any]:
    if not caps.get("usage"):
        return {"available": False, "event_count": 0, "top": [], "last_used": {}}
    result = client.shell("dumpsys usagestats", timeout=60)
    if not result.ok:
        warnings.append("could not read usage stats; unused-app detection is limited")
        return {"available": False, "event_count": 0, "top": [], "last_used": {}}
    counts: Dict[str, int] = {}
    last_used: Dict[str, str] = {}
    event_re = re.compile(r'time="([^"]+)"\s+type=([A-Z_]+)\s+package=([^\s]+)')
    for match in event_re.finditer(result.stdout):
        timestamp, event_type, package = match.group(1), match.group(2), match.group(3)
        if not PACKAGE_RE.match(package):
            continue
        counts[package] = counts.get(package, 0) + 1
        if event_type in ("ACTIVITY_RESUMED", "USER_INTERACTION", "ACTIVITY_STOPPED"):
            previous = last_used.get(package)
            if previous is None or timestamp > previous:
                last_used[package] = timestamp
    top = [{"package": pkg, "events": count} for pkg, count in sorted(counts.items(), key=lambda item: item[1], reverse=True)[:30]]
    if not counts:
        warnings.append("usage stats contained no package events; last-used data may be unavailable on this ROM")
    return {"available": True, "event_count": len(counts), "top": top, "last_used": last_used}


def collect_processes(client: AdbClient, warnings: List[str]) -> Dict[str, Any]:
    mem = client.shell("dumpsys meminfo", timeout=45)
    top_mem: List[Dict[str, Any]] = []
    if mem.ok:
        for line in mem.stdout.splitlines():
            match = re.match(r"^\s*([0-9,]+)K:\s+(.+?)\s+\(pid\s+(\d+)", line)
            if match:
                try:
                    rss_kb = int(match.group(1).replace(",", ""))
                except ValueError:
                    continue
                top_mem.append({"process": match.group(2).strip(), "pid": int(match.group(3)), "rss_bytes": rss_kb * 1024})
        top_mem = top_mem[:15]
    else:
        warnings.append("could not read dumpsys meminfo")
    cpu = client.shell("dumpsys cpuinfo", timeout=45)
    top_cpu: List[Dict[str, Any]] = []
    if cpu.ok:
        for line in cpu.stdout.splitlines():
            match = re.match(r"^\s*([0-9.]+)%\s+(\d+)/([^:]+):", line)
            if match:
                top_cpu.append({"cpu_percent": float(match.group(1)), "pid": int(match.group(2)), "process": match.group(3).strip()})
        top_cpu = top_cpu[:15]
    return {"top_memory": top_mem, "top_cpu": top_cpu}


def select_candidates(client: AdbClient, vendor: str, inventory: Dict[str, Any],
                      critical: Set[str], usage: Dict[str, Any],
                      extra: Optional[Dict[str, Dict[str, Any]]] = None,
                      allow_user_apps: bool = False) -> List[Dict[str, Any]]:
    installed = set(inventory.get("system", set())) | set(inventory.get("third_party", set()))
    disabled = set(inventory.get("disabled", set()))
    system = set(inventory.get("system", set()))
    last_used = usage.get("last_used", {}) if isinstance(usage, dict) else {}
    candidates: List[Dict[str, Any]] = []
    seen: Set[str] = set()
    for tier in ("conservative", "balanced", "aggressive"):
        for package in profile_packages(vendor, tier, extra):
            if package in seen:
                continue
            seen.add(package)
            if package not in installed:
                continue
            if package in disabled:
                continue
            if is_critical_package(package, critical):
                continue
            if system and package not in system and not allow_user_apps:
                continue
            tier_label, risk = package_tier_risk(package, vendor, extra)
            candidates.append({
                "package": package,
                "tiers": tier_label,
                "risk": risk,
                "system": package in system,
                "last_used": last_used.get(package),
            })
    candidates.sort(key=lambda item: (RISK_ORDER.get(item["risk"], 1), item["package"]))
    return candidates


def collect_profile(client: AdbClient, include_usage: bool = True,
                    include_processes: bool = True, full_packages: bool = False,
                    extra: Optional[Dict[str, Dict[str, Any]]] = None,
                    allow_user_apps: bool = False) -> Dict[str, Any]:
    warnings: List[str] = []
    props = client.get_props(refresh=True)
    sdk = safe_int(props.get("ro.build.version.sdk"), 0) or 0
    release = props.get("ro.build.version.release", "unknown")
    manufacturer = props.get("ro.product.manufacturer", "unknown")
    brand = props.get("ro.product.brand", manufacturer)
    model = props.get("ro.product.model", "unknown")
    device = props.get("ro.product.device", "unknown")
    fingerprint = props.get("ro.build.fingerprint", "unknown")
    vendor = detect_vendor(props)
    vendor_name = VENDOR_PROFILES.get(vendor, VENDOR_PROFILES["generic"]).get("name", vendor)

    caps = client.probe_capabilities(sdk)
    inventory = client.package_inventory()
    warnings.extend(inventory.get("warnings", []))
    users = client.get_users()
    defaults = client.get_defaults()
    critical = build_critical_set(defaults)
    storage = client.get_storage()
    memory = client.get_memory()
    battery = client.get_battery()
    thermal = client.get_thermal()
    settings = collect_settings(client, caps, sdk, warnings)
    doze_whitelist = client.get_doze_whitelist() if caps.get("deviceidle") else []
    usage = collect_usage(client, caps, warnings) if include_usage else {"available": False, "event_count": 0, "top": [], "last_used": {}}
    processes = collect_processes(client, warnings) if include_processes else {"top_memory": [], "top_cpu": []}
    candidates = select_candidates(client, vendor, inventory, critical, usage, extra, allow_user_apps)

    display: Dict[str, Any] = {}
    if caps.get("wm"):
        size_result = client.shell("wm size", timeout=15)
        density_result = client.shell("wm density", timeout=15)
        if size_result.ok:
            size_match = re.search(r"(?:Override|Physical) size:\s*(\d+)x(\d+)", size_result.stdout)
            if size_match:
                display["width"] = int(size_match.group(1))
                display["height"] = int(size_match.group(2))
            all_sizes = re.findall(r"(\d+)x(\d+)", size_result.stdout)
            display["sizes"] = all_sizes
        if density_result.ok:
            density_match = re.search(r"(?:Override|Physical) density:\s*(\d+)", density_result.stdout)
            if density_match:
                display["density"] = int(density_match.group(1))

    disabled_sample = sorted(inventory.get("disabled", set()))[:40]
    if full_packages:
        package_detail: Dict[str, Any] = {
            "system": sorted(inventory.get("system", set())),
            "third_party": sorted(inventory.get("third_party", set())),
            "disabled": sorted(inventory.get("disabled", set())),
        }
    else:
        package_detail = {
            "disabled_sample": disabled_sample,
            "third_party_sample": sorted(inventory.get("third_party", set()))[:80],
        }

    profile: Dict[str, Any] = {
        "generated_at": now_iso(),
        "serial": client.serial,
        "device": {
            "manufacturer": manufacturer,
            "brand": brand,
            "model": model,
            "device": device,
            "product": props.get("ro.product.name", "unknown"),
            "sdk": sdk,
            "release": release,
            "security_patch": props.get("ro.build.version.security_patch"),
            "fingerprint": fingerprint,
            "abi": props.get("ro.product.cpu.abi"),
            "first_api": safe_int(props.get("ro.product.first_api_level"), None),
            "build_type": props.get("ro.build.type"),
            "build_tags": props.get("ro.build.tags"),
            "selinux": props.get("ro.boot.selinux") or props.get("ro.build.selinux"),
            "root": bool(caps.get("root")),
            "users": users,
        },
        "vendor": vendor,
        "vendor_name": vendor_name,
        "capabilities": caps,
        "display": display,
        "storage": storage,
        "memory": memory,
        "battery": battery,
        "thermal": thermal,
        "packages": {"counts": dict(inventory.get("counts", {})), **package_detail},
        "defaults": defaults,
        "critical_packages": sorted(critical),
        "settings": settings,
        "doze": {"whitelist": doze_whitelist, "count": len(doze_whitelist)},
        "usage": usage,
        "processes": processes,
        "candidates": candidates,
        "warnings": dedupe(warnings),
    }
    return profile


def compact_profile(profile: Dict[str, Any], max_candidates: int = 80) -> Dict[str, Any]:
    device = profile.get("device", {})
    packages = profile.get("packages", {})
    candidates = profile.get("candidates", [])
    usage = profile.get("usage", {})
    processes = profile.get("processes", {})
    compact = {
        "serial": profile.get("serial"),
        "device": {
            "manufacturer": device.get("manufacturer"),
            "brand": device.get("brand"),
            "model": device.get("model"),
            "sdk": device.get("sdk"),
            "release": device.get("release"),
            "fingerprint": device.get("fingerprint"),
            "abi": device.get("abi"),
            "root": device.get("root"),
            "users": device.get("users"),
        },
        "vendor": profile.get("vendor"),
        "vendor_name": profile.get("vendor_name"),
        "capabilities": profile.get("capabilities", {}),
        "storage": profile.get("storage", {}),
        "memory": profile.get("memory", {}),
        "battery": profile.get("battery", {}),
        "thermal": profile.get("thermal", {}),
        "packages": {
            "counts": packages.get("counts", {}),
            "disabled_sample": packages.get("disabled_sample", [])[:30],
            "third_party_sample": packages.get("third_party_sample", [])[:40],
        },
        "defaults": profile.get("defaults", {}),
        "settings": profile.get("settings", {}),
        "doze": {"count": profile.get("doze", {}).get("count", 0)},
        "usage": {
            "available": usage.get("available"),
            "event_count": usage.get("event_count"),
            "top": usage.get("top", [])[:15],
        },
        "processes": {
            "top_memory": processes.get("top_memory", [])[:8],
            "top_cpu": processes.get("top_cpu", [])[:8],
        },
        "candidates": candidates[:max_candidates],
        "warnings": profile.get("warnings", [])[:15],
    }
    # Keep prompts bounded even on large package inventories.
    while len(json.dumps(compact, ensure_ascii=False)) > 24_000 and len(compact["candidates"]) > 30:
        compact["candidates"] = compact["candidates"][:-10]
    return compact


def print_profile_summary(profile: Dict[str, Any]) -> None:
    device = profile.get("device", {})
    storage = profile.get("storage", {})
    memory = profile.get("memory", {})
    battery = profile.get("battery", {})
    thermal = profile.get("thermal", {})
    packages = profile.get("packages", {})
    counts = packages.get("counts", {})
    caps = profile.get("capabilities", {})
    print("%s%s%s" % (_COLORS.bold, "Device", _COLORS.reset))
    print("  %s %s (%s) - Android %s / API %s" % (
        device.get("manufacturer"), device.get("model"), device.get("device"),
        device.get("release"), device.get("sdk")))
    print("  serial: %s" % profile.get("serial"))
    print("  vendor profile: %s" % profile.get("vendor_name"))
    print("  root: %s   users: %s" % (device.get("root"), len(device.get("users", []))))
    print("  fingerprint: %s" % device.get("fingerprint"))
    print("%sResources%s" % (_COLORS.bold, _COLORS.reset))
    print("  storage: %s used / %s total (%s free)" % (
        human_bytes(storage.get("used")), human_bytes(storage.get("total")), human_bytes(storage.get("available"))))
    print("  app cache: %s" % human_bytes(storage.get("app_cache")))
    print("  memory: %s available / %s total" % (human_bytes(memory.get("available")), human_bytes(memory.get("total"))))
    print("  load: %s   cores: %s" % (memory.get("load"), memory.get("cores")))
    print("  battery: %s%%   temp: %s C   thermal status: %s" % (
        battery.get("level"), battery.get("temperature_c"), thermal.get("status")))
    print("%sPackages%s" % (_COLORS.bold, _COLORS.reset))
    print("  system: %s   third-party: %s   disabled: %s   enabled: %s" % (
        counts.get("system"), counts.get("third_party"), counts.get("disabled"), counts.get("enabled")))
    print("  default launcher: %s" % profile.get("defaults", {}).get("launcher"))
    print("  default SMS: %s" % profile.get("defaults", {}).get("sms"))
    print("  default dialer: %s" % profile.get("defaults", {}).get("dialer"))
    print("%sCapabilities%s" % (_COLORS.bold, _COLORS.reset))
    interesting = [key for key in ("settings", "cmd", "appops_write", "deviceidle", "standby", "compile", "suspend", "trim", "roles", "usage") if key in caps]
    print("  " + "  ".join("%s=%s" % (key, "yes" if caps.get(key) else "no") for key in interesting))
    warnings = profile.get("warnings", [])
    if warnings:
        print("%sWarnings%s" % (_COLORS.bold, _COLORS.reset))
        for warning in warnings:
            print("  - %s" % warning)

# ---------------------------------------------------------------------------
# Journal and rollback data
# ---------------------------------------------------------------------------

class Journal:
    def __init__(self, device: Dict[str, Any], path: Optional[Path] = None,
                 enabled: bool = True) -> None:
        self.device = device
        self.path = Path(path) if path else None
        self.enabled = enabled
        self.created_at = now_iso()
        self.entries: List[Dict[str, Any]] = []

    def add(self, entry_type: str, **fields: Any) -> Dict[str, Any]:
        entry = {"type": entry_type, "timestamp": now_iso()}
        entry.update(fields)
        self.entries.append(entry)
        return entry

    def changed(self) -> int:
        count = 0
        for entry in self.entries:
            if entry.get("result") in ("disabled", "enabled", "set", "deleted", "removed", "added", "suspended", "unsuspended", "trimmed", "compiled", "started", "restricted"):
                count += 1
        return count

    def to_dict(self) -> Dict[str, Any]:
        return {
            "version": JOURNAL_VERSION,
            "created_at": self.created_at,
            "device": self.device,
            "entries": self.entries,
        }

    def save(self) -> Optional[Path]:
        if not self.enabled or self.path is None or not self.entries:
            return None
        write_json(self.path, self.to_dict())
        return self.path

    @staticmethod
    def load(path: Path) -> Dict[str, Any]:
        try:
            data = read_json(path)
        except OSError as exc:
            raise JournalError("could not read journal %s: %s" % (path, exc))
        except ValueError as exc:
            raise JournalError("journal %s is not valid JSON: %s" % (path, exc))
        if not isinstance(data, dict) or not isinstance(data.get("entries"), list):
            raise JournalError("journal %s has an unsupported format" % path)
        if data.get("version") != JOURNAL_VERSION:
            raise JournalError("journal %s has unsupported version %r" % (path, data.get("version")))
        return data


@dataclasses.dataclass
class OptimizerOptions:
    profile: str = "balanced"
    dry_run: bool = False
    allow_risky: bool = False
    allow_user_apps: bool = False
    do_settings: bool = True
    do_disable: bool = True
    do_cache_trim: bool = True
    do_doze_cleanup: bool = True
    cache_size: str = DEFAULT_CACHE_TRIM
    screen_timeout: int = DEFAULT_SCREEN_TIMEOUT_MS
    private_dns_mode: Optional[str] = None
    private_dns_host: Optional[str] = None
    restrict_unused: bool = False
    unused_days: int = 7
    compile_mode: Optional[str] = None
    dexopt: bool = False
    extra_profiles: Optional[Dict[str, Dict[str, Any]]] = None

    def validate(self) -> None:
        if self.profile not in PROFILE_TIERS:
            raise ValidationError("unknown profile: %s" % self.profile)
        if self.profile == "aggressive" and not self.allow_risky:
            raise SafetyError("the aggressive profile contains risky actions; pass --allow-risky to confirm")
        if not SIZE_RE.match(self.cache_size):
            raise ValidationError("invalid cache size %r (examples: 512M, 2G)" % self.cache_size)
        if not (15_000 <= int(self.screen_timeout) <= 1_800_000):
            raise ValidationError("screen timeout must be between 15000 and 1800000 ms")
        if self.private_dns_mode:
            if self.private_dns_mode not in ("off", "opportunistic", "hostname"):
                raise ValidationError("private DNS mode must be off, opportunistic or hostname")
            if self.private_dns_mode == "hostname" and (not self.private_dns_host or not HOSTNAME_RE.match(self.private_dns_host)):
                raise ValidationError("a valid --private-dns-host is required for hostname mode")
        if self.compile_mode and self.compile_mode not in ("speed", "speed-profile", "verify", "quicken"):
            raise ValidationError("invalid compile mode: %s" % self.compile_mode)
        if self.unused_days < 1 or self.unused_days > 365:
            raise ValidationError("unused days must be between 1 and 365")


class Optimizer:
    """Deterministic optimization engine used by both CLI and agent tools."""

    def __init__(self, client: AdbClient, profile: Dict[str, Any],
                 options: OptimizerOptions, journal: Journal) -> None:
        self.client = client
        self.profile = profile
        self.options = options
        self.journal = journal
        self.vendor = profile.get("vendor", "generic")
        self.sdk = int(profile.get("device", {}).get("sdk") or 0)
        self.critical = set(profile.get("critical_packages", []))
        self.caps = profile.get("capabilities", {})
        self.warnings: List[str] = list(profile.get("warnings", []))
        self.summary: Dict[str, Any] = {}
        self._inventory_loaded = False
        self.system_packages: Set[str] = set(client._system_packages or [])
        self.disabled_packages: Set[str] = set(client._disabled_packages or [])
        if not self.system_packages:
            inventory = client.package_inventory()
            self.system_packages = set(inventory.get("system", set()))
            self.disabled_packages = set(inventory.get("disabled", set()))
            self.warnings.extend(inventory.get("warnings", []))
            self._inventory_loaded = True

    # -- shared helpers ----------------------------------------------------
    def _log(self, message: str) -> None:
        log_info(message)

    def _ensure_risk(self, risk: str) -> None:
        allowed = PROFILE_RISK.get(self.options.profile, "safe")
        if RISK_ORDER.get(risk, 1) > RISK_ORDER.get(allowed, 0):
            raise SafetyError("action risk %s exceeds the %s profile" % (risk, self.options.profile))

    def _setting_target(self, namespace: str, key: str) -> Optional[str]:
        spec = SETTINGS_SPEC.get((namespace, key))
        if not spec:
            return None
        if (namespace, key) == ("system", "screen_off_timeout"):
            return str(int(self.options.screen_timeout))
        default = spec.get("default")
        if spec.get("type") == "float":
            return str(float(default))
        return str(default)

    def _validate_setting_target(self, namespace: str, key: str, target: str) -> str:
        spec = SETTINGS_SPEC.get((namespace, key))
        if not spec:
            raise SafetyError("setting %s/%s is not on the allowlist" % (namespace, key))
        kind = spec.get("type")
        if kind == "int":
            try:
                number = int(target)
            except ValueError:
                raise ValidationError("setting %s/%s requires an integer" % (namespace, key))
            minimum = spec.get("minimum")
            maximum = spec.get("maximum")
            if minimum is not None and number < minimum:
                number = minimum
            if maximum is not None and number > maximum:
                number = maximum
            return str(number)
        if kind == "float":
            try:
                number = float(target)
            except ValueError:
                raise ValidationError("setting %s/%s requires a number" % (namespace, key))
            number = max(0.0, min(10.0, number))
            return str(number)
        if kind == "enum":
            allowed = spec.get("allowed", [])
            if target not in allowed:
                raise ValidationError("setting %s/%s must be one of %s" % (namespace, key, ", ".join(allowed)))
            return target
        if not SAFE_VALUE_RE.match(target):
            raise ValidationError("unsafe setting value for %s/%s" % (namespace, key))
        return target

    def preview(self) -> Dict[str, Any]:
        disable_plan: List[Dict[str, Any]] = []
        if self.options.do_disable:
            allowed_risk = PROFILE_RISK.get(self.options.profile, "safe")
            selected = set(profile_packages(self.vendor, self.options.profile, self.options.extra_profiles))
            for package in sorted(selected):
                if package in self.disabled_packages:
                    continue
                if is_critical_package(package, self.critical):
                    continue
                if self.system_packages and package not in self.system_packages and not self.options.allow_user_apps:
                    continue
                tier_label, risk = package_tier_risk(package, self.vendor, self.options.extra_profiles)
                if RISK_ORDER.get(risk, 1) > RISK_ORDER.get(allowed_risk, 0):
                    continue
                disable_plan.append({"package": package, "risk": risk, "tiers": tier_label, "system": package in self.system_packages})
        settings_plan: List[Dict[str, Any]] = []
        if self.options.do_settings and self.caps.get("settings"):
            current_settings = self.profile.get("settings", {})
            for (namespace, key), spec in SETTINGS_SPEC.items():
                min_sdk = spec.get("min_sdk", 0)
                if self.sdk and min_sdk and self.sdk < min_sdk:
                    continue
                target = self._setting_target(namespace, key)
                if target is None:
                    continue
                current = current_settings.get(namespace + "." + key)
                if normalize_setting(current) == normalize_setting(target):
                    continue
                if (namespace, key) == ("system", "screen_off_timeout"):
                    current_int = safe_int(current)
                    if current_int is None or current_int <= int(target):
                        continue
                settings_plan.append({"namespace": namespace, "key": key, "current": current, "target": target, "risk": spec.get("risk", "safe")})
        doze_plan: List[str] = []
        if self.options.do_doze_cleanup and self.caps.get("deviceidle"):
            disabled = set(self.disabled_packages)
            for package in self.profile.get("doze", {}).get("whitelist", []):
                if is_critical_package(package, self.critical) or is_communication_package(package):
                    continue
                if package in disabled or is_telemetry_package(package):
                    doze_plan.append(package)
        return {
            "profile": self.options.profile,
            "dry_run": self.options.dry_run,
            "packages": disable_plan,
            "settings": settings_plan,
            "doze": sorted(set(doze_plan)),
            "cache_trim": bool(self.options.do_cache_trim),
            "cache_size": self.options.cache_size,
            "private_dns": {"mode": self.options.private_dns_mode, "host": self.options.private_dns_host} if self.options.private_dns_mode else None,
            "restrict_unused": bool(self.options.restrict_unused),
            "compile": self.options.compile_mode,
            "dexopt": bool(self.options.dexopt),
        }

    def print_plan(self, plan: Dict[str, Any]) -> None:
        mode = "DRY-RUN" if plan.get("dry_run") else "APPLY"
        print("%s%s (%s)%s" % (_COLORS.bold, mode, plan.get("profile"), _COLORS.reset))
        print("  packages to disable: %d" % len(plan.get("packages", [])))
        for item in plan.get("packages", [])[:12]:
            print("    - %s (%s)" % (item["package"], item["risk"]))
        if len(plan.get("packages", [])) > 12:
            print("    ... and %d more" % (len(plan["packages"]) - 12))
        print("  settings to change: %d" % len(plan.get("settings", [])))
        for item in plan.get("settings", []):
            print("    - %s/%s: %s -> %s" % (item["namespace"], item["key"], item["current"], item["target"]))
        if plan.get("doze"):
            print("  doze whitelist entries to remove: %d" % len(plan["doze"]))
        if plan.get("private_dns"):
            print("  private DNS: %s %s" % (plan["private_dns"].get("mode"), plan["private_dns"].get("host") or ""))
        if plan.get("cache_trim"):
            print("  cache trim: up to %s" % plan.get("cache_size"))
        if plan.get("restrict_unused"):
            print("  restrict unused third-party apps: yes")
        if plan.get("compile"):
            print("  compile launcher/keyboard: %s" % plan.get("compile"))
        if plan.get("dexopt"):
            print("  background dexopt job: yes")

    # -- settings ----------------------------------------------------------
    def apply_settings(self) -> None:
        summary: Dict[str, Any] = {"changed": [], "skipped": [], "failed": []}
        self.summary["settings"] = summary
        if not self.options.do_settings:
            return
        if not self.caps.get("settings"):
            self.warnings.append("settings command unavailable; skipped settings changes")
            return
        for (namespace, key), spec in SETTINGS_SPEC.items():
            min_sdk = spec.get("min_sdk", 0)
            if self.sdk and min_sdk and self.sdk < min_sdk:
                summary["skipped"].append({"key": namespace + "/" + key, "reason": "requires API %s" % min_sdk})
                continue
            target = self._setting_target(namespace, key)
            if target is None:
                continue
            target = self._validate_setting_target(namespace, key, target)
            current = self.client.settings_get(namespace, key)
            if (namespace, key) == ("system", "screen_off_timeout"):
                current_int = safe_int(current)
                if current_int is None or current_int <= int(target):
                    summary["skipped"].append({"key": namespace + "/" + key, "reason": "current value is already at or below target", "current": current})
                    continue
            if normalize_setting(current) == normalize_setting(target):
                summary["skipped"].append({"key": namespace + "/" + key, "reason": "already set", "current": current})
                continue
            if self.options.dry_run:
                summary["changed"].append({"key": namespace + "/" + key, "current": current, "target": target, "result": "planned"})
                self.journal.add("setting", namespace=namespace, key=key, before=current, after=target, result="planned")
                continue
            result = self.client.settings_put(namespace, key, target)
            time.sleep(0.1)
            after = self.client.settings_get(namespace, key)
            if after == target or normalize_setting(after) == normalize_setting(target):
                summary["changed"].append({"key": namespace + "/" + key, "current": current, "target": target, "result": "set"})
                self.journal.add("setting", namespace=namespace, key=key, before=current, after=after or target, result="set")
                self._log("%s/%s: %s -> %s" % (namespace, key, current, after or target))
            else:
                summary["failed"].append({"key": namespace + "/" + key, "current": current, "target": target, "detail": result.summary(200), "after": after})
                self.journal.add("setting", namespace=namespace, key=key, before=current, after=after, result="failed")
                self.warnings.append("could not set %s/%s (shell lacks permission or key is read-only)" % (namespace, key))
        self._apply_private_dns(summary)

    def _apply_private_dns(self, summary: Dict[str, Any]) -> None:
        mode = self.options.private_dns_mode
        if not mode:
            return
        mode_ns, mode_key = PRIVATE_DNS_SPEC["mode"]
        host_ns, host_key = PRIVATE_DNS_SPEC["hostname"]
        old_mode = self.client.settings_get(mode_ns, mode_key)
        if self.options.dry_run:
            summary["changed"].append({"key": "%s/%s" % (mode_ns, mode_key), "current": old_mode, "target": mode, "result": "planned"})
            self.journal.add("setting", namespace=mode_ns, key=mode_key, before=old_mode, after=mode, result="planned")
            if mode == "hostname":
                old_host = self.client.settings_get(host_ns, host_key)
                self.journal.add("setting", namespace=host_ns, key=host_key, before=old_host, after=self.options.private_dns_host, result="planned")
            return
        result = self.client.settings_put(mode_ns, mode_key, mode)
        after = self.client.settings_get(mode_ns, mode_key)
        if after == mode:
            summary["changed"].append({"key": "%s/%s" % (mode_ns, mode_key), "current": old_mode, "target": mode, "result": "set"})
            self.journal.add("setting", namespace=mode_ns, key=mode_key, before=old_mode, after=after, result="set")
        else:
            summary["failed"].append({"key": "%s/%s" % (mode_ns, mode_key), "current": old_mode, "target": mode, "detail": result.summary(200), "after": after})
        old_host = self.client.settings_get(host_ns, host_key)
        if mode == "hostname" and self.options.private_dns_host:
            self.client.settings_put(host_ns, host_key, self.options.private_dns_host)
            new_host = self.client.settings_get(host_ns, host_key)
            if new_host == self.options.private_dns_host:
                summary["changed"].append({"key": "%s/%s" % (host_ns, host_key), "current": old_host, "target": self.options.private_dns_host, "result": "set"})
                self.journal.add("setting", namespace=host_ns, key=host_key, before=old_host, after=new_host, result="set")
            else:
                summary["failed"].append({"key": "%s/%s" % (host_ns, host_key), "current": old_host, "target": self.options.private_dns_host, "detail": "verification failed", "after": new_host})
        elif mode in ("off", "opportunistic") and old_host is not None:
            self.client.settings_delete(host_ns, host_key)
            summary["changed"].append({"key": "%s/%s" % (host_ns, host_key), "current": old_host, "target": None, "result": "deleted"})
            self.journal.add("setting", namespace=host_ns, key=host_key, before=old_host, after=None, result="deleted")

    # -- packages ----------------------------------------------------------
    def apply_packages(self) -> None:
        summary: Dict[str, Any] = {
            "disabled": [], "protected": [], "suspended": [],
            "skipped": [], "failed": [], "already_disabled": [],
        }
        self.summary["packages"] = summary
        if not self.options.do_disable:
            return
        allowed_risk = PROFILE_RISK.get(self.options.profile, "safe")
        selected = profile_packages(self.vendor, self.options.profile, self.options.extra_profiles)
        for package in selected:
            if package in self.disabled_packages:
                summary["already_disabled"].append(package)
                continue
            if is_critical_package(package, self.critical):
                summary["skipped"].append({"package": package, "reason": "critical package"})
                continue
            state = self.client.app_state(package)
            if not state.installed:
                summary["skipped"].append({"package": package, "reason": "not installed"})
                continue
            if state.disabled:
                summary["already_disabled"].append(package)
                continue
            if state.suspended:
                summary["already_disabled"].append(package)
                continue
            if not state.is_system and not self.options.allow_user_apps:
                summary["skipped"].append({"package": package, "reason": "third-party app (use --allow-user-apps to include)"})
                continue
            tier_label, risk = package_tier_risk(package, self.vendor, self.options.extra_profiles)
            if RISK_ORDER.get(risk, 1) > RISK_ORDER.get(allowed_risk, 0):
                summary["skipped"].append({"package": package, "reason": "risk %s exceeds %s profile" % (risk, self.options.profile)})
                continue
            if self.options.dry_run:
                summary["disabled"].append({"package": package, "result": "planned", "risk": risk, "tiers": tier_label})
                self.journal.add("package", name=package, before=state.to_dict(), after=None, result="planned", reason="profile package")
                continue
            result = self.client.disable_package(package, state)
            if result.get("result") == "disabled":
                summary["disabled"].append({"package": package, "result": "disabled", "risk": risk, "tiers": tier_label})
                self.disabled_packages.add(package)
                self.journal.add("package", name=package, before=result.get("before"), after=result.get("after"), result="disabled", reason="profile package")
                self._log("disabled %s" % package)
                continue
            if result.get("result") == "already-disabled":
                summary["already_disabled"].append(package)
                continue
            if result.get("result") == "protected":
                summary["protected"].append(package)
                self.journal.add("package", name=package, before=result.get("before"), after=result.get("after"), result="protected", reason="ROM refused disable-user")
                self._log("protected by ROM: %s" % package)
                self._protected_fallback(package, summary)
                continue
            summary["failed"].append({"package": package, "detail": result.get("detail")})
            self.journal.add("package", name=package, before=result.get("before"), after=result.get("after"), result="failed", reason=result.get("detail") or "disable failed")

    def _protected_fallback(self, package: str, summary: Dict[str, Any]) -> None:
        # appops writes are often blocked to the shell UID.  Suspension is the
        # only reliable way to neutralise a protected telemetry service without
        # root; only use it for telemetry-like packages, never for UI features.
        can_suspend = bool(self.caps.get("suspend")) and self.sdk >= 24 and is_telemetry_package(package)
        if can_suspend:
            if self.options.dry_run:
                summary["suspended"].append({"package": package, "result": "planned"})
                self.journal.add("package", name=package, before=None, after=None, result="planned-suspend", reason="protected telemetry fallback")
            else:
                result = self.client.suspend_package(package)
                if result.get("ok"):
                    summary["suspended"].append({"package": package, "result": result.get("result")})
                    self.disabled_packages.add(package)
                    self.journal.add("package", name=package, before=result.get("before"), after=result.get("after"), result="suspended", reason="protected telemetry fallback")
                    self._log("suspended protected telemetry package: %s" % package)
                else:
                    self.warnings.append("could not suspend protected telemetry package %s" % package)
        if self.options.dry_run:
            summary["skipped"].append({"package": package, "reason": "would force-stop after protected disable"})
        else:
            self.client.force_stop(package)

    # -- doze --------------------------------------------------------------
    def cleanup_doze(self) -> None:
        summary: Dict[str, Any] = {"removed": [], "failed": [], "skipped": []}
        self.summary["doze"] = summary
        if not self.options.do_doze_cleanup:
            return
        if not self.caps.get("deviceidle"):
            summary["skipped"].append("deviceidle is unavailable on this Android version")
            return
        whitelist = set(self.profile.get("doze", {}).get("whitelist", []))
        disabled = set(self.disabled_packages)
        targets: List[str] = []
        for package in sorted(whitelist):
            if is_critical_package(package, self.critical) or is_communication_package(package):
                summary["skipped"].append(package)
                continue
            if package in disabled or is_telemetry_package(package):
                targets.append(package)
        for package in targets:
            if self.options.dry_run:
                summary["removed"].append({"package": package, "result": "planned"})
                self.journal.add("doze", name=package, action="remove", result="planned")
                continue
            result = self.client.doze_whitelist_remove(package)
            if result.ok:
                summary["removed"].append({"package": package, "result": "removed"})
                self.journal.add("doze", name=package, action="remove", result="removed")
            else:
                summary["failed"].append({"package": package, "detail": result.summary(200)})
        if targets and not self.options.dry_run:
            remaining = set(self.client.get_doze_whitelist())
            failed_packages: Set[str] = set()
            for item in list(summary["removed"]):
                if item["package"] in remaining:
                    summary["removed"].remove(item)
                    summary["failed"].append({"package": item["package"], "detail": "still whitelisted after removal"})
                    failed_packages.add(item["package"])
            for entry in self.journal.entries:
                if entry.get("type") == "doze" and entry.get("name") in failed_packages and entry.get("result") == "removed":
                    entry["result"] = "failed"
                    entry["detail"] = "still whitelisted after removal (system whitelist may be protected)"

    # -- cache -------------------------------------------------------------
    def trim_caches(self) -> None:
        summary: Dict[str, Any] = {"before": None, "after": None, "freed_bytes": None, "size": self.options.cache_size, "result": "skipped"}
        self.summary["cache"] = summary
        if not self.options.do_cache_trim:
            return
        before = self.client.get_storage()
        summary["before"] = before
        if self.options.dry_run:
            summary["result"] = "planned"
            self.journal.add("cache", action="trim", size=self.options.cache_size, before=before, result="planned")
            return
        result = self.client.trim_caches(self.options.cache_size)
        time.sleep(1.0)
        after = self.client.get_storage()
        summary["after"] = after
        if result.ok:
            before_available = before.get("available") or 0
            after_available = after.get("available") or 0
            freed = max(0, after_available - before_available)
            summary["freed_bytes"] = freed
            summary["result"] = "trimmed"
            self.journal.add("cache", action="trim", size=self.options.cache_size, before=before, after=after, freed_bytes=freed, result="trimmed")
            self._log("cache trim requested; visible free space increased by %s" % human_bytes(freed))
        else:
            summary["result"] = "failed"
            summary["detail"] = result.summary(300)
            self.journal.add("cache", action="trim", size=self.options.cache_size, before=before, after=after, result="failed")
            self.warnings.append("pm trim-caches failed on this ROM: %s" % result.summary(200))

    # -- optional work ------------------------------------------------------
    def run_optional(self) -> None:
        summary: Dict[str, Any] = {"compile": [], "dexopt": None, "unused": []}
        self.summary["optional"] = summary
        if self.options.compile_mode:
            if not self.caps.get("compile"):
                self.warnings.append("package compilation is unavailable on this ROM")
            else:
                defaults = self.profile.get("defaults", {})
                candidates: List[str] = []
                for key in ("launcher", "ime"):
                    package = package_from_component(defaults.get(key))
                    if package and package not in candidates:
                        candidates.append(package)
                for package in candidates:
                    state = self.client.app_state(package)
                    if not state.installed or state.disabled:
                        continue
                    if self.options.dry_run:
                        summary["compile"].append({"package": package, "mode": self.options.compile_mode, "result": "planned"})
                        self.journal.add("compile", name=package, mode=self.options.compile_mode, result="planned")
                        continue
                    result = self.client.compile_package(package, self.options.compile_mode)
                    if result.ok:
                        summary["compile"].append({"package": package, "mode": self.options.compile_mode, "result": "compiled"})
                        self.journal.add("compile", name=package, mode=self.options.compile_mode, result="compiled")
                    else:
                        summary["compile"].append({"package": package, "mode": self.options.compile_mode, "result": "failed", "detail": result.summary(200)})
        if self.options.dexopt:
            if not self.caps.get("cmd") and not self.caps.get("compile"):
                self.warnings.append("background dexopt is unavailable on this ROM")
            elif self.options.dry_run:
                summary["dexopt"] = {"result": "planned"}
                self.journal.add("dexopt", result="planned")
            else:
                result = self.client.bg_dexopt()
                summary["dexopt"] = {"result": "started" if result.ok else "failed", "detail": result.summary(200)}
                self.journal.add("dexopt", result="started" if result.ok else "failed")
        if self.options.restrict_unused:
            if not self.caps.get("standby"):
                self.warnings.append("standby buckets are unavailable on this Android version")
            else:
                usage = self.profile.get("usage", {})
                last_used = usage.get("last_used", {}) if isinstance(usage, dict) else {}
                third = set(self.client._third_party_packages or []) if self.client._third_party_packages is not None else set()
                for package in sorted(third):
                    if is_critical_package(package, self.critical) or is_communication_package(package):
                        continue
                    if package in last_used:
                        continue
                    if self.options.dry_run:
                        summary["unused"].append({"package": package, "result": "planned", "bucket": "rare"})
                        self.journal.add("standby", name=package, bucket="rare", before=None, result="planned")
                        continue
                    result = self.client.set_standby_bucket(package, "rare")
                    if result.get("ok"):
                        summary["unused"].append({"package": package, "result": "restricted", "bucket": "rare", "before": result.get("before"), "after": result.get("after")})
                        self.journal.add("standby", name=package, bucket="rare", before=result.get("before"), after=result.get("after"), result="restricted")
                    else:
                        summary["unused"].append({"package": package, "result": "ineffective", "bucket": "rare", "before": result.get("before"), "after": result.get("after")})
        if summary["unused"]:
            self.warnings.append("unused-app standby restrictions use a 24-hour usage window; review before relying on them")

    # -- post-run safety ----------------------------------------------------
    def verify_critical(self) -> Dict[str, Any]:
        defaults = self.profile.get("defaults", {}) or {}
        packages: List[str] = []
        for key in ("launcher", "sms", "dialer", "ime"):
            package = package_from_component(defaults.get(key))
            if package:
                packages.append(package)
        packages.extend([
            "com.android.systemui",
            "com.android.settings",
            "com.android.phone",
            "com.google.android.gms",
            "com.android.vending",
        ])
        result: Dict[str, Any] = {}
        failures: List[str] = []
        for package in dedupe(packages):
            state = self.client.app_state(package)
            if not state.installed:
                # AOSP devices may legitimately lack Play services/Play Store.
                result[package] = {"installed": False, "ok": True}
                continue
            ok = not state.disabled and not state.suspended
            result[package] = {"installed": True, "enabled": state.enabled_state, "ok": ok}
            if not ok:
                failures.append(package)
        if failures:
            self.warnings.append("critical package check failed: %s" % ", ".join(failures))
        return {"packages": result, "failures": failures, "ok": not failures}

    # -- execution ----------------------------------------------------------
    def execute(self) -> Dict[str, Any]:
        self.options.validate()
        started = time.monotonic()
        self.summary = {
            "profile": self.options.profile,
            "dry_run": self.options.dry_run,
            "started_at": now_iso(),
            "device": self.profile.get("device", {}),
            "vendor": self.vendor,
            "warnings": self.warnings,
        }
        if self.options.do_settings:
            self.apply_settings()
        if self.options.do_disable:
            self.apply_packages()
        self.cleanup_doze()
        self.trim_caches()
        self.run_optional()
        self.summary["critical_check"] = self.verify_critical()
        self.summary["finished_at"] = now_iso()
        self.summary["duration_sec"] = round(time.monotonic() - started, 2)
        self.summary["warnings"] = dedupe(self.warnings)
        if not self.options.dry_run:
            self.journal.save()
        return self.summary


def summarize_counts(summary: Dict[str, Any]) -> Dict[str, Any]:
    packages = summary.get("packages", {}) or {}
    settings = summary.get("settings", {}) or {}
    cache = summary.get("cache", {}) or {}
    return {
        "disabled": len(packages.get("disabled", [])),
        "protected": len(packages.get("protected", [])),
        "suspended": len(packages.get("suspended", [])),
        "already_disabled": len(packages.get("already_disabled", [])),
        "failed_packages": len(packages.get("failed", [])),
        "settings_changed": len(settings.get("changed", [])),
        "settings_failed": len(settings.get("failed", [])),
        "doze_removed": len((summary.get("doze", {}) or {}).get("removed", [])),
        "doze_failed": len((summary.get("doze", {}) or {}).get("failed", [])),
        "critical_ok": bool((summary.get("critical_check", {}) or {}).get("ok", True)),
        "critical_failures": len((summary.get("critical_check", {}) or {}).get("failures", [])),
        "cache_freed_bytes": cache.get("freed_bytes"),
        "cache_result": cache.get("result"),
    }


def print_run_summary(summary: Dict[str, Any]) -> None:
    counts = summarize_counts(summary)
    mode = "DRY-RUN" if summary.get("dry_run") else "APPLIED"
    print("%s%s: %s%s" % (_COLORS.bold, mode, summary.get("profile"), _COLORS.reset))
    print("  packages disabled: %s   protected: %s   suspended: %s   failed: %s" % (
        counts["disabled"], counts["protected"], counts["suspended"], counts["failed_packages"]))
    print("  settings changed: %s   failed: %s" % (counts["settings_changed"], counts["settings_failed"]))
    print("  doze entries removed: %s   failed: %s" % (counts["doze_removed"], counts["doze_failed"]))
    print("  critical package check: %s%s" % (
        "ok" if counts["critical_ok"] else "FAILED",
        "" if counts["critical_ok"] else " (%s)" % counts["critical_failures"]))
    print("  cache: %s%s" % (
        counts["cache_result"],
        (" (%s freed)" % human_bytes(counts["cache_freed_bytes"])) if counts["cache_freed_bytes"] else ""))
    warnings = summary.get("warnings", [])
    if warnings:
        print("%sWarnings%s" % (_COLORS.bold, _COLORS.reset))
        for warning in warnings[:20]:
            print("  - %s" % warning)
    print("  duration: %ss" % summary.get("duration_sec"))


# ---------------------------------------------------------------------------
# ART / dex2oat batch compiler
# ---------------------------------------------------------------------------

@dataclasses.dataclass
class CompileOptions:
    mode: str = "speed-profile"
    scope: str = "third_party"
    limit: int = 0
    force: bool = False
    full: bool = False
    include: List[str] = dataclasses.field(default_factory=list)
    exclude: List[str] = dataclasses.field(default_factory=list)
    min_battery: int = 25
    max_battery_temp: float = 40.0
    max_thermal_status: int = 2
    charging_only: bool = False
    timeout: int = 300
    max_minutes: float = 0.0
    priority: str = "PRIORITY_BACKGROUND"
    reset: bool = False
    dry_run: bool = False
    yes: bool = False

    def validate(self) -> None:
        if self.mode not in ("speed", "speed-profile", "verify", "quicken"):
            raise ValidationError("compile mode must be speed, speed-profile, verify or quicken")
        if self.scope not in ("third_party", "system", "all"):
            raise ValidationError("scope must be third_party, system or all")
        if self.priority not in ("PRIORITY_BOOT", "PRIORITY_INTERACTIVE_FAST", "PRIORITY_INTERACTIVE", "PRIORITY_BACKGROUND"):
            raise ValidationError("invalid compile priority")
        if not (0 <= self.limit <= 10000):
            raise ValidationError("limit must be between 0 and 10000")
        if not (0 <= self.min_battery <= 100):
            raise ValidationError("min battery must be between 0 and 100")
        if not (20.0 <= self.max_battery_temp <= 60.0):
            raise ValidationError("max battery temperature must be between 20 and 60 C")
        if not (0 <= self.max_thermal_status <= 6):
            raise ValidationError("max thermal status must be between 0 and 6")
        if not (30 <= self.timeout <= 3600):
            raise ValidationError("per-app timeout must be between 30 and 3600 seconds")
        if self.max_minutes < 0:
            raise ValidationError("max minutes must be non-negative")
        for package in list(self.include) + list(self.exclude):
            if not PACKAGE_RE.match(package):
                raise ValidationError("invalid package name in include/exclude list: %s" % package)


class Compiler:
    def __init__(self, client: AdbClient, profile: Dict[str, Any],
                 options: CompileOptions, journal: Journal) -> None:
        self.client = client
        self.profile = profile
        self.options = options
        self.journal = journal
        self.critical = set(profile.get("critical_packages", []))
        self.sdk = int(profile.get("device", {}).get("sdk") or 0)
        self.warnings: List[str] = list(profile.get("warnings", []))

    def check_environment(self) -> Dict[str, Any]:
        battery = self.client.get_battery()
        thermal = self.client.get_thermal()
        issues: List[str] = []
        level = battery.get("level")
        status = battery.get("status")
        temp = battery.get("temperature_c")
        if level is not None and level < self.options.min_battery:
            issues.append("battery %s%% is below the %s%% minimum" % (level, self.options.min_battery))
        if self.options.charging_only and status not in (2, 5):
            issues.append("device is not charging (battery status=%s)" % status)
        if temp is not None and temp > self.options.max_battery_temp:
            issues.append("battery temperature %.1f C exceeds %.1f C" % (temp, self.options.max_battery_temp))
        thermal_status = thermal.get("status")
        if thermal_status is not None and thermal_status > self.options.max_thermal_status:
            issues.append("thermal status %s exceeds %s" % (thermal_status, self.options.max_thermal_status))
        return {"ok": not issues, "issues": issues, "battery": battery, "thermal": thermal}

    def plan(self) -> Dict[str, Any]:
        inventory = self.client.package_inventory()
        state = self.client.get_dexopt_state()
        system = set(inventory.get("system", set()))
        third = set(inventory.get("third_party", set()))
        disabled = set(inventory.get("disabled", set()))
        installed = system | third
        usage = self.profile.get("usage", {}) or {}
        last_used = usage.get("last_used", {}) if isinstance(usage, dict) else {}
        warnings = list(inventory.get("warnings", [])) + list(self.warnings)
        if not state:
            warnings.append("could not read dumpsys package dexopt; compile status is unknown")
        if self.options.reset:
            warnings.append("--reset discards existing AOT compilation; the package is left at verify state")
        if self.options.force and self.options.mode in ("verify", "quicken"):
            warnings.append("--force with %s can downgrade a previously speed/speed-profile app" % self.options.mode)
        if self.options.include:
            candidates = set(self.options.include)
        elif self.options.scope == "third_party":
            candidates = third
        elif self.options.scope == "system":
            candidates = system
        else:
            candidates = installed
        exclude = set(self.options.exclude)
        targets: List[Dict[str, Any]] = []
        skipped: List[Dict[str, Any]] = []
        for package in sorted(candidates):
            if package in exclude:
                skipped.append({"package": package, "reason": "excluded"})
                continue
            if package not in installed:
                skipped.append({"package": package, "reason": "not installed"})
                continue
            if package in disabled:
                skipped.append({"package": package, "reason": "disabled"})
                continue
            if is_critical_package(package, self.critical):
                skipped.append({"package": package, "reason": "critical package"})
                continue
            entry = state.get(package, {}) or {}
            current = entry.get("status")
            if not self.options.reset and not self.options.force and dexopt_at_least(current, self.options.mode):
                skipped.append({"package": package, "reason": "already at least %s" % self.options.mode, "current": current})
                continue
            targets.append({
                "package": package,
                "current_status": current,
                "current_reason": entry.get("reason"),
                "current_path": entry.get("path"),
                "system": package in system,
                "last_used": last_used.get(package),
            })
        targets.sort(key=lambda item: (
            DEXOPT_STATUS_RANK.get(item.get("current_status") or "unknown", 0),
            item.get("package") or "",
        ))
        if self.options.limit:
            targets = targets[: self.options.limit]
        return {
            "mode": self.options.mode,
            "scope": self.options.scope,
            "reset": self.options.reset,
            "full": self.options.full,
            "priority": self.options.priority,
            "targets": targets,
            "skipped": skipped,
            "counts": {
                "targets": len(targets),
                "skipped": len(skipped),
                "already_optimized": sum(1 for item in skipped if "already" in str(item.get("reason"))),
            },
            "status_distribution": self._status_distribution(state, installed),
            "warnings": dedupe(warnings),
        }

    @staticmethod
    def _status_distribution(state: Dict[str, Dict[str, Any]], installed: Set[str]) -> Dict[str, int]:
        counts: Dict[str, int] = {}
        for package in installed:
            status = (state.get(package, {}) or {}).get("status") or "unknown"
            if status == "unknown" and package not in state:
                continue
            counts[status] = counts.get(status, 0) + 1
        return dict(sorted(counts.items(), key=lambda item: (-item[1], item[0])))

    def print_plan(self, plan: Dict[str, Any], environment: Dict[str, Any]) -> None:
        mode = "DRY-RUN" if self.options.dry_run else "APPLY"
        print("%s%s: %s compilation%s" % (_COLORS.bold, mode, plan.get("mode"), _COLORS.reset))
        print("  scope: %s   targets: %s   skipped: %s" % (
            plan.get("scope"), plan.get("counts", {}).get("targets"), plan.get("counts", {}).get("skipped")))
        print("  priority: %s   full: %s   reset: %s" % (
            plan.get("priority"), plan.get("full"), plan.get("reset")))
        print("  status distribution: %s" % compact_json(plan.get("status_distribution", {})))
        for item in plan.get("targets", [])[:20]:
            print("    - %s: %s -> %s" % (item["package"], item.get("current_status") or "unknown", plan.get("mode")))
        if len(plan.get("targets", [])) > 20:
            print("    ... and %d more" % (len(plan["targets"]) - 20))
        print("  battery: %s%%   temp: %s C   thermal: %s" % (
            environment.get("battery", {}).get("level"),
            environment.get("battery", {}).get("temperature_c"),
            environment.get("thermal", {}).get("status")))
        for issue in environment.get("issues", []):
            print("  [!] %s" % issue)
        if self.options.mode == "speed" and not self.options.dry_run:
            print("  [!] full AOT compilation can increase app storage and heat the device")
        if self.options.reset:
            print("  [!] --reset discards existing AOT compilation (leaves verify state)")
        if self.options.force and self.options.mode in ("verify", "quicken"):
            print("  [!] --force with %s can downgrade compiled apps" % self.options.mode)

    def execute(self) -> Dict[str, Any]:
        self.options.validate()
        started = time.monotonic()
        plan = self.plan()
        environment = self.check_environment()
        summary: Dict[str, Any] = {
            "mode": self.options.mode,
            "scope": self.options.scope,
            "dry_run": self.options.dry_run,
            "started_at": now_iso(),
            "plan": plan,
            "environment_before": environment,
            "compiled": [],
            "failed": [],
            "skipped": plan.get("skipped", []),
            "warnings": list(plan.get("warnings", [])),
        }
        if not self.options.dry_run and not environment.get("ok"):
            raise SafetyError("refusing to compile: %s" % "; ".join(environment.get("issues", [])))
        if self.options.dry_run:
            for item in plan.get("targets", []):
                summary["compiled"].append({"package": item["package"], "result": "planned", "before": item.get("current_status")})
                self.journal.add("compile", package=item["package"], mode=self.options.mode, before_status=item.get("current_status"), result="planned")
            summary["finished_at"] = now_iso()
            summary["duration_sec"] = round(time.monotonic() - started, 2)
            return summary
        storage_before = self.client.get_storage()
        timeout_count = 0
        consecutive_failures = 0
        for index, item in enumerate(plan.get("targets", []), start=1):
            if self.options.max_minutes and (time.monotonic() - started) > self.options.max_minutes * 60:
                summary["stop_reason"] = "time-budget"
                summary["warnings"].append("stopped after reaching the %.1f minute budget" % self.options.max_minutes)
                break
            if index == 1 or index % 4 == 0:
                environment = self.check_environment()
                if not environment.get("ok"):
                    summary["stop_reason"] = "environment"
                    summary["warnings"].append("stopped for safety: %s" % "; ".join(environment.get("issues", [])))
                    break
            package = item["package"]
            before_status = item.get("current_status")
            log_info("[%d/%d] compiling %s (%s -> %s)" % (index, len(plan["targets"]), package, before_status or "unknown", self.options.mode))
            result = self.client.compile_package_advanced(
                package,
                mode=self.options.mode,
                priority=self.options.priority,
                full=self.options.full,
                reset=self.options.reset,
                timeout=self.options.timeout,
            )
            after = self.client.get_package_dexopt_status(package)
            after_status = (after or {}).get("status")
            combined = result.combined.lower()
            success = result.ok and "error" not in combined and "failure" not in combined
            if result.timed_out:
                success = False
                timeout_count += 1
            if success:
                consecutive_failures = 0
                fallback = (self.options.mode == "speed-profile" and after_status not in (None, "speed-profile", "speed"))
                summary["compiled"].append({
                    "package": package,
                    "result": "compiled",
                    "before": before_status,
                    "after": after_status,
                    "fallback": fallback,
                })
                self.journal.add("compile", package=package, mode=self.options.mode,
                                 before_status=before_status, after_status=after_status,
                                 result="compiled")
                if fallback:
                    summary["warnings"].append("%s compiled, but ART fell back to %s (no usable profile)" % (package, after_status))
            else:
                consecutive_failures += 1
                summary["failed"].append({
                    "package": package,
                    "result": "timeout" if result.timed_out else "failed",
                    "before": before_status,
                    "after": after_status,
                    "detail": result.summary(400),
                })
                self.journal.add("compile", package=package, mode=self.options.mode,
                                 before_status=before_status, after_status=after_status,
                                 result="failed")
                if consecutive_failures >= 3:
                    summary["stop_reason"] = "repeated-failures"
                    summary["warnings"].append("stopped after three consecutive compile failures")
                    break
                if timeout_count >= 2:
                    summary["stop_reason"] = "timeouts"
                    summary["warnings"].append("stopped after two timeouts")
                    break
            time.sleep(0.2)
        summary["environment_after"] = self.check_environment()
        summary["storage_before"] = storage_before
        summary["storage_after"] = self.client.get_storage()
        summary["finished_at"] = now_iso()
        summary["duration_sec"] = round(time.monotonic() - started, 2)
        summary["warnings"] = dedupe(summary["warnings"])
        self.journal.save()
        return summary


def print_compile_summary(summary: Dict[str, Any]) -> None:
    compiled = summary.get("compiled", [])
    failed = summary.get("failed", [])
    print("%s%s: %s%s" % (_COLORS.bold, "DRY-RUN" if summary.get("dry_run") else "COMPILED", summary.get("mode"), _COLORS.reset))
    print("  %s: %s   failed: %s   skipped: %s" % (
        "planned" if summary.get("dry_run") else "compiled",
        len(compiled), len(failed), len(summary.get("skipped", []))))
    if summary.get("stop_reason"):
        print("  stop reason: %s" % summary["stop_reason"])
    before = summary.get("storage_before", {}).get("available")
    after = summary.get("storage_after", {}).get("available")
    if before is not None and after is not None:
        print("  visible storage change: %s" % human_bytes(after - before))
    for warning in summary.get("warnings", [])[:15]:
        print("  [!] %s" % warning)
    print("  duration: %ss" % summary.get("duration_sec"))


# ---------------------------------------------------------------------------
# Kernel audit / root-only governor tuner
# ---------------------------------------------------------------------------

KERNEL_PROFILES: Dict[str, Dict[str, List[str]]] = {
    "performance": {
        "cpu": ["performance"],
        "gpu": ["performance"],
    },
    "balanced": {
        "cpu": ["schedutil", "walt", "interactive"],
        "gpu": ["msm-adreno-tz", "simple_ondemand", "msm-adreno"],
    },
    "battery": {
        "cpu": ["powersave", "schedutil", "walt"],
        "gpu": ["powersave", "msm-adreno-tz"],
    },
}


class KernelTuner:
    """Read-only kernel audit plus tightly allowlisted governor writes.

    True kernel tuning on production Android requires root and usually an
    unlocked bootloader.  On a locked, non-root device the shell UID cannot
    write these files at all.  This class therefore refuses writes unless
    root is confirmed and the caller explicitly passes --allow-kernel.
    """

    def __init__(self, client: AdbClient, profile: Dict[str, Any], journal: Journal) -> None:
        self.client = client
        self.profile = profile
        self.journal = journal

    @staticmethod
    def _split_values(value: Optional[str]) -> List[str]:
        if not value:
            return []
        return [item for item in re.split(r"[\s,]+", value.strip()) if item]

    def _writable(self, path: str, root: bool) -> bool:
        command = "[ -w %s ] && echo yes" % shlex.quote(path)
        result = self.client.root_shell(command, timeout=10) if root else self.client.shell(command, timeout=10)
        return result.ok and "yes" in result.stdout

    def audit(self) -> Dict[str, Any]:
        root_mode = self.client.root_mode()
        root = root_mode is not None
        props = self.client.get_props()
        bootloader_locked = props.get("ro.boot.flash.locked")
        verified_boot = props.get("ro.boot.verifiedbootstate")
        selinux = self.client.shell("getenforce", timeout=10).stdout.strip() or None
        kernel = self.client.shell("uname -a", timeout=10).stdout.strip() or None
        audit: Dict[str, Any] = {
            "root": root,
            "root_mode": root_mode,
            "bootloader_locked": bootloader_locked,
            "verified_boot": verified_boot,
            "selinux": selinux,
            "kernel": kernel,
            "cpu": {},
            "gpu": {},
            "io": {},
            "vm": {},
            "warnings": [],
        }
        cpu_dirs = self.client.shell("ls -d /sys/devices/system/cpu/cpu[0-9]*/cpufreq 2>/dev/null", timeout=15)
        for directory in [line.strip() for line in cpu_dirs.stdout.splitlines() if line.strip()]:
            governor_path = directory.rstrip("/") + "/scaling_governor"
            available_path = directory.rstrip("/") + "/scaling_available_governors"
            current = self.client.kernel_read(governor_path, root=root)
            available = self._split_values(self.client.kernel_read(available_path, root=root))
            audit["cpu"][directory] = {
                "governor": current,
                "available": available,
                "writable": self._writable(governor_path, root),
            }
        gpu_dirs = self.client.shell("ls -d /sys/class/kgsl/kgsl-3d0/devfreq /sys/class/devfreq/* 2>/dev/null", timeout=15)
        gpu_directories = [line.strip() for line in gpu_dirs.stdout.splitlines() if line.strip()]
        for directory in gpu_directories[:5]:
            governor_path = directory.rstrip("/") + "/governor"
            available_path = directory.rstrip("/") + "/available_governors"
            current = self.client.kernel_read(governor_path, root=root)
            available = self._split_values(self.client.kernel_read(available_path, root=root))
            audit["gpu"][directory] = {
                "governor": current,
                "available": available,
                "writable": self._writable(governor_path, root),
            }
        block_devices = self.client.shell("ls /sys/block 2>/dev/null", timeout=15)
        devices = [line.strip() for line in block_devices.stdout.splitlines() if line.strip()]
        physical = [device for device in devices if not device.startswith(("dm-", "loop", "ram"))]
        for device in (physical or devices)[:12]:
            scheduler_path = "/sys/block/%s/queue/scheduler" % device
            current = self.client.kernel_read(scheduler_path, root=root)
            audit["io"][device] = {
                "scheduler": current,
                "writable": self._writable(scheduler_path, root),
            }
        for key in ("swappiness", "vfs_cache_pressure", "dirty_ratio", "dirty_background_ratio"):
            path = "/proc/sys/vm/%s" % key
            audit["vm"][key] = {
                "value": self.client.kernel_read(path, root=root),
                "writable": self._writable(path, root),
            }
        if not root:
            audit["warnings"].append("root is not available; kernel writes are impossible on this device")
        if bootloader_locked == "1":
            audit["warnings"].append("bootloader is locked; kernel/ROM modifications would require an unlock")
        if selinux == "Enforcing":
            audit["warnings"].append("SELinux is enforcing; many sysfs writes are blocked even for shell/root contexts")
        audit["warnings"].append("VM and I/O tunables are audited only; they are vendor-specific and are not changed automatically")
        return audit

    def plan(self, profile: str) -> Dict[str, Any]:
        root = self.client.root_available()
        targets = KERNEL_PROFILES[profile]
        plan: List[Dict[str, Any]] = []
        skipped: List[Dict[str, Any]] = []
        cpu_dirs = self.client.shell("ls -d /sys/devices/system/cpu/cpu[0-9]*/cpufreq 2>/dev/null", timeout=15)
        for directory in [line.strip() for line in cpu_dirs.stdout.splitlines() if line.strip()]:
            governor_path = directory.rstrip("/") + "/scaling_governor"
            available = self._split_values(self.client.kernel_read(directory.rstrip("/") + "/scaling_available_governors", root=root))
            current = self.client.kernel_read(governor_path, root=root)
            chosen = next((value for value in targets["cpu"] if value in available), None)
            if not chosen:
                skipped.append({"path": governor_path, "reason": "no profile governor available"})
                continue
            if current == chosen:
                skipped.append({"path": governor_path, "reason": "already %s" % chosen})
                continue
            plan.append({"kind": "cpu", "path": governor_path, "before": current, "after": chosen})
        gpu_dirs = self.client.shell("ls -d /sys/class/kgsl/kgsl-3d0/devfreq /sys/class/devfreq/* 2>/dev/null", timeout=15)
        gpu_directories = [line.strip() for line in gpu_dirs.stdout.splitlines() if line.strip()]
        for directory in gpu_directories[:5]:
            governor_path = directory.rstrip("/") + "/governor"
            available = self._split_values(self.client.kernel_read(directory.rstrip("/") + "/available_governors", root=root))
            current = self.client.kernel_read(governor_path, root=root)
            chosen = next((value for value in targets["gpu"] if value in available), None)
            if not chosen:
                skipped.append({"path": governor_path, "reason": "no profile governor available"})
                continue
            if current == chosen:
                skipped.append({"path": governor_path, "reason": "already %s" % chosen})
                continue
            plan.append({"kind": "gpu", "path": governor_path, "before": current, "after": chosen})
        return {"profile": profile, "root": root, "targets": plan, "skipped": skipped}

    def apply(self, profile: str, dry_run: bool = False) -> Dict[str, Any]:
        if not self.client.root_available():
            raise SafetyError("kernel writes require root; this device has no root/su")
        plan = self.plan(profile)
        summary: Dict[str, Any] = {
            "profile": profile,
            "dry_run": dry_run,
            "applied": [],
            "failed": [],
            "skipped": plan.get("skipped", []),
            "warnings": ["kernel governor changes can affect heat, battery and stability"],
        }
        for target in plan.get("targets", []):
            if dry_run:
                summary["applied"].append({"path": target["path"], "before": target.get("before"), "after": target["after"], "result": "planned"})
                self.journal.add("kernel", path=target["path"], before=target.get("before"), after=target["after"], result="planned")
                continue
            result = self.client.kernel_write(target["path"], target["after"])
            if result.get("ok"):
                summary["applied"].append({"path": target["path"], "before": result.get("before"), "after": result.get("after"), "result": "set"})
                self.journal.add("kernel", path=target["path"], before=result.get("before"), after=result.get("after"), result="set")
                log_ok("kernel %s: %s -> %s" % (target["path"], result.get("before"), result.get("after")))
            else:
                summary["failed"].append({"path": target["path"], "before": result.get("before"), "after": result.get("after"), "error": result.get("error") or result.get("detail")})
                self.journal.add("kernel", path=target["path"], before=result.get("before"), after=result.get("after"), result="failed")
        if not dry_run:
            self.journal.save()
        summary["finished_at"] = now_iso()
        return summary


def print_kernel_audit(audit: Dict[str, Any]) -> None:
    print("%sKernel audit%s" % (_COLORS.bold, _COLORS.reset))
    print("  root: %s (%s)   bootloader locked: %s   verified boot: %s" % (
        audit.get("root"), audit.get("root_mode"), audit.get("bootloader_locked"), audit.get("verified_boot")))
    print("  SELinux: %s" % audit.get("selinux"))
    print("  kernel: %s" % audit.get("kernel"))
    cpu = audit.get("cpu", {})
    if cpu:
        print("  CPU governors:")
        for directory, item in list(cpu.items())[:12]:
            print("    %s: %s  available=%s  writable=%s" % (
                directory.split("/")[-2] if "/" in directory else directory,
                item.get("governor"), ",".join(item.get("available", [])), item.get("writable")))
    gpu = audit.get("gpu", {})
    if gpu:
        print("  GPU governors:")
        for directory, item in list(gpu.items())[:6]:
            print("    %s: %s  available=%s  writable=%s" % (
                directory, item.get("governor"), ",".join(item.get("available", [])), item.get("writable")))
    io = audit.get("io", {})
    if io:
        print("  I/O schedulers (read-only):")
        for device, item in list(io.items())[:8]:
            print("    %s: %s" % (device, item.get("scheduler")))
    vm = audit.get("vm", {})
    if vm:
        print("  VM tunables (read-only):")
        for key, item in vm.items():
            print("    %s: %s" % (key, item.get("value")))
    for warning in audit.get("warnings", []):
        print("  [!] %s" % warning)


# ---------------------------------------------------------------------------
# Responsiveness / performance boost
# ---------------------------------------------------------------------------

def default_cached_processes(total_bytes: Optional[int], profile: str = "fast") -> int:
    gib = (float(total_bytes) / (1024.0 ** 3)) if total_bytes else 8.0
    if gib >= 10.0:
        return 64 if profile == "max" else 48
    if gib >= 7.0:
        return 48 if profile == "max" else 32
    if gib >= 5.0:
        return 32 if profile == "max" else 24
    return 24 if profile == "max" else 16


@dataclasses.dataclass
class BoostOptions:
    profile: str = "fast"
    max_cached_processes: Optional[int] = None
    freezer_off: bool = True
    standby_off: bool = True
    adaptive_saver_off: bool = True
    fstrim: bool = False
    dry_run: bool = False
    yes: bool = False

    def validate(self) -> None:
        if self.profile not in ("fast", "max"):
            raise ValidationError("boost profile must be fast or max")
        if self.max_cached_processes is not None and not (16 <= self.max_cached_processes <= 256):
            raise ValidationError("max cached processes must be between 16 and 256")


class BoostTuner:
    """Trade battery for responsiveness using real framework switches.

    This deliberately does not fake thermal status, disable thermal throttling,
    force GPU governors, or claim a refresh-rate change the shell cannot make.
    """

    def __init__(self, client: AdbClient, profile: Dict[str, Any],
                 options: BoostOptions, journal: Journal) -> None:
        self.client = client
        self.profile = profile
        self.options = options
        self.journal = journal
        self.memory = profile.get("memory", {}) or {}

    def _setting_targets(self) -> List[Tuple[str, str, str]]:
        targets: List[Tuple[str, str, str]] = []
        if self.options.freezer_off:
            targets.append(("global", "cached_apps_freezer", "disabled"))
        if self.options.standby_off:
            targets.append(("global", "app_standby_enabled", "0"))
        targets.extend([
            ("global", "low_power", "0"),
            ("global", "window_animation_scale", "0.0"),
            ("global", "transition_animation_scale", "0.0"),
            ("global", "animator_duration_scale", "0.0"),
            ("global", "wifi_scan_always_enabled", "0"),
            ("global", "mobile_data_always_active", "0"),
            ("secure", "adaptive_sleep", "0"),
            ("secure", "long_press_timeout", "300"),
        ])
        return targets

    def plan(self) -> Dict[str, Any]:
        settings_plan: List[Dict[str, Any]] = []
        for namespace, key, target in self._setting_targets():
            current = self.client.settings_get(namespace, key)
            if normalize_setting(current) == normalize_setting(target):
                continue
            settings_plan.append({"namespace": namespace, "key": key, "current": current, "target": target})
        cached_target = self.options.max_cached_processes
        if cached_target is None:
            cached_target = default_cached_processes(self.memory.get("total"), self.options.profile)
        cached_before = self.client.device_config_get("activity_manager", "max_cached_processes")
        device_config_plan = []
        if str(cached_target) != (cached_before or ""):
            device_config_plan.append({"namespace": "activity_manager", "key": "max_cached_processes", "current": cached_before, "target": str(cached_target)})
        adaptive_before = self.client.adaptive_power_saver_state()
        power_plan = []
        if self.options.adaptive_saver_off and adaptive_before is not False:
            power_plan.append({"action": "disable-adaptive-power-saver", "current": adaptive_before, "target": False})
        return {
            "profile": self.options.profile,
            "settings": settings_plan,
            "device_config": device_config_plan,
            "power": power_plan,
            "fstrim": bool(self.options.fstrim),
            "warnings": [
                "boost trades battery life and heat for responsiveness",
                "thermal throttling is not disabled; that would risk the hardware",
                "GPU governors and kernel tunables require root and are not touched here",
                "the shell UID cannot force the 165 Hz display mode on this OnePlus ROM",
                "run `optimize` again to restore battery-friendly freezer/standby settings",
            ],
        }

    def print_plan(self, plan: Dict[str, Any]) -> None:
        print("%s%s boost%s" % (_COLORS.bold, "DRY-RUN" if self.options.dry_run else "APPLY", _COLORS.reset))
        for item in plan.get("settings", []):
            print("  setting %s/%s: %s -> %s" % (item["namespace"], item["key"], item["current"], item["target"]))
        for item in plan.get("device_config", []):
            print("  device_config %s/%s: %s -> %s" % (item["namespace"], item["key"], item["current"], item["target"]))
        for item in plan.get("power", []):
            print("  power %s: %s -> %s" % (item["action"], item["current"], item["target"]))
        if plan.get("fstrim"):
            print("  fstrim: yes")
        for warning in plan.get("warnings", []):
            print("  [!] %s" % warning)

    def execute(self) -> Dict[str, Any]:
        self.options.validate()
        plan = self.plan()
        summary: Dict[str, Any] = {
            "profile": self.options.profile,
            "dry_run": self.options.dry_run,
            "settings": [],
            "device_config": [],
            "power": [],
            "fstrim": None,
            "warnings": list(plan.get("warnings", [])),
            "started_at": now_iso(),
        }
        for item in plan.get("settings", []):
            namespace, key, target = item["namespace"], item["key"], item["target"]
            current = item.get("current")
            if self.options.dry_run:
                summary["settings"].append({"key": namespace + "/" + key, "current": current, "target": target, "result": "planned"})
                self.journal.add("setting", namespace=namespace, key=key, before=current, after=target, result="planned")
                continue
            result = self.client.settings_put(namespace, key, target)
            after = self.client.settings_get(namespace, key)
            if after == target:
                summary["settings"].append({"key": namespace + "/" + key, "current": current, "target": target, "result": "set"})
                self.journal.add("setting", namespace=namespace, key=key, before=current, after=after, result="set")
            else:
                summary["settings"].append({"key": namespace + "/" + key, "current": current, "target": target, "result": "failed", "after": after, "detail": result.summary(200)})
                summary["warnings"].append("could not set %s/%s" % (namespace, key))
        for item in plan.get("device_config", []):
            namespace, key, target = item["namespace"], item["key"], item["target"]
            current = item.get("current")
            if self.options.dry_run:
                summary["device_config"].append({"key": namespace + "/" + key, "current": current, "target": target, "result": "planned"})
                self.journal.add("device_config", namespace=namespace, key=key, before=current, after=target, result="planned")
                continue
            result = self.client.device_config_put(namespace, key, target)
            after = self.client.device_config_get(namespace, key)
            if after == target:
                summary["device_config"].append({"key": namespace + "/" + key, "current": current, "target": target, "result": "set"})
                self.journal.add("device_config", namespace=namespace, key=key, before=current, after=after, result="set")
            else:
                summary["device_config"].append({"key": namespace + "/" + key, "current": current, "target": target, "result": "failed", "after": after, "detail": result.summary(200)})
                summary["warnings"].append("could not set device_config %s/%s" % (namespace, key))
        for item in plan.get("power", []):
            target = bool(item.get("target"))
            current = item.get("current")
            if self.options.dry_run:
                summary["power"].append({"action": item["action"], "current": current, "target": target, "result": "planned"})
                self.journal.add("power", action=item["action"], before=current, after=target, result="planned")
                continue
            result = self.client.set_adaptive_power_saver(target)
            if result.get("ok"):
                summary["power"].append({"action": item["action"], "current": current, "target": target, "result": "set", "after": result.get("after")})
                self.journal.add("power", action=item["action"], before=current, after=result.get("after"), result="set")
            else:
                summary["power"].append({"action": item["action"], "current": current, "target": target, "result": "failed", "after": result.get("after"), "detail": result.get("detail")})
        if plan.get("fstrim"):
            if self.options.dry_run:
                summary["fstrim"] = {"result": "planned"}
                self.journal.add("fstrim", result="planned")
            else:
                result = self.client.fstrim()
                summary["fstrim"] = {"result": "done" if result.ok else "failed", "detail": result.summary(300)}
                self.journal.add("fstrim", result="done" if result.ok else "failed")
                if not result.ok:
                    summary["warnings"].append("fstrim failed on this ROM")
        summary["finished_at"] = now_iso()
        summary["warnings"] = dedupe(summary["warnings"])
        if not self.options.dry_run:
            self.journal.save()
        return summary


def print_boost_summary(summary: Dict[str, Any]) -> None:
    print("%s%s boost%s" % (_COLORS.bold, "DRY-RUN" if summary.get("dry_run") else "APPLIED", _COLORS.reset))
    print("  settings: %s   device_config: %s   power: %s   fstrim: %s" % (
        len(summary.get("settings", [])), len(summary.get("device_config", [])),
        len(summary.get("power", [])), (summary.get("fstrim") or {}).get("result")))
    for warning in summary.get("warnings", []):
        print("  [!] %s" % warning)


# ---------------------------------------------------------------------------
# LLM providers
# ---------------------------------------------------------------------------

def _api_url(base: str, suffix: str) -> str:
    base = (base or "").rstrip("/")
    suffix = "/" + suffix.strip("/")
    if base.endswith("/v1") and suffix.startswith("/v1/"):
        suffix = suffix[3:]
    return base + suffix


def _mask_key(key: Optional[str]) -> str:
    if not key:
        return "(not set)"
    if len(key) <= 8:
        return "***"
    return key[:4] + "..." + key[-4:]


def resolve_provider_config(args: argparse.Namespace) -> Dict[str, Any]:
    requested = (args.provider or "auto").lower()
    if requested == "auto":
        for name in ("openai", "openrouter", "deepseek", "groq", "together", "mistral", "xai", "perplexity", "fireworks", "anthropic", "gemini"):
            if os.environ.get(PROVIDERS[name]["env"]):
                requested = name
                break
        else:
            if os.environ.get("OLLAMA_HOST"):
                requested = "ollama"
            elif os.environ.get("LLAMACPP_HOST"):
                requested = "llamacpp"
            elif os.environ.get("LMSTUDIO_HOST"):
                requested = "lmstudio"
            else:
                raise ProviderError(
                    "no API key found. Set OPENAI_API_KEY, OPENROUTER_API_KEY, DEEPSEEK_API_KEY, "
                    "ANTHROPIC_API_KEY, GEMINI_API_KEY, etc., or pass --provider and --api-key. "
                    "For local models set OLLAMA_HOST or LLAMACPP_HOST."
                )
    if requested not in PROVIDERS:
        raise ProviderError("unknown provider %r. Use one of: %s" % (requested, ", ".join(sorted(PROVIDERS))))
    spec = dict(PROVIDERS[requested])
    base = args.base_url or os.environ.get("OLLAMA_HOST" if requested == "ollama" else "LLAMACPP_HOST" if requested == "llamacpp" else "LMSTUDIO_HOST" if requested == "lmstudio" else "%s_BASE_URL" % requested.upper()) or spec.get("base", "")
    if requested in ("ollama", "llamacpp", "lmstudio"):
        if base and not base.rstrip("/").endswith("/v1"):
            base = base.rstrip("/") + "/v1"
    if not base:
        raise ProviderError("provider %s requires --base-url" % requested)
    parsed = urllib.parse.urlparse(base)
    if parsed.scheme not in ("http", "https"):
        raise ProviderError("base URL must start with http:// or https://")
    if parsed.scheme == "http" and parsed.hostname not in ("127.0.0.1", "localhost", "::1"):
        log_warn("using plain HTTP for a non-local endpoint; API keys and data are not encrypted")
    api_key = args.api_key
    if not api_key and args.api_key_file:
        try:
            api_key = Path(args.api_key_file).read_text(encoding="utf-8").strip()
        except OSError as exc:
            raise ProviderError("could not read API key file: %s" % exc)
    if not api_key:
        api_key = os.environ.get(spec.get("env", ""))
    if requested not in ("ollama", "llamacpp", "lmstudio", "custom") and not api_key:
        raise ProviderError("%s requires an API key. Set %s or pass --api-key." % (requested, spec.get("env")))
    model = args.model or spec.get("model")
    if requested in ("ollama", "llamacpp", "lmstudio") and args.model is None:
        model = None  # discover from the local server
    headers = dict(spec.get("headers", {}))
    return {
        "name": requested,
        "style": spec.get("style", "openai"),
        "base": base,
        "model": model,
        "api_key": api_key,
        "headers": headers,
        "local": bool(spec.get("local")),
        "temperature": args.temperature,
        "max_tokens": args.max_tokens,
        "timeout": args.llm_timeout,
    }


class LLMClient:
    """Small standard-library client for the major chat-completion APIs."""

    def __init__(self, config: Dict[str, Any]) -> None:
        self.config = config
        self.name = config["name"]
        self.style = config["style"]
        self.base = config["base"].rstrip("/")
        self.model = config.get("model")
        self.api_key = config.get("api_key")
        self.headers = dict(config.get("headers", {}))
        self.temperature = float(config.get("temperature", 0.1))
        self.max_tokens = int(config.get("max_tokens", 1200))
        self.timeout = int(config.get("timeout", 180))
        if not self.model:
            self.model = self.discover_model()
        if not self.model:
            raise ProviderError("no model specified and the provider did not advertise one; pass --model")

    # -- HTTP --------------------------------------------------------------
    def _request_json(self, method: str, url: str, payload: Optional[Dict[str, Any]] = None,
                      headers: Optional[Dict[str, str]] = None, timeout: Optional[int] = None) -> Dict[str, Any]:
        request_headers = {
            "Accept": "application/json",
            "User-Agent": "CAOP/%s" % VERSION,
        }
        request_headers.update(self.headers)
        if headers:
            request_headers.update(headers)
        data = None
        if payload is not None:
            data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
            request_headers["Content-Type"] = "application/json"
            request_headers["Content-Length"] = str(len(data))
        request = urllib.request.Request(url, data=data, headers=request_headers, method=method)
        attempts = 2
        last_error: Optional[Exception] = None
        for attempt in range(attempts + 1):
            try:
                with urllib.request.urlopen(request, timeout=timeout or self.timeout) as response:
                    raw = response.read().decode("utf-8", "replace")
                try:
                    value = json.loads(raw)
                except ValueError:
                    raise ProviderError("provider returned non-JSON data: %s" % raw[:300])
                if not isinstance(value, dict):
                    raise ProviderError("provider returned an unexpected JSON value")
                return value
            except urllib.error.HTTPError as exc:
                body = ""
                try:
                    body = exc.read().decode("utf-8", "replace")
                except Exception:
                    pass
                last_error = exc
                retryable = exc.code in (408, 409, 425, 429, 500, 502, 503, 504)
                if retryable and attempt < attempts:
                    retry_after = exc.headers.get("Retry-After") if exc.headers else None
                    delay = 1.5 * (attempt + 1)
                    if retry_after:
                        try:
                            delay = min(10.0, float(retry_after))
                        except ValueError:
                            pass
                    time.sleep(delay)
                    continue
                message = redact_secrets(body[:500].replace("\n", " "), [self.api_key])
                if exc.code in (401, 403):
                    raise ProviderError("authentication failed (%s). Check the API key for %s. %s" % (exc.code, self.name, message))
                if exc.code == 404:
                    raise ProviderError("endpoint or model not found (%s) at %s. Check --base-url and --model. %s" % (exc.code, self._safe_url(url), message))
                if exc.code == 429:
                    raise ProviderError("rate limited (429) by %s. Try again later or use a local model. %s" % (self.name, message))
                raise ProviderError("provider HTTP error %s from %s: %s" % (exc.code, self._safe_url(url), message))
            except urllib.error.URLError as exc:
                last_error = exc
                if attempt < attempts:
                    time.sleep(1.0 * (attempt + 1))
                    continue
                hint = ""
                if self.config.get("local"):
                    hint = " Is the local server running and listening on %s?" % self.base
                raise ProviderError("could not reach %s: %s.%s" % (self._safe_url(url), exc.reason, hint))
            except (TimeoutError, socket.timeout) as exc:
                last_error = exc
                if attempt < attempts:
                    time.sleep(1.0 * (attempt + 1))
                    continue
                raise ProviderError("request timed out after %ss" % (timeout or self.timeout))
        raise ProviderError("provider request failed: %s" % last_error)

    def _safe_url(self, url: str) -> str:
        return re.sub(r"([?&]key=)[^&]+", r"\1***REDACTED***", url)

    def discover_model(self) -> Optional[str]:
        if self.style != "openai":
            return None
        url = _api_url(self.base, "/models")
        headers = {}
        if self.api_key:
            headers["Authorization"] = "Bearer %s" % self.api_key
        try:
            value = self._request_json("GET", url, headers=headers, timeout=min(self.timeout, 30))
            items = value.get("data") or value.get("models") or []
            if isinstance(items, list):
                for item in items:
                    if isinstance(item, dict):
                        model_id = item.get("id") or item.get("name")
                        if model_id:
                            return str(model_id)
        except ProviderError:
            pass
        # Ollama's native tag endpoint is a useful fallback.
        if self.name == "ollama":
            native = self.base[:-3] if self.base.endswith("/v1") else self.base
            try:
                value = self._request_json("GET", native.rstrip("/") + "/api/tags", timeout=20)
                models = value.get("models") or []
                if models and isinstance(models[0], dict):
                    return models[0].get("name")
            except ProviderError:
                pass
        return None

    # -- messages ----------------------------------------------------------
    @staticmethod
    def _split_system(messages: Sequence[Dict[str, str]]) -> Tuple[str, List[Dict[str, str]]]:
        system_parts: List[str] = []
        rest: List[Dict[str, str]] = []
        for message in messages:
            role = message.get("role", "user")
            content = str(message.get("content", ""))
            if role == "system":
                system_parts.append(content)
            else:
                rest.append({"role": "assistant" if role == "assistant" else "user", "content": content})
        return "\n\n".join(system_parts), rest

    @staticmethod
    def _merge_messages(messages: Sequence[Dict[str, str]], assistant_role: str) -> List[Dict[str, str]]:
        merged: List[Dict[str, str]] = []
        for message in messages:
            role = assistant_role if message.get("role") == "assistant" else "user"
            content = str(message.get("content", ""))
            if merged and merged[-1]["role"] == role:
                merged[-1]["content"] += "\n\n" + content
            else:
                merged.append({"role": role, "content": content})
        return merged

    @staticmethod
    def _text_from_content(content: Any) -> str:
        if isinstance(content, str):
            return content
        if isinstance(content, list):
            parts: List[str] = []
            for item in content:
                if isinstance(item, str):
                    parts.append(item)
                elif isinstance(item, dict):
                    if item.get("type") in ("text", "output_text"):
                        parts.append(str(item.get("text", "")))
                    elif "text" in item:
                        parts.append(str(item.get("text", "")))
            return "\n".join(parts)
        return ""

    # -- provider calls ----------------------------------------------------
    def chat(self, messages: Sequence[Dict[str, str]]) -> str:
        if self.style == "anthropic":
            return self._anthropic_chat(messages)
        if self.style == "gemini":
            return self._gemini_chat(messages)
        return self._openai_chat(messages)

    def _openai_chat(self, messages: Sequence[Dict[str, str]]) -> str:
        url = _api_url(self.base, "/chat/completions")
        headers: Dict[str, str] = {}
        if self.api_key:
            headers["Authorization"] = "Bearer %s" % self.api_key
        payload = {
            "model": self.model,
            "messages": [{"role": m.get("role", "user"), "content": str(m.get("content", ""))} for m in messages],
            "temperature": self.temperature,
            "max_tokens": self.max_tokens,
        }
        value = self._request_json("POST", url, payload, headers=headers)
        choices = value.get("choices") or []
        if not choices:
            error = value.get("error")
            if error:
                raise ProviderError("provider error: %s" % str(error)[:400])
            raise ProviderError("provider returned no choices")
        message = choices[0].get("message") or {}
        content = self._text_from_content(message.get("content"))
        if not content:
            content = self._text_from_content(message.get("reasoning_content"))
        if not content:
            raise ProviderError("provider returned an empty message")
        return content

    def _anthropic_chat(self, messages: Sequence[Dict[str, str]]) -> str:
        url = _api_url(self.base, "/v1/messages")
        system, rest = self._split_system(messages)
        converted = self._merge_messages(rest, "assistant")
        if not converted or converted[0]["role"] != "user":
            converted.insert(0, {"role": "user", "content": "Continue."})
        headers = {
            "x-api-key": self.api_key or "",
            "anthropic-version": "2023-06-01",
        }
        payload = {
            "model": self.model,
            "max_tokens": self.max_tokens,
            "temperature": self.temperature,
            "messages": converted,
        }
        if system:
            payload["system"] = system
        value = self._request_json("POST", url, payload, headers=headers)
        blocks = value.get("content") or []
        text = "\n".join(str(block.get("text", "")) for block in blocks if isinstance(block, dict) and block.get("type") == "text")
        if not text:
            raise ProviderError("Anthropic returned no text content")
        return text

    def _gemini_chat(self, messages: Sequence[Dict[str, str]]) -> str:
        base = self.base.rstrip("/")
        if base.endswith("/v1beta"):
            base = base[:-7]
        url = "%s/v1beta/models/%s:generateContent?key=%s" % (
            base, urllib.parse.quote(self.model, safe=""), urllib.parse.quote(self.api_key or "", safe=""))
        system, rest = self._split_system(messages)
        converted = self._merge_messages(rest, "model")
        contents = [{"role": m["role"], "parts": [{"text": m["content"]}]} for m in converted]
        payload: Dict[str, Any] = {
            "contents": contents,
            "generationConfig": {"temperature": self.temperature, "maxOutputTokens": self.max_tokens},
        }
        if system:
            payload["systemInstruction"] = {"parts": [{"text": system}]}
        value = self._request_json("POST", url, payload)
        candidates = value.get("candidates") or []
        if not candidates:
            feedback = value.get("promptFeedback") or {}
            raise ProviderError("Gemini returned no candidates: %s" % str(feedback)[:300])
        candidate = candidates[0]
        finish = candidate.get("finishReason")
        parts = (candidate.get("content") or {}).get("parts") or []
        text = "\n".join(str(part.get("text", "")) for part in parts if isinstance(part, dict))
        if not text:
            raise ProviderError("Gemini returned no text (finishReason=%s)" % finish)
        return text


# ---------------------------------------------------------------------------
# Agent tool surface
# ---------------------------------------------------------------------------

TOOL_SPECS: List[Dict[str, Any]] = [
    {
        "name": "scan",
        "risk": "safe",
        "description": "Collect a fresh device profile. Read-only.",
        "args": {"include_usage": "boolean (optional)"},
    },
    {
        "name": "list_packages",
        "risk": "safe",
        "description": "List installed packages. Read-only.",
        "args": {"scope": "system|third_party|disabled|all (optional)", "filter": "substring (optional)", "limit": "int 1..200 (optional)"},
    },
    {
        "name": "inspect_package",
        "risk": "safe",
        "description": "Show enabled state, system/user ownership, risk tier and last use. Read-only.",
        "args": {"package": "package name"},
    },
    {
        "name": "get_setting",
        "risk": "safe",
        "description": "Read an allowlisted setting. Read-only.",
        "args": {"namespace": "system|global|secure", "key": "allowlisted key"},
    },
    {
        "name": "apply_profile",
        "risk": "profile-dependent",
        "description": "Apply the built-in deterministic profile (packages, settings, doze cleanup, cache trim).",
        "args": {"profile": "conservative|balanced|aggressive", "settings": "boolean (optional)", "disable": "boolean (optional)", "cache_trim": "boolean (optional)", "doze_cleanup": "boolean (optional)"},
    },
    {
        "name": "disable_package",
        "risk": "safe|moderate|risky",
        "description": "Disable one reviewed system package with pm disable-user, verify the result, and journal it.",
        "args": {"package": "package name", "reason": "short reason (optional)"},
    },
    {
        "name": "enable_package",
        "risk": "safe",
        "description": "Re-enable a package disabled by this tool or the user.",
        "args": {"package": "package name"},
    },
    {
        "name": "force_stop",
        "risk": "safe",
        "description": "Force-stop a non-critical app process. It may restart.",
        "args": {"package": "package name"},
    },
    {
        "name": "set_setting",
        "risk": "safe",
        "description": "Write an allowlisted Android setting and verify it.",
        "args": {"namespace": "system|global|secure", "key": "allowlisted key", "value": "new value"},
    },
    {
        "name": "set_standby_bucket",
        "risk": "moderate|risky",
        "description": "Change an app standby bucket. Never use on messaging apps.",
        "args": {"package": "package name", "bucket": "active|working_set|frequent|rare|restricted"},
    },
    {
        "name": "appops_set",
        "risk": "moderate|risky",
        "description": "Set an allowlisted app-op, only if the shell UID has write permission. Never use on messaging apps.",
        "args": {"package": "package name", "op": "RUN_ANY_IN_BACKGROUND|RUN_IN_BACKGROUND|WAKE_LOCK", "mode": "allow|ignore|deny|default|foreground"},
    },
    {
        "name": "doze_whitelist_remove",
        "risk": "safe",
        "description": "Remove a disabled or telemetry package from the Doze whitelist. Never use on messaging apps.",
        "args": {"package": "package name"},
    },
    {
        "name": "compile_package",
        "risk": "safe",
        "description": "Ask the package manager to AOT-compile one installed package.",
        "args": {"package": "package name", "mode": "speed|speed-profile|verify|quicken (optional)"},
    },
    {
        "name": "trim_caches",
        "risk": "safe",
        "description": "Trim app caches. No app data is removed. Runs at most once per agent run.",
        "args": {"size": "size such as 999G (optional)"},
    },
    {
        "name": "finish",
        "risk": "safe",
        "description": "Finish the run with a concise summary. No more actions are executed.",
        "args": {"summary": "short summary"},
    },
]
TOOL_INDEX: Dict[str, Dict[str, Any]] = {item["name"]: item for item in TOOL_SPECS}


def tool_catalog_json() -> str:
    return json.dumps(TOOL_SPECS, ensure_ascii=False, indent=2)


def build_agent_system_prompt(critical: Set[str], max_risk: str) -> str:
    critical_sample = ", ".join(sorted(critical)[:45])
    return """You are CAOP (CYFARE's Android Optimizer Plus), an expert in Android performance, battery, privacy and ADB.

Return ONLY one JSON object. No markdown, no prose outside JSON:
{"thought":"short reasoning","actions":[{"tool":"tool_name","args":{}}],"done":false}

You operate through a harness. The harness executes your actions and returns observations. Never invent results.

Hard safety rules:
- Never uninstall apps, clear app data, factory-reset, reboot, or ask for a shell. You have no shell tool.
- Only use the tools listed below. Unknown tools are rejected.
- Never disable critical packages: %s
- Never disable the default launcher, dialer, SMS app, keyboard, SystemUI, Settings, telephony, Google Play services or the Play Store.
- Do not disable user-installed apps. Only reviewed system packages are eligible by default.
- Do not restrict background execution or Doze status of messaging/communication apps.
- Prefer reversible actions. Verify effects through observations. If a package is protected by the ROM, do not repeat the same action; try a safe alternative or accept it.
- Maximum risk for this run: %s. Actions above that risk are rejected by the harness.
- Maximum 8 actions per step. If there is nothing useful left, return done=true with a concise summary.
- The harness may be in dry-run mode; actions will be reported, not applied.

Tool catalogue:
%s
""" % (critical_sample, max_risk, tool_catalog_json())


def build_agent_user_prompt(goal: str, profile: Dict[str, Any]) -> str:
    return """Goal: %s

Device profile (compact):
%s

Candidate packages include their built-in risk tier and last-used time when available.
Start by deciding whether the built-in profile is sufficient. Use scan again only if you need fresh data after major changes.
Return the JSON decision now.""" % (goal, json.dumps(compact_profile(profile), ensure_ascii=False, indent=2))


class ToolRegistry:
    def __init__(self, client: AdbClient, profile: Dict[str, Any], options: OptimizerOptions,
                 journal: Journal, max_risk: str = "moderate") -> None:
        self.client = client
        self.profile = profile
        self.options = options
        self.journal = journal
        self.max_risk = max_risk
        self.sdk = int(profile.get("device", {}).get("sdk") or 0)
        self.caps = profile.get("capabilities", {})
        self.critical = set(profile.get("critical_packages", []))
        self.vendor = profile.get("vendor", "generic")
        self.extra_profiles = options.extra_profiles
        self.system_packages: Set[str] = set(client._system_packages or [])
        self.disabled_packages: Set[str] = set(client._disabled_packages or [])
        if not self.system_packages:
            inventory = client.package_inventory()
            self.system_packages = set(inventory.get("system", set()))
            self.disabled_packages = set(inventory.get("disabled", set()))
        self._cache_trimmed = False
        self.done = False
        self.finish_summary: Optional[str] = None
        self.actions_executed = 0

    # -- validation --------------------------------------------------------
    def _check_risk(self, risk: str) -> None:
        if RISK_ORDER.get(risk, 1) > RISK_ORDER.get(self.max_risk, 1):
            raise SafetyError("action risk %s exceeds the agent limit %s" % (risk, self.max_risk))

    def _package(self, args: Dict[str, Any]) -> str:
        package = str(args.get("package", "")).strip()
        if not PACKAGE_RE.match(package):
            raise ValidationError("invalid package name")
        return package

    def _reviewed(self, package: str) -> Tuple[str, str]:
        tier, risk = package_tier_risk(package, self.vendor, self.extra_profiles)
        if tier == "unknown":
            raise SafetyError("package %s is not in a reviewed built-in profile; refusing to disable it blindly" % package)
        return tier, risk

    def _ok(self, message: str, **data: Any) -> Dict[str, Any]:
        result = {"ok": True, "message": message}
        result.update(data)
        return result

    def _err(self, message: str, **data: Any) -> Dict[str, Any]:
        result = {"ok": False, "error": message}
        result.update(data)
        return result

    # -- tools -------------------------------------------------------------
    def tool_scan(self, args: Dict[str, Any]) -> Dict[str, Any]:
        self.profile = collect_profile(
            self.client,
            include_usage=bool(args.get("include_usage", True)),
            include_processes=True,
            extra=self.extra_profiles,
            allow_user_apps=self.options.allow_user_apps,
        )
        self.sdk = int(self.profile.get("device", {}).get("sdk") or 0)
        self.caps = self.profile.get("capabilities", {})
        self.critical = set(self.profile.get("critical_packages", []))
        self.vendor = self.profile.get("vendor", self.vendor)
        return self._ok("device profile refreshed", profile=compact_profile(self.profile))

    def tool_list_packages(self, args: Dict[str, Any]) -> Dict[str, Any]:
        scope = str(args.get("scope", "all"))
        if scope not in ("system", "third_party", "disabled", "all"):
            raise ValidationError("scope must be system, third_party, disabled or all")
        filter_text = str(args.get("filter", "")).strip().lower()
        if len(filter_text) > 80:
            raise ValidationError("filter is too long")
        limit = safe_int(args.get("limit", 100), 100) or 100
        limit = max(1, min(200, limit))
        if self.client._system_packages is None or self.client._third_party_packages is None:
            self.client.package_inventory()
        system = set(self.client._system_packages or [])
        third = set(self.client._third_party_packages or [])
        disabled = set(self.client._disabled_packages or [])
        if scope == "system":
            items = system
        elif scope == "third_party":
            items = third
        elif scope == "disabled":
            items = disabled
        else:
            items = system | third
        if filter_text:
            items = {item for item in items if filter_text in item.lower()}
        result = []
        for package in sorted(items)[:limit]:
            result.append({"package": package, "disabled": package in disabled, "system": package in system})
        return self._ok("%d package(s)" % len(result), packages=result, truncated=len(items) > limit)

    def tool_inspect_package(self, args: Dict[str, Any]) -> Dict[str, Any]:
        package = self._package(args)
        state = self.client.app_state(package)
        tier, risk = package_tier_risk(package, self.vendor, self.extra_profiles)
        last_used = (self.profile.get("usage", {}) or {}).get("last_used", {}).get(package)
        return self._ok("package inspected", **{
            "package": package,
            "state": state.to_dict(),
            "tier": tier,
            "risk": risk,
            "critical": is_critical_package(package, self.critical),
            "communication": is_communication_package(package),
            "last_used": last_used,
        })

    def tool_get_setting(self, args: Dict[str, Any]) -> Dict[str, Any]:
        namespace = str(args.get("namespace", ""))
        key = str(args.get("key", ""))
        allowed = (namespace, key) in SETTINGS_SPEC or (namespace, key) in (PRIVATE_DNS_SPEC["mode"], PRIVATE_DNS_SPEC["hostname"])
        if not allowed:
            raise SafetyError("setting is not allowlisted")
        value = self.client.settings_get(namespace, key)
        return self._ok("setting read", namespace=namespace, key=key, value=value)

    def tool_apply_profile(self, args: Dict[str, Any]) -> Dict[str, Any]:
        requested = str(args.get("profile", "balanced"))
        if requested not in PROFILE_TIERS:
            raise ValidationError("unknown profile")
        risk = PROFILE_RISK[requested]
        self._check_risk(risk)
        new_options = OptimizerOptions(
            profile=requested,
            dry_run=self.options.dry_run,
            allow_risky=(self.max_risk == "risky"),
            allow_user_apps=self.options.allow_user_apps,
            do_settings=bool(args.get("settings", True)),
            do_disable=bool(args.get("disable", True)),
            do_cache_trim=bool(args.get("cache_trim", True)),
            do_doze_cleanup=bool(args.get("doze_cleanup", True)),
            cache_size=self.options.cache_size,
            screen_timeout=self.options.screen_timeout,
            private_dns_mode=self.options.private_dns_mode,
            private_dns_host=self.options.private_dns_host,
            extra_profiles=self.options.extra_profiles,
        )
        optimizer = Optimizer(self.client, self.profile, new_options, self.journal)
        result = optimizer.execute()
        self.disabled_packages |= set(item["package"] for item in result.get("packages", {}).get("disabled", []) if isinstance(item, dict))
        return self._ok("profile applied", counts=summarize_counts(result), summary=result)

    def tool_disable_package(self, args: Dict[str, Any]) -> Dict[str, Any]:
        package = self._package(args)
        if is_critical_package(package, self.critical):
            raise SafetyError("refusing to disable critical package %s" % package)
        tier, risk = self._reviewed(package)
        self._check_risk(risk)
        state = self.client.app_state(package)
        if not state.installed:
            return self._err("package is not installed", package=package)
        if state.disabled or state.suspended:
            return self._ok("package is already disabled/suspended", package=package, state=state.to_dict())
        if not state.is_system and not self.options.allow_user_apps:
            raise SafetyError("refusing to disable a third-party app without --allow-user-apps")
        if self.options.dry_run:
            self.journal.add("package", name=package, before=state.to_dict(), after=None, result="planned", reason=args.get("reason") or "agent request")
            return self._ok("would disable package", package=package, risk=risk, dry_run=True)
        result = self.client.disable_package(package, state)
        if result.get("result") == "disabled":
            self.disabled_packages.add(package)
            self.journal.add("package", name=package, before=result.get("before"), after=result.get("after"), result="disabled", reason=args.get("reason") or "agent request")
            return self._ok("package disabled", package=package, risk=risk, result=result)
        if result.get("result") == "already-disabled":
            return self._ok("package was already disabled", package=package, result=result)
        self.journal.add("package", name=package, before=result.get("before"), after=result.get("after"), result=result.get("result", "failed"), reason=args.get("reason") or "agent request")
        if result.get("result") == "protected":
            fallback = None
            if self.caps.get("suspend") and self.sdk >= 24 and is_telemetry_package(package):
                fallback = self.client.suspend_package(package)
                if fallback.get("ok"):
                    self.journal.add("package", name=package, before=fallback.get("before"), after=fallback.get("after"), result="suspended", reason="protected telemetry fallback")
            self.client.force_stop(package)
            return self._ok("package is protected by the ROM; fallback applied where safe", package=package, protected=True, fallback=fallback, result=result)
        return self._err("could not disable package", package=package, result=result)

    def tool_enable_package(self, args: Dict[str, Any]) -> Dict[str, Any]:
        package = self._package(args)
        result = self.client.enable_package(package)
        if result.get("ok"):
            self.disabled_packages.discard(package)
            self.journal.add("package", name=package, before=result.get("before"), after=result.get("after"), result="enabled", reason="agent request")
            return self._ok("package enabled", package=package, result=result)
        self.journal.add("package", name=package, before=result.get("before"), after=result.get("after"), result="failed", reason="agent enable failed")
        return self._err("could not enable package", package=package, result=result)

    def tool_force_stop(self, args: Dict[str, Any]) -> Dict[str, Any]:
        package = self._package(args)
        if is_critical_package(package, self.critical):
            raise SafetyError("refusing to force-stop critical package %s" % package)
        if self.options.dry_run:
            return self._ok("would force-stop package", package=package, dry_run=True)
        result = self.client.force_stop(package)
        return self._ok("force-stop requested", package=package, detail=result.summary(200)) if result.ok else self._err("force-stop failed", detail=result.summary(200))

    def tool_set_setting(self, args: Dict[str, Any]) -> Dict[str, Any]:
        namespace = str(args.get("namespace", ""))
        key = str(args.get("key", ""))
        value = str(args.get("value", ""))
        spec = SETTINGS_SPEC.get((namespace, key))
        if not spec:
            raise SafetyError("setting is not allowlisted")
        self._check_risk(spec.get("risk", "safe"))
        min_sdk = spec.get("min_sdk", 0)
        if self.sdk and min_sdk and self.sdk < min_sdk:
            return self._err("setting requires API %s" % min_sdk)
        if not self.caps.get("settings"):
            return self._err("settings command is unavailable")
        target = self._validate_agent_setting(namespace, key, value, spec)
        current = self.client.settings_get(namespace, key)
        if (namespace, key) == ("system", "screen_off_timeout"):
            current_int = safe_int(current)
            if current_int is not None and int(target) > current_int:
                raise SafetyError("the agent may reduce the screen timeout, not increase it")
        if normalize_setting(current) == normalize_setting(target):
            return self._ok("setting is already at target", namespace=namespace, key=key, value=target)
        if self.options.dry_run:
            self.journal.add("setting", namespace=namespace, key=key, before=current, after=target, result="planned")
            return self._ok("would set setting", namespace=namespace, key=key, current=current, target=target, dry_run=True)
        result = self.client.settings_put(namespace, key, target)
        after = self.client.settings_get(namespace, key)
        if after == target:
            self.journal.add("setting", namespace=namespace, key=key, before=current, after=after, result="set")
            return self._ok("setting applied", namespace=namespace, key=key, current=current, value=after)
        self.journal.add("setting", namespace=namespace, key=key, before=current, after=after, result="failed")
        return self._err("setting did not verify", namespace=namespace, key=key, current=current, target=target, after=after, detail=result.summary(200))

    def _validate_agent_setting(self, namespace: str, key: str, value: str, spec: Dict[str, Any]) -> str:
        kind = spec.get("type")
        if kind == "int":
            number = safe_int(value)
            if number is None:
                raise ValidationError("value must be an integer")
            minimum = spec.get("minimum")
            maximum = spec.get("maximum")
            if minimum is not None and number < minimum:
                number = minimum
            if maximum is not None and number > maximum:
                number = maximum
            return str(number)
        if kind == "float":
            number = safe_float(value)
            if number is None:
                raise ValidationError("value must be a number")
            return str(max(0.0, min(10.0, number)))
        if kind == "enum":
            allowed = spec.get("allowed", [])
            if value not in allowed:
                raise ValidationError("value must be one of %s" % ", ".join(allowed))
            return value
        if not SAFE_VALUE_RE.match(value):
            raise ValidationError("unsafe value")
        return value

    def tool_set_standby_bucket(self, args: Dict[str, Any]) -> Dict[str, Any]:
        package = self._package(args)
        bucket = str(args.get("bucket", "rare"))
        if bucket not in ("active", "working_set", "frequent", "rare", "restricted"):
            raise ValidationError("invalid standby bucket")
        if is_critical_package(package, self.critical) or is_communication_package(package):
            raise SafetyError("refusing to change standby bucket for critical/communication package")
        risk = "risky" if bucket == "restricted" else "moderate" if bucket == "rare" else "safe"
        self._check_risk(risk)
        if not self.caps.get("standby"):
            return self._err("standby buckets are unavailable on this Android version")
        before = self.client.get_standby_bucket(package)
        if self.options.dry_run:
            self.journal.add("standby", name=package, bucket=bucket, before=before, result="planned")
            return self._ok("would set standby bucket", package=package, bucket=bucket, before=before, dry_run=True)
        result = self.client.set_standby_bucket(package, bucket)
        if result.get("ok"):
            self.journal.add("standby", name=package, bucket=bucket, before=before, after=result.get("after"), result="restricted")
            return self._ok("standby bucket applied", package=package, bucket=bucket, result=result)
        self.journal.add("standby", name=package, bucket=bucket, before=before, after=result.get("after"), result="failed")
        return self._err("standby bucket was ineffective or failed", package=package, bucket=bucket, before=before, after=result.get("after"), detail=result.get("detail"))

    def tool_appops_set(self, args: Dict[str, Any]) -> Dict[str, Any]:
        package = self._package(args)
        op = str(args.get("op", ""))
        mode = str(args.get("mode", "default"))
        if op not in ("RUN_ANY_IN_BACKGROUND", "RUN_IN_BACKGROUND", "WAKE_LOCK"):
            raise ValidationError("app-op is not allowlisted")
        if mode not in ("allow", "ignore", "deny", "default", "foreground"):
            raise ValidationError("invalid app-op mode")
        if is_critical_package(package, self.critical) or is_communication_package(package):
            raise SafetyError("refusing to change app-ops for critical/communication package")
        risk = "risky" if op == "WAKE_LOCK" and mode in ("ignore", "deny") else "moderate" if mode in ("ignore", "deny") else "safe"
        self._check_risk(risk)
        if not self.caps.get("appops_write"):
            return self._err("the shell UID does not have MANAGE_APP_OPS_MODES on this ROM")
        before = self.client.appops_get(package, op)
        if self.options.dry_run:
            self.journal.add("appops", package=package, op=op, mode=mode, before=before, result="planned")
            return self._ok("would set app-op", package=package, op=op, mode=mode, before=before, dry_run=True)
        result = self.client.appops_set(package, op, mode)
        after = self.client.appops_get(package, op)
        if after == mode:
            self.journal.add("appops", package=package, op=op, mode=mode, before=before, after=after, result="restricted")
            return self._ok("app-op applied", package=package, op=op, mode=after)
        self.journal.add("appops", package=package, op=op, mode=mode, before=before, after=after, result="failed")
        return self._err("app-op did not verify", package=package, op=op, mode=mode, before=before, after=after, detail=result.summary(200))

    def tool_doze_whitelist_remove(self, args: Dict[str, Any]) -> Dict[str, Any]:
        package = self._package(args)
        if is_critical_package(package, self.critical) or is_communication_package(package):
            raise SafetyError("refusing to alter Doze status for critical/communication package")
        if not self.caps.get("deviceidle"):
            return self._err("deviceidle is unavailable on this Android version")
        whitelist = set(self.profile.get("doze", {}).get("whitelist", []))
        if package not in whitelist:
            return self._ok("package is not on the Doze whitelist", package=package)
        if package not in self.disabled_packages and not is_telemetry_package(package):
            raise SafetyError("only disabled or telemetry packages may be removed from the Doze whitelist")
        if self.options.dry_run:
            self.journal.add("doze", name=package, action="remove", result="planned")
            return self._ok("would remove from Doze whitelist", package=package, dry_run=True)
        result = self.client.doze_whitelist_remove(package)
        remaining = set(self.client.get_doze_whitelist())
        if result.ok and package not in remaining:
            self.journal.add("doze", name=package, action="remove", result="removed")
            return self._ok("removed from Doze whitelist", package=package)
        self.journal.add("doze", name=package, action="remove", result="failed")
        return self._err("Doze whitelist removal failed or was ineffective", package=package, detail=result.summary(200))

    def tool_compile_package(self, args: Dict[str, Any]) -> Dict[str, Any]:
        package = self._package(args)
        mode = str(args.get("mode", "speed"))
        if mode not in ("speed", "speed-profile", "verify", "quicken"):
            raise ValidationError("invalid compile mode")
        if not self.caps.get("compile"):
            return self._err("package compilation is unavailable on this ROM")
        state = self.client.app_state(package)
        if not state.installed or state.disabled:
            return self._err("package is not installed or is disabled", package=package)
        if self.options.dry_run:
            self.journal.add("compile", name=package, mode=mode, result="planned")
            return self._ok("would compile package", package=package, mode=mode, dry_run=True)
        result = self.client.compile_package(package, mode)
        if result.ok:
            self.journal.add("compile", name=package, mode=mode, result="compiled")
            return self._ok("package compiled", package=package, mode=mode)
        self.journal.add("compile", name=package, mode=mode, result="failed")
        return self._err("compilation failed", package=package, detail=result.summary(300))

    def tool_trim_caches(self, args: Dict[str, Any]) -> Dict[str, Any]:
        if self._cache_trimmed:
            return self._err("cache trim already performed in this agent run")
        size = str(args.get("size", self.options.cache_size))
        if not SIZE_RE.match(size):
            raise ValidationError("invalid cache trim size")
        before = self.client.get_storage()
        if self.options.dry_run:
            self._cache_trimmed = True
            self.journal.add("cache", action="trim", size=size, before=before, result="planned")
            return self._ok("would trim caches", size=size, before=before, dry_run=True)
        result = self.client.trim_caches(size)
        time.sleep(1.0)
        after = self.client.get_storage()
        freed = max(0, (after.get("available") or 0) - (before.get("available") or 0))
        if result.ok:
            self._cache_trimmed = True
            self.journal.add("cache", action="trim", size=size, before=before, after=after, freed_bytes=freed, result="trimmed")
            return self._ok("caches trimmed", size=size, freed_bytes=freed, before=before, after=after)
        self.journal.add("cache", action="trim", size=size, before=before, after=after, result="failed")
        return self._err("cache trim failed", detail=result.summary(300))

    def tool_finish(self, args: Dict[str, Any]) -> Dict[str, Any]:
        self.done = True
        self.finish_summary = str(args.get("summary", ""))[:1000]
        return self._ok("agent finished", summary=self.finish_summary)

    # -- dispatch ----------------------------------------------------------
    def execute(self, action: Any) -> Dict[str, Any]:
        if not isinstance(action, dict):
            return self._err("action must be an object")
        tool = action.get("tool")
        args = action.get("args") or {}
        if not isinstance(tool, str) or tool not in TOOL_INDEX:
            return self._err("unknown tool %r" % tool, tool=tool)
        if not isinstance(args, dict):
            return self._err("tool args must be an object", tool=tool)
        handlers: Dict[str, Callable[[Dict[str, Any]], Dict[str, Any]]] = {
            "scan": self.tool_scan,
            "list_packages": self.tool_list_packages,
            "inspect_package": self.tool_inspect_package,
            "get_setting": self.tool_get_setting,
            "apply_profile": self.tool_apply_profile,
            "disable_package": self.tool_disable_package,
            "enable_package": self.tool_enable_package,
            "force_stop": self.tool_force_stop,
            "set_setting": self.tool_set_setting,
            "set_standby_bucket": self.tool_set_standby_bucket,
            "appops_set": self.tool_appops_set,
            "doze_whitelist_remove": self.tool_doze_whitelist_remove,
            "compile_package": self.tool_compile_package,
            "trim_caches": self.tool_trim_caches,
            "finish": self.tool_finish,
        }
        self.actions_executed += 1
        try:
            log_debug("agent tool %s args=%s" % (tool, compact_json(args)))
            result = handlers[tool](args)
            if not isinstance(result, dict):
                return self._err("tool returned an invalid result", tool=tool)
            result.setdefault("tool", tool)
            return result
        except (SafetyError, ValidationError) as exc:
            return self._err(str(exc), tool=tool, safety=True)
        except AdbError as exc:
            return self._err("ADB error: %s" % exc, tool=tool)
        except Exception as exc:
            log_debug("unexpected tool error: %r" % exc)
            return self._err("tool failed: %s" % exc, tool=tool)


class AndroidAgent:
    def __init__(self, client: AdbClient, profile: Dict[str, Any], llm: LLMClient,
                 options: OptimizerOptions, journal: Journal, args: argparse.Namespace) -> None:
        self.client = client
        self.profile = profile
        self.llm = llm
        self.options = options
        self.journal = journal
        self.args = args
        self.max_risk = args.agent_max_risk
        self.max_steps = int(args.max_steps)
        self.goal = args.goal
        self.transcript: List[Dict[str, Any]] = []
        self.tools = ToolRegistry(client, profile, options, journal, self.max_risk)
        self.steps: List[Dict[str, Any]] = []

    def _status(self) -> Dict[str, Any]:
        status = self.client.quick_status()
        status["setting_sample"] = {
            key: value for key, value in self.tools.profile.get("settings", {}).items()
            if key in ("system.screen_off_timeout", "global.cached_apps_freezer", "global.wifi_scan_always_enabled", "secure.adaptive_sleep")
        }
        return status

    def _mutating(self, actions: Sequence[Any]) -> bool:
        readonly = {"scan", "list_packages", "inspect_package", "get_setting", "finish"}
        return any(isinstance(action, dict) and action.get("tool") not in readonly for action in actions)

    def run(self) -> Dict[str, Any]:
        system_prompt = build_agent_system_prompt(self.tools.critical, self.max_risk)
        user_prompt = build_agent_user_prompt(self.goal, self.profile)
        messages: List[Dict[str, str]] = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ]
        invalid_responses = 0
        stagnant_steps = 0
        stop_reason = "max-steps"
        for step in range(1, self.max_steps + 1):
            log_info("agent step %d/%d (model=%s)" % (step, self.max_steps, self.llm.model))
            try:
                response_text = self.llm.chat(messages)
            except ProviderError:
                raise
            try:
                parsed = extract_json_object(response_text)
            except ValidationError as exc:
                invalid_responses += 1
                log_warn("model returned invalid JSON (%d/2): %s" % (invalid_responses, exc))
                messages.append({"role": "assistant", "content": response_text[:4000]})
                messages.append({"role": "user", "content": "Your previous reply was not a single valid JSON object. Return only JSON matching the schema, with no markdown fences or extra prose."})
                if invalid_responses >= 2:
                    raise ProviderError("model did not produce valid JSON after two repair attempts")
                continue
            thought = str(parsed.get("thought", ""))[:1500]
            if thought:
                log_info("thought: %s" % thought)
            actions = parsed.get("actions", [])
            done = bool(parsed.get("done", False))
            if not isinstance(actions, list):
                actions = []
            if len(actions) > MAX_ACTIONS_PER_STEP:
                log_warn("model requested %d actions; limit is %d" % (len(actions), MAX_ACTIONS_PER_STEP))
                messages.append({"role": "assistant", "content": response_text[:4000]})
                messages.append({"role": "user", "content": "Too many actions in one step. Return at most %d actions." % MAX_ACTIONS_PER_STEP})
                continue
            if actions and self._mutating(actions) and not self.options.dry_run and not self.args.yes:
                print("Agent wants to run:")
                for item in actions:
                    print("  - %s %s" % (item.get("tool"), compact_json(item.get("args", {}))))
                if not confirm("Apply these actions?", assume_yes=False):
                    stop_reason = "user-declined"
                    break
            results: List[Dict[str, Any]] = []
            for action in actions:
                if self.tools.actions_executed >= MAX_TOTAL_AGENT_ACTIONS:
                    results.append({"ok": False, "error": "total action budget exhausted"})
                    stop_reason = "action-budget"
                    break
                log_info("action: %s %s" % (action.get("tool") if isinstance(action, dict) else "?", compact_json(action.get("args", {})) if isinstance(action, dict) else ""))
                result = self.tools.execute(action)
                results.append(result)
                if result.get("ok"):
                    log_ok(result.get("message", "done"))
                else:
                    log_warn(result.get("error", "action failed"))
                if self.tools.done:
                    done = True
                    break
            self.steps.append({
                "step": step,
                "thought": thought,
                "response": response_text,
                "actions": actions,
                "results": results,
                "done": done,
                "timestamp": now_iso(),
            })
            if done or self.tools.done:
                stop_reason = "model-finished"
                break
            # Build the next observation.  Keep it compact; full scans only
            # happen when the model explicitly asks for one.
            status = self._status()
            observation = {
                "step": step,
                "results": results,
                "status": status,
                "candidates_remaining": compact_profile(self.tools.profile, max_candidates=35).get("candidates", []),
                "hint": "If the actions were rejected or ineffective, do not repeat them. Either use a safe alternative or finish.",
            }
            messages.append({"role": "assistant", "content": response_text[:6000]})
            messages.append({"role": "user", "content": json.dumps(observation, ensure_ascii=False)[:16000]})
            # Keep the context bounded.
            if len(messages) > 12:
                messages = [messages[0]] + messages[-10:]
            if not any(result.get("ok") for result in results):
                stagnant_steps += 1
                if stagnant_steps >= 2:
                    stop_reason = "no-progress"
                    break
            else:
                stagnant_steps = 0
        self.journal.save()
        final = {
            "provider": self.llm.name,
            "model": self.llm.model,
            "goal": self.goal,
            "steps": self.steps,
            "stop_reason": stop_reason,
            "finish_summary": self.tools.finish_summary,
            "actions_executed": self.tools.actions_executed,
            "dry_run": self.options.dry_run,
            "warnings": self.tools.profile.get("warnings", []),
            "final_status": self._status(),
        }
        transcript_path = self._save_transcript(final)
        if transcript_path:
            final["transcript"] = str(transcript_path)
        return final

    def _save_transcript(self, final: Dict[str, Any]) -> Optional[Path]:
        if not self.args.transcript:
            return None
        path = Path(self.args.transcript)
        payload = {
            "version": VERSION,
            "generated_at": now_iso(),
            "device": self.profile.get("device", {}),
            "provider": self.llm.name,
            "model": self.llm.model,
            "final": final,
        }
        write_json(path, payload)
        return path


# ---------------------------------------------------------------------------
# Rollback
# ---------------------------------------------------------------------------

BUCKET_NAMES: Dict[int, str] = {
    5: "exempted",
    10: "active",
    20: "working_set",
    30: "frequent",
    40: "rare",
    45: "restricted",
    50: "never",
}


class Rollbacker:
    def __init__(self, client: AdbClient, journal: Dict[str, Any],
                 dry_run: bool = False, assume_yes: bool = False,
                 force: bool = False) -> None:
        self.client = client
        self.journal = journal
        self.dry_run = dry_run
        self.assume_yes = assume_yes
        self.force = force
        self.actions: List[Dict[str, Any]] = []
        self.warnings: List[str] = []

    def run(self) -> Dict[str, Any]:
        device = self.journal.get("device", {}) or {}
        journal_serial = device.get("serial")
        if journal_serial and self.client.serial and journal_serial != self.client.serial and not self.force:
            raise JournalError("journal belongs to device %s, not %s (pass --force to override)" % (journal_serial, self.client.serial))
        entries = list(self.journal.get("entries", []))
        if not self.dry_run and not self.assume_yes:
            if not confirm("Roll back %d journal entries on %s?" % (len(entries), self.client.serial), assume_yes=False):
                return {"result": "cancelled", "actions": [], "warnings": []}
        for entry in reversed(entries):
            try:
                self._rollback_entry(entry)
            except OptimizerError as exc:
                self.warnings.append("rollback entry failed: %s" % exc)
            except Exception as exc:
                self.warnings.append("unexpected rollback error: %s" % exc)
        return {"result": "dry-run" if self.dry_run else "rolled-back", "actions": self.actions, "warnings": dedupe(self.warnings)}

    def _record(self, action: str, target: str, result: str, **data: Any) -> None:
        item = {"action": action, "target": target, "result": result}
        item.update(data)
        self.actions.append(item)

    def _rollback_entry(self, entry: Dict[str, Any]) -> None:
        entry_type = entry.get("type")
        result = entry.get("result")
        if entry_type == "package":
            package = entry.get("name")
            if not isinstance(package, str) or not PACKAGE_RE.match(package):
                return
            before = entry.get("before") or {}
            if result == "disabled":
                if before.get("enabled") in (2, 3, 4):
                    self._record("enable", package, "skipped", reason="was disabled before this run")
                    return
                if self.dry_run:
                    self._record("enable", package, "planned")
                    return
                value = self.client.enable_package(package)
                self._record("enable", package, "enabled" if value.get("ok") else "failed", detail=value.get("detail"))
            elif result == "suspended":
                if before.get("suspended"):
                    self._record("unsuspend", package, "skipped", reason="was suspended before this run")
                    return
                if self.dry_run:
                    self._record("unsuspend", package, "planned")
                    return
                value = self.client.unsuspend_package(package)
                self._record("unsuspend", package, "unsuspended" if value.get("ok") else "failed", detail=value.get("detail"))
            # protected/failed/planned entries changed nothing.
            return
        if entry_type == "setting":
            namespace = entry.get("namespace")
            key = entry.get("key")
            if not isinstance(namespace, str) or not isinstance(key, str):
                return
            if result not in ("set", "deleted"):
                return
            before = entry.get("before")
            if self.dry_run:
                self._record("restore-setting", "%s/%s" % (namespace, key), "planned", value=before)
                return
            if before is None or str(before).lower() == "null":
                value = self.client.settings_delete(namespace, key)
                after = self.client.settings_get(namespace, key)
                self._record("restore-setting", "%s/%s" % (namespace, key), "deleted" if after is None else "failed", value=before)
            else:
                value = self.client.settings_put(namespace, key, str(before))
                after = self.client.settings_get(namespace, key)
                self._record("restore-setting", "%s/%s" % (namespace, key), "restored" if after == str(before) else "failed", value=before, after=after)
            return
        if entry_type == "appops":
            package = entry.get("package")
            op = entry.get("op")
            if result != "restricted" or not isinstance(package, str) or not isinstance(op, str):
                return
            before = entry.get("before") or "default"
            if self.dry_run:
                self._record("restore-appops", "%s:%s" % (package, op), "planned", value=before)
                return
            value = self.client.appops_set(package, op, str(before))
            after = self.client.appops_get(package, op)
            self._record("restore-appops", "%s:%s" % (package, op), "restored" if after == before else "failed", value=before, after=after)
            return
        if entry_type == "standby":
            package = entry.get("name")
            if result != "restricted" or not isinstance(package, str):
                return
            before = entry.get("before")
            if before not in BUCKET_NAMES:
                self.warnings.append("cannot restore standby bucket for %s: previous bucket %r is unknown" % (package, before))
                return
            bucket = BUCKET_NAMES[before]
            if self.dry_run:
                self._record("restore-standby", package, "planned", value=bucket)
                return
            value = self.client.set_standby_bucket(package, bucket)
            self._record("restore-standby", package, "restored" if value.get("ok") else "failed", value=bucket, after=value.get("after"))
            return
        if entry_type == "doze":
            package = entry.get("name")
            if not isinstance(package, str) or result != "removed":
                return
            if self.dry_run:
                self._record("restore-doze", package, "planned")
                return
            value = self.client.doze_whitelist_add(package)
            remaining = set(self.client.get_doze_whitelist())
            self._record("restore-doze", package, "restored" if package in remaining else "failed")
            return
        if entry_type == "kernel":
            path = entry.get("path")
            before = entry.get("before")
            if result != "set" or not isinstance(path, str) or before is None:
                return
            if not self.client.root_available():
                self.warnings.append("cannot restore kernel tunable %s without root" % path)
                return
            if self.dry_run:
                self._record("restore-kernel", path, "planned", value=before)
                return
            value = self.client.kernel_write(path, str(before))
            self._record("restore-kernel", path, "restored" if value.get("ok") else "failed", value=before, after=value.get("after"))
            return
        if entry_type == "device_config":
            namespace = entry.get("namespace")
            key = entry.get("key")
            if result != "set" or not isinstance(namespace, str) or not isinstance(key, str):
                return
            before = entry.get("before")
            if self.dry_run:
                self._record("restore-device_config", "%s/%s" % (namespace, key), "planned", value=before)
                return
            if before is None or str(before).lower() == "null":
                self.client.device_config_delete(namespace, key)
                after = self.client.device_config_get(namespace, key)
                self._record("restore-device_config", "%s/%s" % (namespace, key), "deleted" if after is None else "failed")
            else:
                self.client.device_config_put(namespace, key, str(before))
                after = self.client.device_config_get(namespace, key)
                self._record("restore-device_config", "%s/%s" % (namespace, key), "restored" if after == str(before) else "failed", value=before, after=after)
            return
        if entry_type == "power":
            if result != "set":
                return
            before = entry.get("before")
            if before is None:
                self.warnings.append("cannot restore adaptive power saver: previous state was unknown")
                return
            if self.dry_run:
                self._record("restore-power", "adaptive-power-saver", "planned", value=before)
                return
            value = self.client.set_adaptive_power_saver(bool(before))
            self._record("restore-power", "adaptive-power-saver", "restored" if value.get("ok") else "failed", value=before, after=value.get("after"))
            return
        if entry_type == "fstrim":
            self.warnings.append("fstrim is a maintenance operation and cannot be undone (no data is removed)")
            return
        if entry_type == "cache":
            self.warnings.append("cache trims cannot be undone; apps rebuild caches automatically")
            return
        if entry_type in ("compile", "dexopt"):
            self.warnings.append("%s entries are not reversible; no action needed" % entry_type)
            return


def find_latest_journal(reports_dir: Path, serial: Optional[str] = None) -> Optional[Path]:
    candidates = sorted(reports_dir.glob("*-journal.json"), key=lambda p: p.stat().st_mtime, reverse=True)
    if serial:
        exact = [p for p in candidates if serial in p.name]
        if exact:
            return exact[0]
    return candidates[0] if candidates else None


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def add_common_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--adb", help="path to the adb executable (default: find adb on PATH)")
    parser.add_argument("--serial", help="device serial (required when more than one device is attached)")
    parser.add_argument("--timeout", type=int, default=60, help="default ADB command timeout in seconds (default: 60)")
    parser.add_argument("--retries", type=int, default=1, help="retries for transient ADB errors (default: 1)")
    parser.add_argument("--user", type=int, default=0, help="Android user id to operate on (default: 0)")


def add_profile_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--profile", choices=sorted(PROFILE_TIERS), default="balanced", help="optimization profile (default: balanced)")
    parser.add_argument("--dry-run", action="store_true", help="show what would change; never mutate the device")
    parser.add_argument("--yes", "-y", action="store_true", help="do not ask for confirmation")
    parser.add_argument("--no-settings", action="store_true", help="skip settings changes")
    parser.add_argument("--no-disable", action="store_true", help="skip package disabling")
    parser.add_argument("--no-cache-trim", action="store_true", help="skip cache trimming")
    parser.add_argument("--no-doze-cleanup", action="store_true", help="skip Doze whitelist cleanup")
    parser.add_argument("--cache-size", default=DEFAULT_CACHE_TRIM, help="pm trim-caches size argument (default: 999G)")
    parser.add_argument("--screen-timeout", type=int, default=DEFAULT_SCREEN_TIMEOUT_MS, help="screen-off timeout in ms (default: 60000)")
    parser.add_argument("--private-dns", choices=["off", "opportunistic", "hostname"], help="set Android Private DNS mode (opt-in)")
    parser.add_argument("--private-dns-host", help="hostname for --private-dns hostname")
    parser.add_argument("--restrict-unused", action="store_true", help="put unused third-party apps in the rare standby bucket (opt-in)")
    parser.add_argument("--unused-days", type=int, default=7, help="usage window for --restrict-unused (default: 7)")
    parser.add_argument("--compile", choices=["speed", "speed-profile", "verify", "quicken"], help="AOT-compile the launcher and keyboard after optimizing (opt-in)")
    parser.add_argument("--dexopt", action="store_true", help="start the background dexopt job (opt-in; can heat the phone)")
    parser.add_argument("--allow-risky", action="store_true", help="allow risky actions (required for the aggressive profile)")
    parser.add_argument("--allow-user-apps", action="store_true", help="allow disabling reviewed user-installed apps (off by default)")
    parser.add_argument("--profiles-file", help="JSON file with extra vendor package lists")
    parser.add_argument("--json", action="store_true", help="print the final report as JSON on stdout")
    parser.add_argument("--json-out", help="write the final report JSON to this path")
    parser.add_argument("--journal-out", help="write the rollback journal to this path")


def add_agent_options(parser: argparse.ArgumentParser) -> None:
    add_profile_options(parser)
    parser.add_argument("--provider", choices=sorted(PROVIDERS) + ["auto"], default="auto", help="LLM provider (default: auto-detect from environment)")
    parser.add_argument("--model", help="model id (default depends on provider; local servers auto-discover)")
    parser.add_argument("--base-url", help="override the provider API base URL")
    parser.add_argument("--api-key", help="API key (prefer an environment variable or --api-key-file)")
    parser.add_argument("--api-key-file", help="read the API key from a file")
    parser.add_argument("--temperature", type=float, default=0.1, help="sampling temperature (default: 0.1)")
    parser.add_argument("--max-tokens", type=int, default=1200, help="maximum model output tokens (default: 1200)")
    parser.add_argument("--llm-timeout", type=int, default=180, help="LLM request timeout in seconds (default: 180)")
    parser.add_argument("--max-steps", type=int, default=MAX_AGENT_STEPS, help="maximum agent steps (default: 6)")
    parser.add_argument("--agent-max-risk", choices=["safe", "moderate", "risky"], default="moderate", help="maximum risk the model may take (default: moderate)")
    parser.add_argument("--goal", default="Improve battery life, performance and privacy without uninstalling apps or breaking core functionality.", help="agent goal")
    parser.add_argument("--transcript", help="write the full agent transcript here")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="caop.py",
        description="CAOP - CYFARE's Android Optimizer Plus: safe, reversible ADB optimization with an optional LLM agent.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Examples:\n  python3 caop.py doctor\n  python3 caop.py optimize --profile balanced --dry-run\n  python3 caop.py optimize --profile balanced --yes\n  python3 caop.py compile --mode speed-profile --limit 10 --dry-run\n  python3 caop.py kernel\n  python3 caop.py agent --provider ollama --model qwen2.5:7b --yes\n",
    )
    parser.add_argument("--version", action="version", version="CAOP %s" % VERSION)
    parser.add_argument("--verbose", "-v", action="store_true", help="verbose logging")
    parser.add_argument("--debug", action="store_true", help="show tracebacks on failure")
    parser.add_argument("--no-color", action="store_true", help="disable ANSI colour")
    parser.add_argument("--reports-dir", default=DEFAULT_REPORTS_DIR, help="directory for reports and journals (default: caop-reports)")
    subparsers = parser.add_subparsers(dest="command", required=True)

    doctor = subparsers.add_parser("doctor", help="check ADB, device state, capabilities and provider setup")
    add_common_args(doctor)
    doctor.add_argument("--json", action="store_true", help="print JSON")
    doctor.add_argument("--provider", choices=sorted(PROVIDERS) + ["auto"], help="also report provider key availability")

    scan = subparsers.add_parser("scan", help="collect and print a device profile")
    add_common_args(scan)
    scan.add_argument("--json", action="store_true", help="print JSON instead of a human summary")
    scan.add_argument("--json-out", help="write the profile JSON to this path")
    scan.add_argument("--no-usage", action="store_true", help="skip usage-stats collection")
    scan.add_argument("--no-processes", action="store_true", help="skip process collection")
    scan.add_argument("--full-packages", action="store_true", help="include full package lists in JSON")
    scan.add_argument("--profiles-file", help="JSON file with extra vendor package lists")

    optimize = subparsers.add_parser("optimize", help="run the deterministic optimizer")
    add_common_args(optimize)
    add_profile_options(optimize)

    compile_cmd = subparsers.add_parser("compile", help="ART/dex2oat batch compilation of installed apps")
    add_common_args(compile_cmd)
    compile_cmd.add_argument("--mode", choices=["speed-profile", "speed", "verify", "quicken"], default="speed-profile", help="compiler filter (default: speed-profile)")
    compile_cmd.add_argument("--scope", choices=["third_party", "system", "all"], default="third_party", help="which packages to consider (default: third_party)")
    compile_cmd.add_argument("--limit", type=int, default=0, help="maximum packages to compile; 0 = all (default: 0)")
    compile_cmd.add_argument("--force", action="store_true", help="recompile even if the package is already at the target filter")
    compile_cmd.add_argument("--full", action="store_true", help="compile primary dex, secondary dex and dependencies")
    compile_cmd.add_argument("--reset", action="store_true", help="reset dexopt state (equivalent to verify; not a rollback of earlier compiles)")
    compile_cmd.add_argument("--include", help="comma-separated packages to force into the candidate set")
    compile_cmd.add_argument("--exclude", help="comma-separated packages to exclude")
    compile_cmd.add_argument("--min-battery", type=int, default=25, help="abort/skip below this battery percentage (default: 25)")
    compile_cmd.add_argument("--max-battery-temp", type=float, default=40.0, help="abort above this battery temperature in C (default: 40)")
    compile_cmd.add_argument("--max-thermal", type=int, default=2, help="abort above this thermal status 0-6 (default: 2)")
    compile_cmd.add_argument("--charging-only", action="store_true", help="only compile while charging")
    compile_cmd.add_argument("--compile-timeout", type=int, default=300, help="per-app timeout in seconds (default: 300)")
    compile_cmd.add_argument("--max-minutes", type=float, default=0.0, help="stop after this many minutes; 0 = no budget")
    compile_cmd.add_argument("--priority", choices=["PRIORITY_BOOT", "PRIORITY_INTERACTIVE_FAST", "PRIORITY_INTERACTIVE", "PRIORITY_BACKGROUND"], default="PRIORITY_BACKGROUND", help="dex2oat scheduling priority (default: BACKGROUND)")
    compile_cmd.add_argument("--dry-run", action="store_true", help="show the compile plan without compiling")
    compile_cmd.add_argument("--yes", "-y", action="store_true", help="do not ask for confirmation")
    compile_cmd.add_argument("--json", action="store_true", help="print JSON on stdout")
    compile_cmd.add_argument("--json-out", help="write the report JSON here")
    compile_cmd.add_argument("--journal-out", help="write the rollback/compile journal here")

    kernel_cmd = subparsers.add_parser("kernel", help="audit kernel tunables and optionally apply root-only governor changes")
    add_common_args(kernel_cmd)
    kernel_cmd.add_argument("--apply", action="store_true", help="apply governor changes (requires root and --allow-kernel)")
    kernel_cmd.add_argument("--profile", choices=["balanced", "performance", "battery"], default="balanced", help="governor profile (default: balanced)")
    kernel_cmd.add_argument("--allow-kernel", action="store_true", help="explicitly allow root-only kernel writes")
    kernel_cmd.add_argument("--dry-run", action="store_true", help="show the planned governor changes without writing")
    kernel_cmd.add_argument("--yes", "-y", action="store_true", help="do not ask for confirmation")
    kernel_cmd.add_argument("--json", action="store_true", help="print JSON on stdout")
    kernel_cmd.add_argument("--json-out", help="write the audit/report JSON here")
    kernel_cmd.add_argument("--journal-out", help="write the rollback journal here")

    boost = subparsers.add_parser("boost", help="trade battery for responsiveness using framework switches")
    add_common_args(boost)
    boost.add_argument("--profile", choices=["fast", "max"], default="fast", help="boost profile (default: fast)")
    boost.add_argument("--max-cached-processes", type=int, help="ActivityManager cached-process limit (default: RAM-based)")
    boost.add_argument("--no-freezer-off", action="store_true", help="keep the cached-app freezer enabled")
    boost.add_argument("--no-standby-off", action="store_true", help="keep app standby enabled")
    boost.add_argument("--no-adaptive-off", action="store_true", help="keep adaptive battery saver enabled")
    boost.add_argument("--fstrim", action="store_true", help="run sm fstrim after applying settings")
    boost.add_argument("--dry-run", action="store_true", help="show the boost plan without changing anything")
    boost.add_argument("--yes", "-y", action="store_true", help="do not ask for confirmation")
    boost.add_argument("--json", action="store_true", help="print JSON on stdout")
    boost.add_argument("--json-out", help="write the report JSON here")
    boost.add_argument("--journal-out", help="write the rollback journal here")

    rollback = subparsers.add_parser("rollback", help="revert changes recorded in a journal")
    add_common_args(rollback)
    rollback.add_argument("--journal", help="path to a journal JSON file")
    rollback.add_argument("--latest", action="store_true", help="use the newest journal in the reports directory")
    rollback.add_argument("--list", action="store_true", help="list available journals and exit")
    rollback.add_argument("--dry-run", action="store_true", help="show what would be reverted")
    rollback.add_argument("--yes", "-y", action="store_true", help="do not ask for confirmation")
    rollback.add_argument("--force", action="store_true", help="allow a journal from a different device serial")
    rollback.add_argument("--json", action="store_true", help="print JSON")

    providers = subparsers.add_parser("providers", help="list supported LLM providers and environment keys")
    providers.add_argument("--json", action="store_true", help="print JSON")

    profiles = subparsers.add_parser("profiles", help="list built-in vendor package profiles")
    profiles.add_argument("--profiles-file", help="JSON file with extra vendor package lists")
    profiles.add_argument("--json", action="store_true", help="print JSON")

    return parser


def split_csv(value: Optional[str]) -> List[str]:
    if not value:
        return []
    return [item.strip() for item in value.split(",") if item.strip()]


def load_extra_profiles(path: Optional[str]) -> Optional[Dict[str, Dict[str, Any]]]:
    if not path:
        return None
    try:
        data = read_json(Path(path))
    except (OSError, ValueError) as exc:
        raise ValidationError("could not read profiles file %s: %s" % (path, exc))
    if not isinstance(data, dict):
        raise ValidationError("profiles file must contain a JSON object")
    if "vendors" in data:
        data = data["vendors"]
    result: Dict[str, Dict[str, Any]] = {}
    for vendor, tiers in data.items():
        if not isinstance(tiers, dict):
            continue
        clean: Dict[str, Any] = {}
        for tier in ("conservative", "balanced", "aggressive"):
            values = tiers.get(tier, [])
            if not isinstance(values, list):
                continue
            clean[tier] = [str(item) for item in values if isinstance(item, str) and PACKAGE_RE.match(item)]
        result[str(vendor)] = clean
    return result


def make_client(args: argparse.Namespace) -> AdbClient:
    return AdbClient(adb=args.adb, serial=args.serial, timeout=args.timeout, retries=args.retries, user=args.user)


def make_options(args: argparse.Namespace, extra: Optional[Dict[str, Dict[str, Any]]] = None) -> OptimizerOptions:
    options = OptimizerOptions(
        profile=args.profile,
        dry_run=bool(getattr(args, "dry_run", False)),
        allow_risky=bool(getattr(args, "allow_risky", False)) or getattr(args, "agent_max_risk", "moderate") == "risky",
        allow_user_apps=bool(getattr(args, "allow_user_apps", False)),
        do_settings=not bool(getattr(args, "no_settings", False)),
        do_disable=not bool(getattr(args, "no_disable", False)),
        do_cache_trim=not bool(getattr(args, "no_cache_trim", False)),
        do_doze_cleanup=not bool(getattr(args, "no_doze_cleanup", False)),
        cache_size=getattr(args, "cache_size", DEFAULT_CACHE_TRIM),
        screen_timeout=getattr(args, "screen_timeout", DEFAULT_SCREEN_TIMEOUT_MS),
        private_dns_mode=getattr(args, "private_dns", None),
        private_dns_host=getattr(args, "private_dns_host", None),
        restrict_unused=bool(getattr(args, "restrict_unused", False)),
        unused_days=getattr(args, "unused_days", 7),
        compile_mode=getattr(args, "compile", None),
        dexopt=bool(getattr(args, "dexopt", False)),
        extra_profiles=extra,
    )
    options.validate()
    return options


def journal_path_for(args: argparse.Namespace, profile: Dict[str, Any], kind: str) -> Path:
    if getattr(args, "journal_out", None):
        return Path(args.journal_out)
    serial = re.sub(r"[^A-Za-z0-9._-]", "_", str(profile.get("serial") or "device"))
    stamp = _dt.datetime.now().strftime("%Y%m%d-%H%M%S")
    return Path(getattr(args, "reports_dir", DEFAULT_REPORTS_DIR)) / ("%s-%s-%s-journal.json" % (serial, stamp, kind))


def save_report(args: argparse.Namespace, report: Dict[str, Any], kind: str, profile: Dict[str, Any]) -> Optional[Path]:
    explicit = getattr(args, "json_out", None)
    if explicit:
        path = Path(explicit)
    else:
        serial = re.sub(r"[^A-Za-z0-9._-]", "_", str(profile.get("serial") or "device"))
        stamp = _dt.datetime.now().strftime("%Y%m%d-%H%M%S")
        path = Path(getattr(args, "reports_dir", DEFAULT_REPORTS_DIR)) / ("%s-%s-%s.json" % (serial, stamp, kind))
    write_json(path, report)
    return path


def cmd_doctor(args: argparse.Namespace) -> int:
    client = make_client(args)
    client.ensure_device()
    profile = collect_profile(client, include_usage=False, include_processes=False)
    provider_status = None
    if args.provider:
        provider_status = []
        for name, spec in PROVIDERS.items():
            key = os.environ.get(spec.get("env", ""))
            provider_status.append({"provider": name, "env": spec.get("env"), "key_present": bool(key), "base": spec.get("base"), "default_model": spec.get("model")})
    if args.json:
        print(pretty_json({"device": profile.get("device"), "capabilities": profile.get("capabilities"), "warnings": profile.get("warnings"), "providers": provider_status}))
        return 0
    print_profile_summary(profile)
    if provider_status is not None:
        print("%sProviders%s" % (_COLORS.bold, _COLORS.reset))
        for item in provider_status:
            print("  %-12s env=%-22s key=%s" % (item["provider"], item["env"], "present" if item["key_present"] else "missing"))
    return 0


def cmd_scan(args: argparse.Namespace) -> int:
    client = make_client(args)
    client.ensure_device()
    extra = load_extra_profiles(args.profiles_file)
    profile = collect_profile(client, include_usage=not args.no_usage,
                              include_processes=not args.no_processes,
                              full_packages=args.full_packages, extra=extra)
    if args.json_out:
        write_json(Path(args.json_out), profile)
        log_ok("profile written to %s" % args.json_out)
    if args.json:
        print(pretty_json(profile))
    else:
        print_profile_summary(profile)
        if args.json_out:
            print("  profile file: %s" % args.json_out)
    return 0


def cmd_optimize(args: argparse.Namespace) -> int:
    if not args.dry_run and not args.yes and not sys.stdin.isatty():
        raise SafetyError("non-interactive optimize needs --yes (or use --dry-run)")
    client = make_client(args)
    client.ensure_device()
    extra = load_extra_profiles(args.profiles_file)
    profile = collect_profile(client, include_usage=True, include_processes=True, extra=extra)
    options = make_options(args, extra)
    journal_path = journal_path_for(args, profile, "optimize")
    journal = Journal(profile.get("device", {}), path=journal_path, enabled=not args.dry_run)
    optimizer = Optimizer(client, profile, options, journal)
    plan = optimizer.preview()
    if not args.json:
        print_profile_summary(profile)
        optimizer.print_plan(plan)
    if plan["packages"] or plan["settings"] or plan["doze"] or plan["cache_trim"]:
        if not args.dry_run and not args.yes:
            if not confirm("Apply this plan to %s?" % client.serial, assume_yes=False):
                log_warn("cancelled")
                return 0
    else:
        log_info("no changes are needed for this profile")
        if not args.dry_run:
            return 0
    try:
        summary = optimizer.execute()
    finally:
        # Persist whatever was actually changed even if a later action failed.
        if not args.dry_run:
            journal.save()
    report = {
        "version": VERSION,
        "kind": "optimize",
        "generated_at": now_iso(),
        "device": profile.get("device"),
        "serial": profile.get("serial"),
        "vendor": profile.get("vendor"),
        "profile": args.profile,
        "dry_run": args.dry_run,
        "plan": plan,
        "summary": summary,
        "journal": str(journal_path) if not args.dry_run else None,
    }
    report_path = save_report(args, report, "optimize", profile)
    if not args.json:
        print_run_summary(summary)
        if report_path:
            print("  report: %s" % report_path)
        if not args.dry_run:
            print("  journal: %s" % journal_path)
    else:
        print(pretty_json(report))
    return 0


def cmd_agent(args: argparse.Namespace) -> int:
    if not args.dry_run and not args.yes and not sys.stdin.isatty():
        raise SafetyError("agent mode needs --yes when stdin is not a terminal (or use --dry-run)")
    if args.allow_risky:
        args.agent_max_risk = "risky"
    args.max_steps = max(1, int(args.max_steps))
    config = resolve_provider_config(args)
    log_info("LLM provider: %s  model: %s" % (config["name"], config.get("model") or "(discover)"))
    llm = LLMClient(config)
    log_info("using model: %s" % llm.model)
    client = make_client(args)
    client.ensure_device()
    extra = load_extra_profiles(args.profiles_file)
    profile = collect_profile(client, include_usage=True, include_processes=True, extra=extra)
    options = make_options(args, extra)
    journal_path = journal_path_for(args, profile, "agent")
    journal = Journal(profile.get("device", {}), path=journal_path, enabled=not args.dry_run)
    if not args.transcript:
        serial = re.sub(r"[^A-Za-z0-9._-]", "_", str(profile.get("serial") or "device"))
        stamp = _dt.datetime.now().strftime("%Y%m%d-%H%M%S")
        args.transcript = str(Path(args.reports_dir) / ("%s-%s-agent-transcript.json" % (serial, stamp)))
    agent = AndroidAgent(client, profile, llm, options, journal, args)
    try:
        result = agent.run()
    finally:
        # Keep rollback coverage when the provider or a tool fails mid-run.
        if not args.dry_run:
            journal.save()
    report = {
        "version": VERSION,
        "kind": "agent",
        "generated_at": now_iso(),
        "device": profile.get("device"),
        "serial": profile.get("serial"),
        "provider": llm.name,
        "model": llm.model,
        "dry_run": args.dry_run,
        "result": result,
        "journal": str(journal_path) if not args.dry_run else None,
    }
    report_path = save_report(args, report, "agent", profile)
    if args.json:
        print(pretty_json(report))
    else:
        print("%sAgent finished%s" % (_COLORS.bold, _COLORS.reset))
        print("  stop reason: %s" % result.get("stop_reason"))
        print("  steps: %s   actions: %s" % (len(result.get("steps", [])), result.get("actions_executed")))
        if result.get("finish_summary"):
            print("  summary: %s" % result["finish_summary"])
        if result.get("transcript"):
            print("  transcript: %s" % result["transcript"])
        if report_path:
            print("  report: %s" % report_path)
        if not args.dry_run:
            print("  journal: %s" % journal_path)
    return 0


def cmd_compile(args: argparse.Namespace) -> int:
    if not args.dry_run and not args.yes and not sys.stdin.isatty():
        raise SafetyError("non-interactive compile needs --yes (or use --dry-run)")
    client = make_client(args)
    client.ensure_device()
    profile = collect_profile(client, include_usage=True, include_processes=False)
    options = CompileOptions(
        mode=args.mode,
        scope=args.scope,
        limit=args.limit,
        force=args.force,
        full=args.full,
        include=split_csv(args.include),
        exclude=split_csv(args.exclude),
        min_battery=args.min_battery,
        max_battery_temp=args.max_battery_temp,
        max_thermal_status=args.max_thermal,
        charging_only=args.charging_only,
        timeout=args.compile_timeout,
        max_minutes=args.max_minutes,
        priority=args.priority,
        reset=args.reset,
        dry_run=args.dry_run,
        yes=args.yes,
    )
    options.validate()
    journal_path = journal_path_for(args, profile, "compile")
    journal = Journal(profile.get("device", {}), path=journal_path, enabled=not args.dry_run)
    compiler = Compiler(client, profile, options, journal)
    plan = compiler.plan()
    environment = compiler.check_environment()
    if not args.json:
        compiler.print_plan(plan, environment)
    if not args.dry_run and not environment.get("ok"):
        raise SafetyError("refusing to compile: %s" % "; ".join(environment.get("issues", [])))
    if not args.dry_run and not args.yes:
        if not confirm("Compile %d package(s) on %s?" % (len(plan.get("targets", [])), client.serial), assume_yes=False):
            log_warn("cancelled")
            return 0
    if not plan.get("targets"):
        log_info("no packages need %s compilation" % options.mode)
        if args.json:
            print(pretty_json({
                "version": VERSION, "kind": "compile", "generated_at": now_iso(),
                "device": profile.get("device"), "serial": profile.get("serial"),
                "plan": plan, "environment": environment, "summary": None,
            }))
        return 0
    try:
        summary = compiler.execute()
    finally:
        if not args.dry_run:
            journal.save()
    report = {
        "version": VERSION,
        "kind": "compile",
        "generated_at": now_iso(),
        "device": profile.get("device"),
        "serial": profile.get("serial"),
        "options": {
            "mode": options.mode, "scope": options.scope, "limit": options.limit,
            "force": options.force, "full": options.full, "reset": options.reset,
            "include": options.include, "exclude": options.exclude,
        },
        "environment": environment,
        "plan": plan,
        "summary": summary,
        "journal": str(journal_path) if not args.dry_run else None,
    }
    report_path = save_report(args, report, "compile", profile)
    if args.json:
        print(pretty_json(report))
    else:
        print_compile_summary(summary)
        if report_path:
            print("  report: %s" % report_path)
        if not args.dry_run:
            print("  journal: %s" % journal_path)
    return 0


def cmd_kernel(args: argparse.Namespace) -> int:
    if args.apply and not args.dry_run and not args.yes and not sys.stdin.isatty():
        raise SafetyError("non-interactive kernel apply needs --yes (or use --dry-run)")
    client = make_client(args)
    client.ensure_device()
    profile = collect_profile(client, include_usage=False, include_processes=False)
    journal_path = journal_path_for(args, profile, "kernel")
    journal = Journal(profile.get("device", {}), path=journal_path, enabled=not args.dry_run)
    tuner = KernelTuner(client, profile, journal)
    audit = tuner.audit()
    plan = None
    summary = None
    if args.apply:
        if not args.allow_kernel:
            raise SafetyError("kernel writes require --allow-kernel")
        if not audit.get("root"):
            raise SafetyError("kernel writes require root; this device has no root/su (bootloader locked=%s, verified boot=%s)" % (
                audit.get("bootloader_locked"), audit.get("verified_boot")))
        plan = tuner.plan(args.profile)
        if not args.json:
            print_kernel_audit(audit)
            print("%sKernel plan (%s)%s" % (_COLORS.bold, args.profile, _COLORS.reset))
            for item in plan.get("targets", []):
                print("  - %s: %s -> %s" % (item["path"], item.get("before"), item["after"]))
            if not plan.get("targets"):
                print("  no governor changes needed/available")
        if not args.dry_run and plan.get("targets"):
            if not confirm("Apply kernel governor changes?", assume_yes=False):
                log_warn("cancelled")
                return 0
        summary = tuner.apply(args.profile, dry_run=args.dry_run)
    report = {
        "version": VERSION,
        "kind": "kernel",
        "generated_at": now_iso(),
        "device": profile.get("device"),
        "serial": profile.get("serial"),
        "profile": args.profile,
        "apply": bool(args.apply),
        "dry_run": bool(args.dry_run),
        "audit": audit,
        "plan": plan,
        "summary": summary,
        "journal": str(journal_path) if args.apply and not args.dry_run else None,
    }
    report_path = save_report(args, report, "kernel", profile)
    if args.json:
        print(pretty_json(report))
    else:
        if not args.apply:
            print_kernel_audit(audit)
        if summary:
            print("%sKernel %s%s" % (_COLORS.bold, "DRY-RUN" if args.dry_run else "APPLIED", _COLORS.reset))
            print("  applied: %s   failed: %s   skipped: %s" % (
                len(summary.get("applied", [])), len(summary.get("failed", [])), len(summary.get("skipped", []))))
            for warning in summary.get("warnings", []):
                print("  [!] %s" % warning)
        if report_path:
            print("  report: %s" % report_path)
        if args.apply and not args.dry_run:
            print("  journal: %s" % journal_path)
    return 0


def cmd_boost(args: argparse.Namespace) -> int:
    if not args.dry_run and not args.yes and not sys.stdin.isatty():
        raise SafetyError("non-interactive boost needs --yes (or use --dry-run)")
    client = make_client(args)
    client.ensure_device()
    profile = collect_profile(client, include_usage=False, include_processes=False)
    options = BoostOptions(
        profile=args.profile,
        max_cached_processes=args.max_cached_processes,
        freezer_off=not args.no_freezer_off,
        standby_off=not args.no_standby_off,
        adaptive_saver_off=not args.no_adaptive_off,
        fstrim=args.fstrim,
        dry_run=args.dry_run,
        yes=args.yes,
    )
    options.validate()
    journal_path = journal_path_for(args, profile, "boost")
    journal = Journal(profile.get("device", {}), path=journal_path, enabled=not args.dry_run)
    tuner = BoostTuner(client, profile, options, journal)
    plan = tuner.plan()
    if not args.json:
        tuner.print_plan(plan)
    if not args.dry_run and not args.yes:
        if not confirm("Apply boost settings on %s?" % client.serial, assume_yes=False):
            log_warn("cancelled")
            return 0
    try:
        summary = tuner.execute()
    finally:
        if not args.dry_run:
            journal.save()
    report = {
        "version": VERSION,
        "kind": "boost",
        "generated_at": now_iso(),
        "device": profile.get("device"),
        "serial": profile.get("serial"),
        "profile": args.profile,
        "dry_run": args.dry_run,
        "plan": plan,
        "summary": summary,
        "journal": str(journal_path) if not args.dry_run else None,
    }
    report_path = save_report(args, report, "boost", profile)
    if args.json:
        print(pretty_json(report))
    else:
        print_boost_summary(summary)
        if report_path:
            print("  report: %s" % report_path)
        if not args.dry_run:
            print("  journal: %s" % journal_path)
    return 0


def cmd_rollback(args: argparse.Namespace) -> int:
    reports_dir = Path(args.reports_dir)
    if args.list:
        paths = sorted(reports_dir.glob("*-journal.json"), key=lambda p: p.stat().st_mtime, reverse=True) if reports_dir.exists() else []
        if args.json:
            print(pretty_json([str(p) for p in paths]))
        else:
            if not paths:
                print("No journals found in %s" % reports_dir)
            for path in paths:
                print(path)
        return 0
    path: Optional[Path] = Path(args.journal) if args.journal else None
    if path is None:
        path = find_latest_journal(reports_dir, args.serial)
    if path is None or not path.exists():
        raise JournalError("no journal found; pass --journal PATH or use --list")
    journal = Journal.load(path)
    client = make_client(args)
    client.ensure_device()
    rollbacker = Rollbacker(client, journal, dry_run=args.dry_run, assume_yes=args.yes, force=args.force)
    result = rollbacker.run()
    if args.json:
        print(pretty_json(result))
    else:
        print("%s%s%s" % (_COLORS.bold, "Rollback", _COLORS.reset))
        for action in result.get("actions", []):
            symbol = "ok" if action.get("result") in ("enabled", "restored", "deleted", "unsuspended", "planned") else "skip/fail"
            print("  [%s] %s %s %s" % (symbol, action.get("action"), action.get("target"), action.get("result")))
        for warning in result.get("warnings", []):
            print("  [!] %s" % warning)
        print("  journal: %s" % path)
    return 0


def cmd_providers(args: argparse.Namespace) -> int:
    rows = []
    for name, spec in sorted(PROVIDERS.items()):
        key = os.environ.get(spec.get("env", ""))
        rows.append({
            "provider": name,
            "env": spec.get("env"),
            "key_present": bool(key),
            "base": spec.get("base"),
            "default_model": spec.get("model"),
            "local": bool(spec.get("local")),
            "style": spec.get("style"),
        })
    if args.json:
        print(pretty_json(rows))
        return 0
    for row in rows:
        print("%-12s %-18s %s  %s" % (row["provider"], row["env"], "key" if row["key_present"] else "   ", row["base"] or "(custom)"))
        print("             default model: %s%s" % (row["default_model"], "  [local]" if row["local"] else ""))
    print("\nSet the environment variable or use --api-key/--api-key-file. Local providers do not require a key.")
    return 0


def cmd_profiles(args: argparse.Namespace) -> int:
    extra = load_extra_profiles(args.profiles_file)
    data: Dict[str, Any] = {}
    for vendor, spec in sorted(VENDOR_PROFILES.items()):
        data[vendor] = {
            "name": spec.get("name"),
            "conservative": len(tier_packages(vendor, "conservative", extra)),
            "balanced": len(tier_packages(vendor, "balanced", extra)),
            "aggressive": len(tier_packages(vendor, "aggressive", extra)),
        }
    if extra:
        for vendor in sorted(extra):
            data.setdefault(vendor, {"name": "custom: %s" % vendor})
            for tier in ("conservative", "balanced", "aggressive"):
                data[vendor][tier] = len(tier_packages(vendor, tier, extra))
    if args.json:
        print(pretty_json(data))
        return 0
    for vendor, counts in data.items():
        print("%-12s %-48s conservative=%s balanced=%s aggressive=%s" % (
            vendor, counts.get("name", ""), counts.get("conservative", 0), counts.get("balanced", 0), counts.get("aggressive", 0)))
    return 0


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    setup_logging(verbose=args.verbose, no_color=args.no_color)
    try:
        if args.command == "doctor":
            return cmd_doctor(args)
        if args.command == "scan":
            return cmd_scan(args)
        if args.command == "optimize":
            return cmd_optimize(args)
        if args.command == "agent":
            return cmd_agent(args)
        if args.command == "compile":
            return cmd_compile(args)
        if args.command == "kernel":
            return cmd_kernel(args)
        if args.command == "boost":
            return cmd_boost(args)
        if args.command == "rollback":
            return cmd_rollback(args)
        if args.command == "providers":
            return cmd_providers(args)
        if args.command == "profiles":
            return cmd_profiles(args)
        parser.error("unknown command")
        return 2
    except KeyboardInterrupt:
        log_warn("interrupted")
        return 130
    except DeviceError as exc:
        log_error(str(exc))
        return 3
    except ProviderError as exc:
        log_error(str(exc))
        return 4
    except SafetyError as exc:
        log_error(str(exc))
        return 5
    except JournalError as exc:
        log_error(str(exc))
        return 6
    except OptimizerError as exc:
        log_error(str(exc))
        if args.debug:
            raise
        return 1
    except Exception as exc:
        log_error("unexpected error: %s" % exc)
        if args.debug:
            raise
        return 1


if __name__ == "__main__":
    sys.exit(main())
