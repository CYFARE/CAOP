#!/usr/bin/env python3
"""Pure unit tests for CAOP's profile, risk, JSON and safety logic."""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import caop


class ProfileTests(unittest.TestCase):
    def test_tiers_are_not_cumulative(self):
        conservative = caop.tier_packages("oneplus", "conservative")
        aggressive = caop.tier_packages("oneplus", "aggressive")
        self.assertIn("com.oplus.dmp", conservative)
        self.assertNotIn("com.oplus.aiunit", conservative)
        self.assertIn("com.oplus.aiunit", aggressive)

    def test_profile_is_cumulative(self):
        packages = caop.profile_packages("oneplus", "balanced")
        self.assertIn("com.oplus.dmp", packages)       # conservative
        self.assertIn("com.oplus.cast", packages)      # balanced
        self.assertNotIn("com.oplus.aiunit", packages)  # aggressive

    def test_risk_uses_lowest_tier(self):
        self.assertEqual(caop.package_tier_risk("com.oplus.dmp", "oneplus")[1], "safe")
        self.assertEqual(caop.package_tier_risk("com.oplus.cast", "oneplus")[1], "moderate")
        self.assertEqual(caop.package_tier_risk("com.oplus.aiunit", "oneplus")[1], "risky")
        self.assertEqual(caop.package_tier_risk("com.example.unknown", "oneplus")[0], "unknown")

    def test_critical_packages(self):
        critical = caop.build_critical_set({"launcher": "com.android.launcher/.Launcher"})
        self.assertTrue(caop.is_critical_package("com.android.launcher3", critical))
        self.assertTrue(caop.is_critical_package("com.google.android.gms", critical))
        self.assertTrue(caop.is_critical_package("com.android.systemui", critical))
        self.assertFalse(caop.is_critical_package("com.oplus.aiunit", critical))

    def test_custom_profiles_extend_builtins(self):
        extra = {"oneplus": {"conservative": ["com.example.custom"], "balanced": [], "aggressive": []}}
        packages = caop.tier_packages("oneplus", "conservative", extra)
        self.assertIn("com.oplus.dmp", packages)
        self.assertIn("com.example.custom", packages)

    def test_communication_packages(self):
        self.assertTrue(caop.is_communication_package("com.whatsapp"))
        self.assertTrue(caop.is_communication_package("org.telegram.messenger"))
        self.assertTrue(caop.is_communication_package("com.truecaller"))
        self.assertFalse(caop.is_communication_package("com.oplus.aimemory"))


class JsonTests(unittest.TestCase):
    def test_plain_json(self):
        value = caop.extract_json_object('{"done": true, "actions": []}')
        self.assertTrue(value["done"])

    def test_fenced_json(self):
        value = caop.extract_json_object('```json\n{"done": false, "actions": []}\n```')
        self.assertFalse(value["done"])

    def test_json_with_prose(self):
        value = caop.extract_json_object('Here is the plan: {"done": true, "actions": []} thanks')
        self.assertTrue(value["done"])

    def test_invalid_json(self):
        with self.assertRaises(caop.ValidationError):
            caop.extract_json_object("not json at all")


class CompileTests(unittest.TestCase):
    DEXOPT_SAMPLE = """Dexopt state:
  [com.example.verify]
    path: /data/app/example/base.apk
      arm64: [status=verify] [reason=vdex] [primary-abi]
        [location is /data/app/example/oat/arm64/base.vdex]
  [com.example.compiled]
    path: /data/app/compiled/base.apk
      arm64: [status=speed] [reason=bg-dexopt] [primary-abi]
        [location is /data/app/compiled/oat/arm64/base.odex]
  [com.example.profile]
      arm64: [status=speed-profile] [reason=install] [primary-abi]
"""

    def test_parse_dexopt_state(self):
        state = caop.parse_dexopt_state(self.DEXOPT_SAMPLE)
        self.assertEqual(state["com.example.verify"]["status"], "verify")
        self.assertEqual(state["com.example.compiled"]["status"], "speed")
        self.assertEqual(state["com.example.profile"]["status"], "speed-profile")
        self.assertEqual(state["com.example.compiled"]["path"], "/data/app/compiled/base.apk")

    def test_parse_package_dexopt(self):
        status = caop.parse_package_dexopt(self.DEXOPT_SAMPLE)
        self.assertEqual(status["status"], "verify")

    def test_compile_rank(self):
        self.assertTrue(caop.dexopt_at_least("speed", "speed-profile"))
        self.assertTrue(caop.dexopt_at_least("speed-profile", "speed-profile"))
        self.assertFalse(caop.dexopt_at_least("verify", "speed"))
        self.assertFalse(caop.dexopt_at_least(None, "verify"))

    def test_compile_options_reject_bad_values(self):
        with self.assertRaises(caop.ValidationError):
            caop.CompileOptions(mode="everything").validate()
        with self.assertRaises(caop.ValidationError):
            caop.CompileOptions(scope="everything").validate()
        with self.assertRaises(caop.ValidationError):
            caop.CompileOptions(min_battery=101).validate()

    def test_kernel_paths_are_allowlisted(self):
        cpu = "/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor"
        vm = "/proc/sys/vm/swappiness"
        self.assertTrue(any(pattern.match(cpu) for pattern in caop.KERNEL_WRITE_PATTERNS))
        self.assertFalse(any(pattern.match(vm) for pattern in caop.KERNEL_WRITE_PATTERNS))


class BoostTests(unittest.TestCase):
    def test_default_cached_processes(self):
        gib = 1024 ** 3
        self.assertEqual(caop.default_cached_processes(12 * gib, "fast"), 48)
        self.assertEqual(caop.default_cached_processes(12 * gib, "max"), 64)
        self.assertEqual(caop.default_cached_processes(8 * gib, "fast"), 32)
        self.assertEqual(caop.default_cached_processes(4 * gib, "max"), 24)

    def test_boost_options_validation(self):
        with self.assertRaises(caop.ValidationError):
            caop.BoostOptions(profile="turbo").validate()
        with self.assertRaises(caop.ValidationError):
            caop.BoostOptions(max_cached_processes=8).validate()


class SafetyTests(unittest.TestCase):
    def test_aggressive_requires_allow_risky(self):
        options = caop.OptimizerOptions(profile="aggressive", allow_risky=False)
        with self.assertRaises(caop.SafetyError):
            options.validate()

    def test_bad_cache_size(self):
        options = caop.OptimizerOptions(cache_size="999G; reboot")
        with self.assertRaises(caop.ValidationError):
            options.validate()

    def test_bad_screen_timeout(self):
        options = caop.OptimizerOptions(screen_timeout=1000)
        with self.assertRaises(caop.ValidationError):
            options.validate()

    def test_private_dns_requires_host(self):
        options = caop.OptimizerOptions(private_dns_mode="hostname")
        with self.assertRaises(caop.ValidationError):
            options.validate()

    def test_private_dns_valid(self):
        caop.OptimizerOptions(private_dns_mode="hostname", private_dns_host="dns.google").validate()

    def test_json_output_has_no_secret(self):
        text = '{"error":"Authorization: Bearer sk-abcdef123456789"}'
        redacted = caop.redact_secrets(text, ["sk-abcdef123456789"])
        self.assertNotIn("sk-abcdef123456789", redacted)
        self.assertIn("REDACTED", redacted)


if __name__ == "__main__":
    unittest.main()
