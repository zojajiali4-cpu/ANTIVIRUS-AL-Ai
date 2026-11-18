import unittest
import xml.etree.ElementTree as ET
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RES = ROOT / "app" / "src" / "main" / "res"
ANDROID_NS = "{http://schemas.android.com/apk/res/android}"


class AndroidReleaseInvariantTests(unittest.TestCase):
    def test_launcher_icon_is_declared_and_resolvable(self):
        manifest = ET.parse(ROOT / "app/src/main/AndroidManifest.xml").getroot()
        application = manifest.find("application")
        self.assertIsNotNone(application, "AndroidManifest.xml must declare an application")

        self.assertEqual("@mipmap/ic_launcher", application.get(ANDROID_NS + "icon"))
        self.assertEqual("@mipmap/ic_launcher", application.get(ANDROID_NS + "roundIcon"))

        launcher_activity_found = False
        for activity in application.findall("activity"):
            for intent_filter in activity.findall("intent-filter"):
                actions = {node.get(ANDROID_NS + "name") for node in intent_filter.findall("action")}
                categories = {node.get(ANDROID_NS + "name") for node in intent_filter.findall("category")}
                if "android.intent.action.MAIN" in actions and "android.intent.category.LAUNCHER" in categories:
                    launcher_activity_found = True
        self.assertTrue(launcher_activity_found, "The app must retain a MAIN/LAUNCHER activity")

        adaptive_path = RES / "mipmap-anydpi-v26" / "ic_launcher.xml"
        fallback_path = RES / "mipmap-anydpi" / "ic_launcher.xml"
        foreground_path = RES / "drawable" / "launcher_icon_foreground.xml"
        legacy_path = RES / "drawable" / "launcher_icon_legacy.xml"
        artwork_path = RES / "drawable" / "guardian_robot.webp"
        colors_path = RES / "values" / "launcher_colors.xml"

        for path in (adaptive_path, fallback_path, foreground_path, legacy_path, artwork_path, colors_path):
            with self.subTest(path=str(path)):
                self.assertTrue(path.is_file(), f"Required launcher asset is missing: {path.relative_to(ROOT)}")
                self.assertGreater(path.stat().st_size, 0, f"Launcher asset is empty: {path.relative_to(ROOT)}")

        adaptive = ET.parse(adaptive_path).getroot()
        self.assertTrue(adaptive.tag.endswith("adaptive-icon"))
        self.assertEqual("@drawable/launcher_icon_foreground", adaptive.find("foreground").get(ANDROID_NS + "drawable"))
        self.assertEqual("@color/launcher_icon_background", adaptive.find("background").get(ANDROID_NS + "drawable"))

        fallback = ET.parse(fallback_path).getroot()
        fallback_refs = {node.get(ANDROID_NS + "drawable") for node in fallback.findall("item")}
        self.assertIn("@drawable/launcher_icon_foreground", fallback_refs)
        self.assertIn("@color/launcher_icon_background", fallback_refs)

        foreground = ET.parse(foreground_path).getroot()
        self.assertEqual("@drawable/guardian_robot", foreground.get(ANDROID_NS + "drawable"))

        legacy = ET.parse(legacy_path).getroot()
        legacy_refs = {node.get(ANDROID_NS + "drawable") for node in legacy.findall("item")}
        self.assertIn("@drawable/launcher_icon_foreground", legacy_refs)
        self.assertIn("@color/launcher_icon_background", legacy_refs)

    def test_core_scanner_and_protection_components_are_present(self):
        required = (
            "app/src/main/java/com/antivirusalai/AntivirusApplication.kt",
            "app/src/main/java/com/antivirusalai/ProtectionService.kt",
            "app/src/main/java/com/antivirusalai/engine/DeviceScanEngine.kt",
            "app/src/main/java/com/antivirusalai/engine/ScanEngine.kt",
            "app/src/main/java/com/antivirusalai/engine/ScanReportStore.kt",
            "app/src/main/java/com/antivirusalai/engine/FormatStaticAnalyzer.kt",
            "app/src/main/java/com/antivirusalai/engine/OnDeviceMlScorer.kt",
            "app/src/main/java/com/antivirusalai/remediation/QuarantineVault.kt",
            "app/src/main/java/com/antivirusalai/intel/ThreatFeedRuntime.kt",
        )
        for relative in required:
            with self.subTest(path=relative):
                self.assertTrue((ROOT / relative).is_file(), f"Core product component is missing: {relative}")

    def test_store_vault_and_consent_based_cloud_lookup_stay_wired(self):
        app_source = (ROOT / "app/src/main/java/com/antivirusalai/AntivirusApp.kt").read_text(encoding="utf-8")
        self.assertIn('STORE("store")', app_source)
        self.assertIn('VAULT("vault")', app_source)
        self.assertIn("CloudHashReputationCard(result = it, fa = fa)", app_source)

        self.assertTrue((ROOT / "app/src/main/java/com/antivirusalai/CloudThreatApi.kt").is_file())
        self.assertTrue((ROOT / "app/src/main/java/com/antivirusalai/CloudHashReputationCard.kt").is_file())
        self.assertTrue((ROOT / "cloud-api/src/index.js").is_file())
        self.assertTrue((ROOT / "cloud-api/test/worker.test.js").is_file())


    def test_offline_url_inspection_stays_local_and_visible(self):
        app_source = (ROOT / "app/src/main/java/com/antivirusalai/AntivirusApp.kt").read_text(encoding="utf-8")
        analyzer = (ROOT / "app/src/main/java/com/antivirusalai/security/UrlRiskAnalyzer.kt").read_text(encoding="utf-8")
        card = (ROOT / "app/src/main/java/com/antivirusalai/LocalUrlRiskCard.kt").read_text(encoding="utf-8")

        self.assertIn("LocalUrlRiskCard(fa = fa)", app_source)
        self.assertIn("UrlRiskAnalyzer.analyze(address)", card)
        self.assertIn("never opens, resolves, or contacts the supplied URL", analyzer)
        self.assertIn("not a phishing verdict", analyzer)

if __name__ == "__main__":
    unittest.main()
