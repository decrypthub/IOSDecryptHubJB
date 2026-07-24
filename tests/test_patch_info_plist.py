from __future__ import annotations

import plistlib
import tempfile
import unittest
from pathlib import Path

from tools.patch_info_plist import SERVICE_TYPE, patch_info_plist


class PatchInfoPlistTests(unittest.TestCase):
    def test_preserves_existing_values_and_format(self) -> None:
        for output_format in (plistlib.FMT_XML, plistlib.FMT_BINARY):
            with self.subTest(output_format=output_format):
                with tempfile.TemporaryDirectory() as directory:
                    path = Path(directory) / "Info.plist"
                    original = {
                        "CFBundleIdentifier": "com.example.app",
                        "NSLocalNetworkUsageDescription": "宿主已有说明",
                        "NSBonjourServices": ["_existing._tcp."],
                    }
                    path.write_bytes(plistlib.dumps(original, fmt=output_format, sort_keys=False))

                    self.assertTrue(patch_info_plist(path))
                    updated = plistlib.loads(path.read_bytes())
                    self.assertEqual(updated["NSLocalNetworkUsageDescription"], "宿主已有说明")
                    self.assertEqual(
                        updated["NSBonjourServices"], ["_existing._tcp.", SERVICE_TYPE]
                    )
                    self.assertEqual(
                        path.read_bytes().startswith(b"bplist"),
                        output_format == plistlib.FMT_BINARY,
                    )
                    self.assertFalse(patch_info_plist(path))

    def test_adds_missing_keys(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "Info.plist"
            path.write_bytes(plistlib.dumps({"CFBundleIdentifier": "com.example.app"}))
            self.assertTrue(patch_info_plist(path))
            updated = plistlib.loads(path.read_bytes())
            self.assertTrue(updated["NSLocalNetworkUsageDescription"])
            self.assertEqual(updated["NSBonjourServices"], [SERVICE_TYPE])


if __name__ == "__main__":
    unittest.main()

