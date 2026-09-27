"""Cockpit 导入纯转换、预检和实际写入回归。"""
import hashlib
import json
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch

from qoder_accounts import Account, AccountPool, _coerce_account_rows, normalise_import_row, normalize_epoch


class CockpitImportTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.pool = AccountPool(self.temp.name)

    def row(self, uid="cockpit", **fields):
        raw = {"id": uid, "token": " token-secret ", "refreshToken": "refresh-secret",
               "name": "Name", "expireTime": int(time.time() + 3600) * 1000}
        raw.update(fields)
        return {"auth_user_info_raw": raw}

    def hashes(self):
        return {str(p.relative_to(self.temp.name)): hashlib.sha256(p.read_bytes()).hexdigest()
                for p in Path(self.temp.name).rglob("*") if p.is_file()}

    def test_containers_and_raw_json_string(self):
        row = self.row()
        for container in (row, [row], {"accounts": [row]}):
            rows, error = _coerce_account_rows(container)
            self.assertFalse(error)
            self.assertEqual(len(rows), 1)
        parsed = normalise_import_row(row, realm="cn")
        row["auth_user_info_raw"] = json.dumps(row["auth_user_info_raw"])
        self.assertEqual(parsed, normalise_import_row(row, realm="cn"))
        self.assertEqual(parsed["accessToken"], "token-secret")
        self.assertLess(parsed["expiresAt"], 1e11)

    def test_priority_and_fallback(self):
        row = self.row()
        row.update(user_id="fallback", display_name="Fallback")
        self.assertEqual(normalise_import_row(row, realm="intl")["uid"], "cockpit")
        row["auth_user_info_raw"].update(id=" ", name="")
        result = normalise_import_row(row, realm="intl")
        self.assertEqual(result["uid"], "fallback")
        self.assertEqual(result["nickname"], "Fallback")
        self.assertEqual(result["realm"], "intl")

    def test_explicit_realm_and_required_fields(self):
        for realm in (None, "", "all", "CN"):
            self.assertTrue(self.pool.preview_import_rows([self.row()], realm=realm)["invalid"])
        for field in ("id", "token", "expireTime"):
            row = self.row()
            row["auth_user_info_raw"].pop(field)
            self.assertTrue(self.pool.preview_import_rows([row], realm="cn")["invalid"])

    def test_invalid_expiry_and_epoch_do_not_overflow(self):
        for value in (None, "bad", float("nan"), float("inf"), -1, 0, True, "-Infinity", 10 ** 1000):
            with self.subTest(value=type(value).__name__):
                self.assertEqual(normalize_epoch(value), 0)
                result = self.pool.preview_import_rows([self.row(expireTime=value)], realm="cn")
                self.assertTrue(result["invalid"])
        future = int(time.time()) + 60
        self.assertEqual(normalise_import_row(self.row(expireTime=str(future)), realm="cn")["expiresAt"], future)

    def test_expired_refresh_warning_matches_commit(self):
        row = self.row(expireTime=1)
        preview = self.pool.preview_import_rows([row], realm="cn")
        self.assertEqual(preview, self.pool.import_rows([row], realm="cn"))
        self.assertEqual(preview["warnings"][0]["reason"], "首次使用需刷新")
        self.assertTrue(self.pool.preview_import_rows([self.row(expireTime=1, refreshToken="")], realm="cn")["invalid"])

    def test_mixed_native_and_cockpit(self):
        native = {"uid": "native", "accessToken": "native-secret", "realm": "cn"}
        rows = [native, self.row(), self.row(uid=" ")]
        preview = self.pool.preview_import_rows(rows, realm="cn")
        self.assertEqual(preview, self.pool.import_rows(rows, realm="cn"))
        self.assertEqual(preview["added"], ["native", "cockpit"])
        self.assertEqual(len(preview["invalid"]), 1)
        self.assertGreater(self.pool.get("native").expires_at, time.time())

    def test_duplicate_normalization_and_cross_realm_conflict(self):
        rows = [self.row(uid="same/x"), self.row(uid="same?x")]
        preview = self.pool.preview_import_rows(rows, realm="cn")
        self.assertEqual(preview, self.pool.import_rows(rows, realm="cn"))
        self.assertEqual(preview["added"], ["same_x"])
        self.assertEqual(len(preview["skipped"]), 1)
        for overwrite in (False, True):
            preview = self.pool.preview_import_rows(rows[:1], realm="intl", overwrite=overwrite)
            self.assertEqual(preview, self.pool.import_rows(rows[:1], realm="intl", overwrite=overwrite))
            self.assertEqual(len(preview["invalid"]), 1)
            self.assertEqual(self.pool.get("same_x").realm, "cn")

    def test_preview_no_writes_or_network_and_overwrite_backup(self):
        original = self.pool.add(Account({"uid": "cockpit", "realm": "cn", "accessToken": "original-secret"}))
        original_bytes = Path(original.path).read_bytes()
        before = self.hashes()
        with patch("qoder_accounts.http_json", side_effect=AssertionError("network forbidden")):
            preview = self.pool.preview_import_rows([self.row()], realm="cn", overwrite=True)
        self.assertEqual(before, self.hashes())
        self.assertEqual(preview["updated"], ["cockpit"])
        self.assertEqual(preview, self.pool.import_rows([self.row()], realm="cn", overwrite=True))
        backups = list((Path(self.temp.name) / ".runtime" / "import-backups").glob("*.json"))
        self.assertEqual(len(backups), 1)
        self.assertEqual(backups[0].read_bytes(), original_bytes)
        self.assertEqual(self.pool.get("cockpit").access_token, "token-secret")

    def test_skip_does_not_create_backup(self):
        self.pool.import_rows([self.row()], realm="cn")
        before = self.hashes()
        result = self.pool.import_rows([self.row()], realm="cn", overwrite=False)
        self.assertEqual(len(result["skipped"]), 1)
        self.assertEqual(before, self.hashes())

    def test_backup_failure_preserves_current_account(self):
        original = self.pool.add(Account({"uid": "cockpit", "realm": "cn", "accessToken": "original-secret"}))
        original_bytes = Path(original.path).read_bytes()
        with patch.object(Path, "write_bytes", side_effect=OSError("synthetic-secret-error")):
            result = self.pool.import_rows([self.row()], realm="cn", overwrite=True)
        self.assertEqual(len(result["invalid"]), 1)
        self.assertNotIn("synthetic-secret-error", json.dumps(result))
        self.assertIs(self.pool.get("cockpit"), original)
        self.assertEqual(Path(original.path).read_bytes(), original_bytes)

    def test_replace_failure_preserves_current_account_and_readiness(self):
        original = self.pool.add(Account({"uid": "cockpit", "realm": "cn", "accessToken": "original-secret"}))
        original_bytes = Path(original.path).read_bytes()
        with patch("qoder_accounts.os.replace", side_effect=OSError("synthetic failure")):
            result = self.pool.import_rows([self.row()], realm="cn", overwrite=True)
        self.assertEqual(len(result["invalid"]), 1)
        self.assertEqual(result["updated"], [])
        self.assertIs(self.pool.get("cockpit"), original)
        self.assertFalse(original._retired)
        self.assertEqual(Path(original.path).read_bytes(), original_bytes)
        lease = self.pool.acquire(realm="cn")
        self.assertIs(lease.account, original)
        lease.release()

    def test_new_account_save_failure_does_not_insert_memory(self):
        with patch("qoder_accounts.os.replace", side_effect=OSError("synthetic failure")):
            result = self.pool.import_rows([self.row()], realm="cn")
        self.assertEqual(len(result["invalid"]), 1)
        self.assertIsNone(self.pool.get("cockpit"))

    def test_malformed_raw_errors_never_echo_credentials(self):
        rows = [{"auth_user_info_raw": value} for value in (
            'token-secret{"broken"', "[]", None, 123, {"token": ["token-secret"]},
        )]
        result = self.pool.preview_import_rows(rows, realm="cn")
        self.assertEqual(len(result["invalid"]), len(rows))
        self.assertNotIn("token-secret", json.dumps(result))
        self.assertEqual([i["index"] for i in result["invalid"]], [1, 2, 3, 4, 5])

    def test_commit_rechecks_pool_changes_after_preview(self):
        self.assertEqual(self.pool.preview_import_rows([self.row()], realm="cn")["added"], ["cockpit"])
        self.pool.add(Account({"uid": "cockpit", "realm": "intl", "accessToken": "other"}))
        result = self.pool.import_rows([self.row()], realm="cn", overwrite=True)
        self.assertEqual(len(result["invalid"]), 1)
        self.assertFalse((Path(self.temp.name) / ".runtime" / "import-backups").exists())


if __name__ == "__main__":
    unittest.main()
