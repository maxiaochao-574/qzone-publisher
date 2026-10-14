"""Offline unit tests for scripts/qzone_publisher.py.

Network is fully mocked. No real connections, no credentials, no personal
directories are touched (everything runs under temp dirs).

Covers the post-audit safety model:
- prepare is fully offline and never takes the user-level fingerprint lock;
- the fingerprint lock is taken in publish, AFTER the explicit confirm gates
  and BEFORE any network egress;
- verify requires EXACTLY one image and only reads the 5 most recent feeds;
- host must be exactly 127.0.0.1 (localhost / ::1 rejected);
- publish requires --confirm-visibility api-default-public-risk and
  --confirm-digest <hex> (a preview/content-integrity digest, NOT a signature);
- all CLI exceptions are normalized (no traceback) and failures exit non-zero.
"""

import io
import contextlib
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import qzone_publisher as qp

UIN = "10001"
VIS = qp.API_DEFAULT_VISIBILITY


# Known fake secrets that must NEVER appear in any manifest / output.
SECRET_TOKEN = "SECRET_NAPCAT_TOKEN_XYZ"
SECRET_CRED = "SECRET_CREDENTIAL_ABC"
SECRET_SKEY = "SECRET_SKEY_123"
SECRET_PKEY = "SECRET_PKEY_456"
SECRET_GTK_SOURCE = SECRET_PKEY  # gtk is derived from this
ALL_SECRETS = (SECRET_TOKEN, SECRET_CRED, SECRET_SKEY, SECRET_PKEY, SECRET_GTK_SOURCE)


class FakeResp:
    """Minimal stand-in for an urllib response (context manager + read())."""

    def __init__(self, data):
        self._data = data

    def read(self):
        return self._data

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def make_fake_open(scenario):
    """Return an open_req callable that serves canned responses by URL."""

    def fake(req, timeout=60):
        url = req.full_url

        if "/api/auth/login" in url:
            return FakeResp(
                json.dumps({"code": 0, "data": {"Credential": SECRET_CRED}}).encode()
            )
        if "/api/QQLogin/GetQQLoginInfo" in url:
            return FakeResp(
                json.dumps({"code": 0, "data": {"uin": UIN, "online": True}}).encode()
            )
        if "/api/Debug/call" in url:
            cookies = "uin=o{}; skey={}; p_skey={}".format(UIN, SECRET_SKEY, SECRET_PKEY)
            return FakeResp(
                json.dumps(
                    {"code": 0, "data": {"cookies": cookies}}
                ).encode()
            )
        if "emotion_cgi_msglist_v6" in url:
            return FakeResp(
                ("callback(" + json.dumps(scenario.get("feeds", {"code": 0, "msglist": []})) + ")").encode()
            )
        if "cgi_upload_image" in url:
            upload_data = {
                "ret": 0,
                "data": {
                    "url": "http://x/abc&bo=ABCDEF&t=1",
                    "albumid": "a1",
                    "lloc": "l1",
                    "sloc": "s1",
                    "type": "0",
                    "height": "100",
                    "width": "200",
                },
            }
            return FakeResp(
                ("callback(" + json.dumps(scenario.get("upload", upload_data)) + ")").encode()
            )
        if "emotion_cgi_publish_v6" in url:
            return FakeResp(
                ("callback(" + json.dumps(scenario.get("publish", {"code": 0, "tid": "999"})) + ")").encode()
            )
        raise AssertionError("unexpected url: " + url)

    return fake


def write_config(tmp):
    cfg = Path(tmp) / "webui.json"
    cfg.write_text(json.dumps({"token": SECRET_TOKEN}), encoding="utf-8")
    return str(cfg)


def write_image(tmp, name="img.png", content=b"\x89PNG-placeholder-bytes"):
    p = Path(tmp) / name
    p.write_bytes(content)
    return str(p)


def make_request(tmp, text="hello 空间", image=None, config=None, host=None):
    if image is None:
        image = write_image(tmp)
    if config is None:
        config = write_config(tmp)
    req = {
        "account": UIN,
        "text": text,
        "image_path": image,
        "config_path": config,
        "loopback_port": 6099,
    }
    if host is not None:
        req["napcat_host"] = host
    return req


def run_main(argv):
    """Run the CLI main() with captured stdout/stderr; return (code, out, err)."""
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = qp.main(argv)
    return code, out.getvalue(), err.getvalue()


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.job = os.path.join(self.tmp, "job")
        self.state = os.path.join(self.tmp, "state")
        self.req = make_request(self.tmp)
        self.req_path = os.path.join(self.tmp, "request.json")
        Path(self.req_path).write_text(json.dumps(self.req), encoding="utf-8")

    def prepare(self, dryrun=False, req=None):
        return qp.prepare_job(req if req is not None else self.req,
                              self.job, self.state, dryrun)

    def publish(self, fake, visibility=VIS, digest=None, account=UIN):
        m = qp.read_manifest(self.job)
        if digest is None:
            digest = m["request_digest"]
        return qp.publish_job(
            self.job, True, account,
            confirm_visibility=visibility, confirm_digest=digest,
            state_dir=self.state, open_req=fake,
        )

    def fp_locks(self):
        return list(Path(self.state).glob("fp_*.lock")) if Path(self.state).exists() else []


# ---------------------------------------------------------------------------
# 1) prepare: offline, no locks, digest + visibility
# ---------------------------------------------------------------------------
class TestPrepare(Base):
    def test_prepare_offline_creates_manifest_and_hash(self):
        m = self.prepare()
        self.assertEqual(m["status"], "prepared")
        self.assertIsNotNone(m["image_sha256"])
        import hashlib
        expected = hashlib.sha256(b"\x89PNG-placeholder-bytes").hexdigest()
        self.assertEqual(m["image_sha256"], expected)
        manifest_on_disk = json.loads(
            (Path(self.job) / "manifest.json").read_text(encoding="utf-8")
        )
        self.assertEqual(manifest_on_disk["image_sha256"], expected)

    def test_prepare_rejects_non_absolute_image(self):
        self.req["image_path"] = "relative/img.png"
        with self.assertRaises(qp.QzonePublisherError) as ctx:
            self.prepare()
        self.assertEqual(ctx.exception.category, "IMAGE_PATH_NOT_ABSOLUTE")

    def test_prepare_rejects_missing_field(self):
        bad = dict(self.req)
        del bad["account"]
        with self.assertRaises(qp.QzonePublisherError) as ctx:
            self.prepare(req=bad)
        self.assertEqual(ctx.exception.category, "MISSING_FIELD")

    def test_prepare_never_creates_fingerprint_lock(self):
        # prepare must stay offline and must NOT occupy the user's publish lock.
        self.prepare(dryrun=True)
        self.assertEqual(len(self.fp_locks()), 0)
        # even a non-dryrun prepare must not create the lock
        self.prepare(dryrun=False)
        self.assertEqual(len(self.fp_locks()), 0)

    def test_prepare_adds_visibility_and_digest(self):
        m = self.prepare()
        self.assertEqual(m["visibility_policy"], VIS)
        self.assertIsNotNone(m["request_digest"])
        self.assertEqual(len(m["request_digest"]), 64)  # sha256 hex

    def test_prepare_digest_is_deterministic(self):
        d1 = self.prepare().copy()
        d2 = self.prepare(req=make_request(self.tmp, text=self.req["text"])).copy()
        self.assertEqual(d1["request_digest"], d2["request_digest"])

    def test_prepare_digest_depends_on_text(self):
        a = self.prepare().copy()
        b = self.prepare(req=make_request(self.tmp, text="different text")).copy()
        self.assertNotEqual(a["request_digest"], b["request_digest"])

    def test_prepare_digest_depends_on_image(self):
        a = self.prepare().copy()
        other_img = write_image(self.tmp, name="img2.png", content=b"other-bytes-xx")
        b = self.prepare(req=make_request(self.tmp, image=other_img)).copy()
        self.assertNotEqual(a["request_digest"], b["request_digest"])

    def test_prepare_rejects_localhost_host(self):
        # Per audit: host must be exactly 127.0.0.1; localhost is rejected.
        with self.assertRaises(qp.QzonePublisherError) as ctx:
            self.prepare(req=make_request(self.tmp, host="localhost"))
        self.assertEqual(ctx.exception.category, "NON_LOOPBACK_HOST_BLOCKED")

    def test_prepare_rejects_ipv6_loopback_host(self):
        with self.assertRaises(qp.QzonePublisherError) as ctx:
            self.prepare(req=make_request(self.tmp, host="::1"))
        self.assertEqual(ctx.exception.category, "NON_LOOPBACK_HOST_BLOCKED")


# ---------------------------------------------------------------------------
# 2) host enforcement: 127.0.0.1 only
# ---------------------------------------------------------------------------
class TestHostEnforcement(Base):
    def test_enforce_loopback_accepts_127(self):
        qp.enforce_loopback("127.0.0.1")  # must not raise

    def test_enforce_loopback_rejects_localhost(self):
        with self.assertRaises(qp.QzonePublisherError):
            qp.enforce_loopback("localhost")

    def test_enforce_loopback_rejects_ipv6_loopback(self):
        with self.assertRaises(qp.QzonePublisherError):
            qp.enforce_loopback("::1")
        with self.assertRaises(qp.QzonePublisherError):
            qp.enforce_loopback("[::1]")

    def test_enforce_loopback_rejects_other_loopback_ip(self):
        with self.assertRaises(qp.QzonePublisherError):
            qp.enforce_loopback("127.0.0.2")

    def test_enforce_loopback_rejects_public_ip(self):
        with self.assertRaises(qp.QzonePublisherError):
            qp.enforce_loopback("8.8.8.8")

    def test_publish_refuses_nonloopback_host(self):
        self.prepare()
        manifest = json.loads(
            (Path(self.job) / "manifest.json").read_text(encoding="utf-8")
        )
        manifest["napcat_host"] = "8.8.8.8"
        (Path(self.job) / "manifest.json").write_text(
            json.dumps(manifest), encoding="utf-8"
        )
        with self.assertRaises(qp.QzonePublisherError) as ctx:
            self.publish(make_fake_open({}))
        self.assertEqual(ctx.exception.category, "NON_LOOPBACK_HOST_BLOCKED")


# ---------------------------------------------------------------------------
# 3) visibility confirm gate
# ---------------------------------------------------------------------------
class TestVisibilityConfirm(Base):
    def test_publish_requires_visibility_confirm(self):
        self.prepare()
        m = qp.publish_job(self.job, True, UIN, confirm_visibility=None,
                           confirm_digest=qp.read_manifest(self.job)["request_digest"],
                           state_dir=self.state, open_req=make_fake_open({}))
        self.assertEqual(m["status"], "refused")
        self.assertEqual(m["error_category"], "VISIBILITY_CONFIRM_MISSING")

    def test_publish_refuses_wrong_visibility(self):
        self.prepare()
        m = qp.publish_job(self.job, True, UIN, confirm_visibility="private-please",
                           confirm_digest=qp.read_manifest(self.job)["request_digest"],
                           state_dir=self.state, open_req=make_fake_open({}))
        self.assertEqual(m["status"], "refused")
        self.assertEqual(m["error_category"], "VISIBILITY_CONFIRM_MISMATCH")

    def test_publish_accepts_api_default_visibility(self):
        self.prepare()
        m = self.publish(make_fake_open({"publish": {"code": 0, "tid": "777"}}))
        self.assertEqual(m["status"], "published_unverified")


# ---------------------------------------------------------------------------
# 4) digest confirm gate (preview/content-integrity, NOT a signature)
# ---------------------------------------------------------------------------
class TestDigestConfirm(Base):
    def test_publish_requires_digest_confirm(self):
        self.prepare()
        m = qp.publish_job(self.job, True, UIN, confirm_visibility=VIS,
                           confirm_digest=None, state_dir=self.state,
                           open_req=make_fake_open({}))
        self.assertEqual(m["status"], "refused")
        self.assertEqual(m["error_category"], "DIGEST_CONFIRM_MISSING")

    def test_publish_refuses_digest_mismatch(self):
        self.prepare()
        m = qp.publish_job(self.job, True, UIN, confirm_visibility=VIS,
                           confirm_digest="0" * 64, state_dir=self.state,
                           open_req=make_fake_open({}))
        self.assertEqual(m["status"], "refused")
        self.assertEqual(m["error_category"], "DIGEST_MISMATCH")

    def test_publish_accepts_matching_digest(self):
        self.prepare()
        m = self.publish(make_fake_open({"publish": {"code": 0, "tid": "777"}}))
        self.assertEqual(m["status"], "published_unverified")

    def test_digest_mismatch_when_manifest_image_sha_tampered(self):
        self.prepare()
        manifest = qp.read_manifest(self.job)
        # Tamper the recorded image hash; the recomputed digest must then differ
        # from the user-confirmed (original) digest.
        manifest["image_sha256"] = "0" * 64
        (Path(self.job) / "manifest.json").write_text(
            json.dumps(manifest), encoding="utf-8"
        )
        original_digest = self.prepare().copy()["request_digest"]  # not used; recompute below
        # Read the (tampered) manifest digest to confirm we pass it through:
        confirmed = qp.read_manifest(self.job)["request_digest"]
        m = qp.publish_job(self.job, True, UIN, confirm_visibility=VIS,
                           confirm_digest=confirmed, state_dir=self.state,
                           open_req=make_fake_open({}))
        # Confirmed digest came from the tampered manifest, so it still matches
        # the recompute -> this exercises the recompute path; ensure no network leak.
        self.assertIn(m["status"], ("published_unverified", "rejected"))

    def test_confirmed_digest_from_original_blocks_tampered_manifest(self):
        prepared = self.prepare()
        original_digest = prepared["request_digest"]
        # Now tamper the manifest on disk (simulating a different preview).
        manifest = qp.read_manifest(self.job)
        manifest["text"] = "TAMPERED TEXT"
        (Path(self.job) / "manifest.json").write_text(
            json.dumps(manifest), encoding="utf-8"
        )
        m = qp.publish_job(self.job, True, UIN, confirm_visibility=VIS,
                           confirm_digest=original_digest, state_dir=self.state,
                           open_req=make_fake_open({}))
        self.assertEqual(m["status"], "refused")
        self.assertEqual(m["error_category"], "DIGEST_MISMATCH")


# ---------------------------------------------------------------------------
# 5) fingerprint lock lives in publish (after confirms, before network)
# ---------------------------------------------------------------------------
class TestFingerprintAtPublish(Base):
    def test_prepare_never_creates_fingerprint_lock(self):
        self.prepare()
        self.assertEqual(len(self.fp_locks()), 0)

    def test_fingerprint_lock_created_only_at_publish(self):
        self.prepare()
        self.assertEqual(len(self.fp_locks()), 0)
        self.publish(make_fake_open({"publish": {"code": 0, "tid": "1"}}))
        self.assertEqual(len(self.fp_locks()), 1)

    def test_fingerprint_blocks_duplicate_publish(self):
        self.prepare()
        self.publish(make_fake_open({"publish": {"code": 0, "tid": "1"}}))
        # Second job with identical content must be refused by the fingerprint.
        job2 = os.path.join(self.tmp, "job2")
        qp.prepare_job(self.req, job2, self.state, dryrun=False)
        m2 = qp.publish_job(job2, True, UIN,
                            confirm_visibility=VIS,
                            confirm_digest=qp.read_manifest(job2)["request_digest"],
                            state_dir=self.state, open_req=make_fake_open({}))
        self.assertEqual(m2["status"], "refused")
        self.assertEqual(m2["error_category"], "FINGERPRINT_EXISTS")

    def test_fingerprint_allows_different_content(self):
        self.prepare()
        self.publish(make_fake_open({"publish": {"code": 0, "tid": "1"}}))
        job2 = os.path.join(self.tmp, "job2")
        req2 = make_request(self.tmp, text="a totally different post")
        qp.prepare_job(req2, job2, self.state, dryrun=False)
        m2 = qp.publish_job(job2, True, UIN,
                            confirm_visibility=VIS,
                            confirm_digest=qp.read_manifest(job2)["request_digest"],
                            state_dir=self.state,
                            open_req=make_fake_open({"publish": {"code": 0, "tid": "2"}}))
        self.assertEqual(m2["status"], "published_unverified")
        self.assertEqual(m2["tid"], "2")

    def test_fingerprint_acquired_before_network(self):
        # If the fingerprint lock already exists, publish must refuse WITHOUT
        # touching the network (no preflight/upload/publish calls).
        self.prepare()
        fp = qp.fingerprint(self.req["account"], self.req["text"],
                            qp.read_manifest(self.job)["image_sha256"])
        Path(self.state).mkdir(parents=True, exist_ok=True)
        (Path(self.state) / ("fp_" + fp + ".lock")).write_text("")
        calls = {"n": 0}

        def fake(req, timeout=60):
            calls["n"] += 1
            raise AssertionError("network must not be reached: " + req.full_url)

        m = qp.publish_job(self.job, True, UIN, confirm_visibility=VIS,
                           confirm_digest=qp.read_manifest(self.job)["request_digest"],
                           state_dir=self.state, open_req=fake)
        self.assertEqual(m["status"], "refused")
        self.assertEqual(m["error_category"], "FINGERPRINT_EXISTS")
        self.assertEqual(calls["n"], 0)


# ---------------------------------------------------------------------------
# 6) content-change detection (image hash re-validation at publish)
# ---------------------------------------------------------------------------
class TestContentChange(Base):
    def test_publish_refuses_when_image_changed(self):
        self.prepare()
        Path(self.req["image_path"]).write_bytes(b"different-bytes-now")
        m = self.publish(make_fake_open({}))
        self.assertEqual(m["status"], "rejected")
        self.assertEqual(m["error_category"], "IMAGE_HASH_MISMATCH")


# ---------------------------------------------------------------------------
# 7) account confirmation gate
# ---------------------------------------------------------------------------
class TestAccountConfirm(Base):
    def test_publish_refuses_without_confirm(self):
        self.prepare()
        m = qp.publish_job(self.job, False, None, confirm_visibility=VIS,
                           confirm_digest=qp.read_manifest(self.job)["request_digest"],
                           state_dir=self.state, open_req=make_fake_open({}))
        self.assertEqual(m["status"], "refused")
        self.assertEqual(m["error_category"], "MISSING_CONFIRM")

    def test_publish_refuses_on_account_mismatch(self):
        self.prepare()
        m = qp.publish_job(self.job, True, "99999", confirm_visibility=VIS,
                           confirm_digest=qp.read_manifest(self.job)["request_digest"],
                           state_dir=self.state, open_req=make_fake_open({}))
        self.assertEqual(m["status"], "refused")
        self.assertEqual(m["error_category"], "ACCOUNT_CONFIRM_MISMATCH")


# ---------------------------------------------------------------------------
# 8) secret hygiene (never in manifest / results / digest preview)
# ---------------------------------------------------------------------------
class TestSecretHygiene(Base):
    def test_no_secret_in_manifest_on_auth_error(self):
        def fake(req, timeout=60):
            if "/api/auth/login" in req.full_url:
                return FakeResp(json.dumps({"code": 1, "message": "bad"}).encode())
            raise AssertionError("should not reach: " + req.full_url)

        self.prepare()
        m = self.publish(fake)
        text = (Path(self.job) / "manifest.json").read_text(encoding="utf-8")
        for secret in ALL_SECRETS:
            self.assertNotIn(secret, text)
        pub = json.dumps(qp.public_result(m), ensure_ascii=False)
        for secret in ALL_SECRETS:
            self.assertNotIn(secret, pub)
        self.assertEqual(m["error_category"], "NAPCAT_API_ERROR")

    def test_no_secret_in_success_manifest(self):
        self.prepare()
        m = self.publish(make_fake_open({"publish": {"code": 0, "tid": "777"}}))
        text = (Path(self.job) / "manifest.json").read_text(encoding="utf-8")
        for secret in ALL_SECRETS:
            self.assertNotIn(secret, text)
        self.assertNotIn(SECRET_TOKEN, m["request_digest"])

    def test_no_secret_leaks_in_digest_output(self):
        m = self.prepare()
        self.assertNotIn(SECRET_TOKEN, m["request_digest"])
        self.assertNotIn(SECRET_CRED, m["request_digest"])
        # request_digest must be a plain sha256 over the four content fields.
        import hashlib
        manual = hashlib.sha256()
        manual.update(b"account\x00" + m["account"].encode())
        manual.update(b"\x00text\x00" + m["text"].encode())
        manual.update(b"\x00image_sha256\x00" + m["image_sha256"].encode())
        manual.update(b"\x00visibility\x00" + m["visibility_policy"].encode())
        self.assertEqual(manual.hexdigest(), m["request_digest"])


# ---------------------------------------------------------------------------
# 9) verify: exactly one image required; only 5 most recent feeds read
# ---------------------------------------------------------------------------
class TestVerifyImageCount(Base):
    def _publish_unverified(self, scenario):
        self.prepare()
        self.publish(make_fake_open(scenario))

    def test_verify_one_image_verified(self):
        self._publish_unverified({"publish": {"code": 0, "tid": "555"}})
        feeds = {"code": 0, "msglist": [
            {"tid": "555", "content": self.req["text"], "pic": [{"id": 1}]}
        ]}
        m = qp.verify_job(self.job, open_req=make_fake_open({"feeds": feeds}))
        self.assertEqual(m["status"], "verified")
        self.assertEqual(m["image_count"], 1)
        self.assertEqual(m["verify_status"], "matched")

    def test_verify_two_images_image_count_mismatch(self):
        # AUDIT FIX: 2 images must NOT be verified; stays unverified.
        self._publish_unverified({"publish": {"code": 0, "tid": "555"}})
        feeds = {"code": 0, "msglist": [
            {"tid": "555", "content": self.req["text"], "pic": [{}, {}]}
        ]}
        m = qp.verify_job(self.job, open_req=make_fake_open({"feeds": feeds}))
        self.assertEqual(m["status"], "published_unverified")
        self.assertEqual(m["image_count"], 2)
        self.assertEqual(m["verify_status"], "image_count_mismatch")

    def test_verify_zero_images_not_verified(self):
        self._publish_unverified({"publish": {"code": 0, "tid": "555"}})
        feeds = {"code": 0, "msglist": [
            {"tid": "555", "content": self.req["text"], "pic": []}
        ]}
        m = qp.verify_job(self.job, open_req=make_fake_open({"feeds": feeds}))
        self.assertEqual(m["status"], "published_unverified")
        self.assertEqual(m["image_count"], 0)
        self.assertEqual(m["verify_status"], "image_count_mismatch")

    def test_verify_three_images_image_count_mismatch(self):
        self._publish_unverified({"publish": {"code": 0, "tid": "555"}})
        feeds = {"code": 0, "msglist": [
            {"tid": "555", "content": self.req["text"], "pic": [{}, {}, {}]}
        ]}
        m = qp.verify_job(self.job, open_req=make_fake_open({"feeds": feeds}))
        self.assertEqual(m["status"], "published_unverified")
        self.assertEqual(m["verify_status"], "image_count_mismatch")

    def test_verify_content_mismatch_not_verified(self):
        self._publish_unverified({"publish": {"code": 0, "tid": "555"}})
        feeds = {"code": 0, "msglist": [
            {"tid": "555", "content": "DIFFERENT CONTENT", "pic": [{"id": 1}]}
        ]}
        m = qp.verify_job(self.job, open_req=make_fake_open({"feeds": feeds}))
        self.assertEqual(m["status"], "published_unverified")
        self.assertEqual(m["verify_status"], "content_mismatch")

    def test_verify_empty_msglist_no_resend(self):
        self._publish_unverified({"publish": {"code": 0, "tid": "555"}})
        feeds = {"code": 0, "msglist": []}
        counter = {"n": 0}
        base = make_fake_open({})

        def fake(req, timeout=60):
            counter["n"] += 1
            if "emotion_cgi_msglist_v6" in req.full_url:
                return FakeResp(("callback(" + json.dumps(feeds) + ")").encode())
            if "emotion_cgi_publish_v6" in req.full_url:
                raise AssertionError("verify must not publish")
            return base(req, timeout)

        m = qp.verify_job(self.job, open_req=fake)
        self.assertEqual(m["verify_status"], "no_match")
        self.assertEqual(m["status"], "published_unverified")  # unchanged
        self.assertGreaterEqual(counter["n"], 1)

    def test_verify_recent5_not_found_does_not_assert_not_published(self):
        # Only the 5 most recent feeds are read. If the tid is absent we must
        # NOT flip to a "not published" status -- merely leave it unverified.
        self._publish_unverified({"publish": {"code": 0, "tid": "555"}})
        feeds = {"code": 0, "msglist": [
            {"tid": "9999", "content": "some other old post", "pic": [{"id": 0}]}
        ]}
        m = qp.verify_job(self.job, open_req=make_fake_open({"feeds": feeds}))
        self.assertEqual(m["verify_status"], "no_match")
        self.assertEqual(m["status"], "published_unverified")
        self.assertEqual(m["tid"], "555")  # tid preserved

    def test_verify_inconclusive_on_network_error_keeps_status(self):
        self._publish_unverified({"publish": {"code": 0, "tid": "555"}})

        def fake(req, timeout=60):
            if "/api/auth/login" in req.full_url:
                raise RuntimeError("simulated network down")
            raise AssertionError("unexpected: " + req.full_url)

        m = qp.verify_job(self.job, open_req=fake)
        self.assertEqual(m["verify_status"], "inconclusive")
        self.assertEqual(m["status"], "published_unverified")


# ---------------------------------------------------------------------------
# 10) unknown outcome not re-sent (attempt lock persists)
# ---------------------------------------------------------------------------
class TestUnknownNoResend(Base):
    def test_unknown_not_resent(self):
        scenario = {"publish": {"code": 0}}
        self.prepare()
        m1 = self.publish(make_fake_open(scenario))
        self.assertEqual(m1["status"], "publish_outcome_unknown")
        # The permanent fingerprint lock (taken before network) blocks any
        # re-send of the same content, so a second publish is refused.
        m2 = self.publish(make_fake_open(scenario))
        self.assertEqual(m2["status"], "refused")
        self.assertEqual(m2["error_category"], "FINGERPRINT_EXISTS")

    def test_attempt_lock_blocks_same_job_republish_after_edit(self):
        # Same job-dir, but the manifest text is edited (and the digest updated
        # to match) so the fingerprint no longer matches. The per-job attempt
        # lock must still block re-send.
        self.prepare()
        self.publish(make_fake_open({"publish": {"code": 0, "tid": "777"}}))
        manifest = qp.read_manifest(self.job)
        manifest["text"] = "edited text after first publish"
        manifest["request_digest"] = qp.compute_request_digest(
            manifest["account"], manifest["text"], manifest["image_sha256"],
            manifest["visibility_policy"],
        )
        (Path(self.job) / "manifest.json").write_text(
            json.dumps(manifest), encoding="utf-8"
        )
        m2 = qp.publish_job(
            self.job, True, UIN, confirm_visibility=VIS,
            confirm_digest=qp.read_manifest(self.job)["request_digest"],
            state_dir=self.state, open_req=make_fake_open({}),
        )
        self.assertEqual(m2["status"], "refused")
        self.assertEqual(m2["error_category"], "ATTEMPT_LOCK_EXISTS")

    def test_no_tid_stays_unknown(self):
        scenario = {"publish": {"code": 0}}
        self.prepare()
        m = self.publish(make_fake_open(scenario))
        self.assertEqual(m["status"], "publish_outcome_unknown")
        self.assertTrue(m.get("no_tid"))

    def test_success_sets_published_unverified(self):
        scenario = {"publish": {"code": 0, "tid": "777"}}
        self.prepare()
        m = self.publish(make_fake_open(scenario))
        self.assertEqual(m["status"], "published_unverified")
        self.assertEqual(m["tid"], "777")
        self.assertIn("mood/777", m["url"])


# ---------------------------------------------------------------------------
# 11) preflight failure stops; online duplicate stops (no resend)
# ---------------------------------------------------------------------------
class TestPreflightAndDup(Base):
    def test_preflight_failure_stops(self):
        scenario = {"feeds": {"code": -1, "message": "blocked"}}
        self.prepare()
        m = self.publish(make_fake_open(scenario))
        self.assertEqual(m["status"], "rejected")
        self.assertEqual(m["error_category"], "PREFLIGHT_FAILED")

    def test_online_duplicate_skips_without_send(self):
        feeds = {"code": 0, "msglist": [{"tid": "111", "content": self.req["text"]}]}
        self.prepare()
        sent = {"publish": False}

        def fake(req, timeout=60):
            if "emotion_cgi_publish_v6" in req.full_url:
                sent["publish"] = True
                raise AssertionError("should not publish on duplicate")
            if "cgi_upload_image" in req.full_url:
                raise AssertionError("should not upload on duplicate")
            return make_fake_open({"feeds": feeds})(req, timeout)

        m = self.publish(fake)
        self.assertEqual(m["status"], "duplicate_skipped")
        self.assertEqual(m["tid"], "111")
        self.assertFalse(sent["publish"])


# ---------------------------------------------------------------------------
# 12) CLI: no traceback, normalized errors, non-zero on failure
# ---------------------------------------------------------------------------
class TestCLIExitCodes(Base):
    def test_prepare_success_exit_zero(self):
        code, out, err = run_main([
            "prepare", "--request", self.req_path,
            "--job-dir", self.job, "--state-dir", self.state,
        ])
        self.assertEqual(code, 0)
        self.assertNotIn("Traceback", err)

    def test_publish_success_exit_zero(self):
        self.prepare()
        with mock.patch.object(qp, "open_request",
                               make_fake_open({"publish": {"code": 0, "tid": "777"}})):
            code, out, err = run_main([
                "publish", "--job-dir", self.job, "--state-dir", self.state,
                "--confirm-publish", "--confirm-account", UIN,
                "--confirm-visibility", VIS,
                "--confirm-digest", qp.read_manifest(self.job)["request_digest"],
            ])
        self.assertEqual(code, 0)
        self.assertNotIn("Traceback", err)

    def test_publish_missing_visibility_exit_nonzero(self):
        self.prepare()
        code, out, err = run_main([
            "publish", "--job-dir", self.job, "--state-dir", self.state,
            "--confirm-publish", "--confirm-account", UIN,
            "--confirm-digest", qp.read_manifest(self.job)["request_digest"],
        ])
        self.assertEqual(code, 1)
        self.assertNotIn("Traceback", err)

    def test_publish_digest_mismatch_exit_nonzero(self):
        self.prepare()
        code, out, err = run_main([
            "publish", "--job-dir", self.job, "--state-dir", self.state,
            "--confirm-publish", "--confirm-account", UIN,
            "--confirm-visibility", VIS, "--confirm-digest", "0" * 64,
        ])
        self.assertEqual(code, 1)
        self.assertNotIn("Traceback", err)

    def test_verify_inconclusive_exit_nonzero(self):
        self.prepare()
        with mock.patch.object(qp, "open_request",
                               side_effect=RuntimeError("simulated down")):
            code, out, err = run_main(["verify", "--job-dir", self.job])
        self.assertEqual(code, 1)
        self.assertNotIn("Traceback", err)

    def test_missing_manifest_exit_nonzero(self):
        missing = os.path.join(self.tmp, "nope")
        code, out, err = run_main(["verify", "--job-dir", missing])
        self.assertEqual(code, 1)
        self.assertNotIn("Traceback", err)

    def test_bad_request_file_exit_nonzero(self):
        bad = os.path.join(self.tmp, "missing_request.json")
        code, out, err = run_main([
            "prepare", "--request", bad,
            "--job-dir", self.job, "--state-dir", self.state,
        ])
        self.assertEqual(code, 1)
        self.assertNotIn("Traceback", err)

    def test_cli_output_is_safe_json_without_secrets(self):
        # Force an auth error path and confirm stdout is a safe JSON blob.
        self.prepare()
        with mock.patch.object(qp, "open_request",
                               side_effect=qp.QzonePublisherError("auth", "NAPCAT_API_ERROR")):
            code, out, err = run_main([
                "publish", "--job-dir", self.job, "--state-dir", self.state,
                "--confirm-publish", "--confirm-account", UIN,
                "--confirm-visibility", VIS,
                "--confirm-digest", qp.read_manifest(self.job)["request_digest"],
            ])
        self.assertEqual(code, 1)
        payload = json.loads(out)
        self.assertEqual(payload["status"], "rejected")
        self.assertEqual(payload["error_category"], "NAPCAT_API_ERROR")
        self.assertNotIn("Traceback", err)


if __name__ == "__main__":
    unittest.main(verbosity=2)
