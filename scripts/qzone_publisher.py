"""Qzone single-image + text publisher (NapCat-assisted).

STAGING skill script. Rewritten from a working one-shot script.
Source project URL is used ONLY as a field reference; no project code is copied.

Safety model (read references/protocol.md for details):
- No hardcoded account, text, image path, or credential.
- NapCat HTTP is restricted to loopback 127.0.0.1 ONLY (localhost/::1 rejected).
- External requests are limited to two fixed HTTPS Qzone domains.
- urllib uses no environment proxy and rejects redirects.
- Credentials live only in memory; they are never written to manifest/results.
- Errors expose only a stage name + a whitelisted category (no raw secrets).

Workflow:
- prepare: FULLY OFFLINE. Validates inputs, computes image SHA-256, and writes
  a per-job manifest.json only. It does NOT touch any user-level lock, so it
  never occupies the user's publish lock. It also computes a `request_digest`
  (a content-integrity / preview-confirmation digest, NOT a signature -- see
  below) over account + text + image_sha256 + visibility policy.
- publish: requires explicit confirms (--confirm-publish, --confirm-account,
  --confirm-visibility api-default-public-risk, --confirm-digest <hex>). Only
  AFTER all confirm gates does it acquire the permanent user-level fingerprint
  lock (blocking cross-job duplicates) and only THEN reaches the network.
- verify: read-only re-check of the published tid, full text, and image count.
  It never re-sends. It reads only the 5 most recent feeds.

request_digest is NOT a cryptographic authentication / signature. It is a plain
SHA-256 over the resolved request content so the user can preview the manifest
and explicitly confirm "this digest matches what I intend to publish". It does
NOT defend against a malicious local attacker tampering with files or memory;
do not advertise it as identity authentication or tamper-proof signing.
"""

import argparse
import base64
import hashlib
import hmac
import ipaddress
import json
import os
import sys
import urllib.parse
import urllib.request
from http.cookies import SimpleCookie
from pathlib import Path

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

DEFAULT_CONFIG_PATH = "C:/NapCat/napcat/config/webui.json"
DEFAULT_NAPCAT_HOST = "127.0.0.1"
DEFAULT_STATE_DIR = str(Path.home() / ".cache" / "qzone-publisher-state")

# Only these two HTTPS Qzone domains may be contacted for external requests.
ALLOWED_QZONE_HOSTS = frozenset({"user.qzone.qq.com", "up.qzone.qq.com"})

# The only visibility policy this skill supports. The underlying Qzone API
# applies a default (effectively public) visibility; fine-grained visibility is
# NOT guaranteed. Users who require private visibility must be refused.
API_DEFAULT_VISIBILITY = "api-default-public-risk"

MSGLIST_URL = (
    "https://user.qzone.qq.com/proxy/domain/taotao.qq.com/"
    "cgi-bin/emotion_cgi_msglist_v6"
)
UPLOAD_URL = "https://up.qzone.qq.com/cgi-bin/upload/cgi_upload_image"
PUBLISH_URL = (
    "https://user.qzone.qq.com/proxy/domain/taotao.qzone.qq.com/"
    "cgi-bin/emotion_cgi_publish_v6"
)

# Safe (secret-free) error categories. Never include raw exception text.
SAFE_CATEGORIES = {
    "IMAGE_PATH_NOT_ABSOLUTE",
    "IMAGE_NOT_FOUND",
    "IMAGE_UNREADABLE",
    "IMAGE_HASH_MISMATCH",
    "MISSING_FIELD",
    "MISSING_CONFIRM",
    "ACCOUNT_CONFIRM_MISMATCH",
    "VISIBILITY_CONFIRM_MISSING",
    "VISIBILITY_CONFIRM_MISMATCH",
    "DIGEST_CONFIRM_MISSING",
    "DIGEST_MISMATCH",
    "NON_LOOPBACK_HOST_BLOCKED",
    "ATTEMPT_LOCK_EXISTS",
    "FINGERPRINT_EXISTS",
    "NAPCAT_API_ERROR",
    "AUTH_UNKNOWN",
    "ACCOUNT_MISMATCH",
    "ACCOUNT_OFFLINE",
    "COOKIE_ACCOUNT_MISMATCH",
    "NO_QZONE_CREDENTIAL",
    "NON_HTTPS_BLOCKED",
    "DISALLOWED_HOST_BLOCKED",
    "NON_JSON_RESPONSE",
    "PREFLIGHT_FAILED",
    "PREFLIGHT_UNKNOWN",
    "DUPLICATE_FOUND",
    "UPLOAD_FAILED",
    "PUBLISH_REJECTED",
    "PUBLISH_UNKNOWN",
    "MANIFEST_MISSING",
    "UNEXPECTED_ERROR",
}


class QzonePublisherError(Exception):
    """Carries only a stage name and a whitelisted category (no secrets)."""

    def __init__(self, stage, category):
        if category not in SAFE_CATEGORIES:
            # Never leak an arbitrary message; fall back to a safe constant.
            category = "UNEXPECTED_ERROR"
        super().__init__(category)
        self.stage = stage
        self.category = category


# ---------------------------------------------------------------------------
# Low-level HTTP (no proxy, no redirects, loopback-only NapCat)
# ---------------------------------------------------------------------------

class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise QzonePublisherError("network", "DISALLOWED_HOST_BLOCKED")


def make_opener():
    """Opener that ignores environment proxies and never follows redirects."""
    return urllib.request.build_opener(
        urllib.request.ProxyHandler({}),
        _NoRedirect(),
    )


_OPENER = make_opener()


def open_request(req, timeout=60):
    """Single network egress point; uses no-proxy / no-redirect opener."""
    return _OPENER.open(req, timeout=timeout)


def enforce_loopback(host):
    """Reject anything other than the literal 127.0.0.1.

    localhost, ::1, [::1], and any other loopback IP are explicitly REJECTED
    per the audit requirement: the host must be exactly 127.0.0.1.
    """
    h = (host or "").strip().lower()
    if h == "127.0.0.1":
        return
    # Defensive: never trust name resolution or other loopback forms.
    raise QzonePublisherError("network", "NON_LOOPBACK_HOST_BLOCKED")


def enforce_qzone_domain(url):
    p = urllib.parse.urlparse(url)
    if p.scheme != "https":
        raise QzonePublisherError("network", "NON_HTTPS_BLOCKED")
    if p.hostname not in ALLOWED_QZONE_HOSTS:
        raise QzonePublisherError("network", "DISALLOWED_HOST_BLOCKED")


def parse_jsonp(raw):
    s = raw.find("{")
    e = raw.rfind("}")
    if s < 0 or e < 0 or e < s:
        raise QzonePublisherError("network", "NON_JSON_RESPONSE")
    return json.loads(raw[s : e + 1])


def compute_sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def compute_request_digest(account, text, image_sha256, visibility_policy):
    """Plain SHA-256 over the resolved request content.

    Covers account + text + image_sha256 + visibility policy. This is a
    content-integrity / preview-confirmation digest ONLY -- it is NOT a
    signature and must NOT be advertised as cryptographic authentication or as
    protection against local malicious tampering.
    """
    h = hashlib.sha256()
    h.update(b"account\x00")
    h.update(str(account).encode("utf-8"))
    h.update(b"\x00text\x00")
    h.update(str(text).encode("utf-8"))
    h.update(b"\x00image_sha256\x00")
    h.update(str(image_sha256).encode("utf-8"))
    h.update(b"\x00visibility\x00")
    h.update(str(visibility_policy).encode("utf-8"))
    return h.hexdigest()


# ---------------------------------------------------------------------------
# NapCat local API (loopback only) -- credentials stay in memory
# ---------------------------------------------------------------------------

def napcat_call(port, host, path, data, token, open_req):
    enforce_loopback(host)
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = "Bearer " + token
    body = json.dumps(data).encode("utf-8")
    url = "http://{}:{}/api{}".format(host, port, path)
    req = urllib.request.Request(url, data=body, headers=headers)
    try:
        with open_req(req, timeout=60) as r:
            obj = json.load(r)
    except QzonePublisherError:
        raise
    except Exception:
        raise QzonePublisherError("auth", "NAPCAT_API_ERROR")
    if obj.get("code") != 0:
        raise QzonePublisherError("auth", "NAPCAT_API_ERROR")
    return obj.get("data", {})


def build_session(config_path, port, host, open_req):
    """Authenticate with NapCat and return an in-memory session dict.

    The returned dict holds the credential and cookies; it is never written to
    disk or to results.
    """
    config = json.loads(Path(config_path).read_text(encoding="utf-8-sig"))
    token = config["token"]  # read once; kept only in memory
    token_hash = hashlib.sha256((token + ".napcat").encode("utf-8")).hexdigest()
    cred = napcat_call(port, host, "/auth/login", {"hash": token_hash}, None, open_req)
    credential = cred.get("Credential")
    info = napcat_call(
        port, host, "/QQLogin/GetQQLoginInfo", {}, credential, open_req
    )
    cookies_payload = napcat_call(
        port,
        host,
        "/Debug/call",
        {"action": "get_cookies", "params": {"domain": "user.qzone.qq.com"}},
        credential,
        open_req,
    )
    if "cookies" not in cookies_payload and "data" in cookies_payload:
        cookies_payload = cookies_payload["data"]
    cookie = SimpleCookie(cookies_payload["cookies"])
    cookies = {k: v.value for k, v in cookie.items()}
    return {
        "credential": credential,
        "uin": str(info.get("uin")),
        "online": bool(info.get("online")),
        "cookies": cookies,
    }


def compute_gtk(key):
    gtk = 5381
    for ch in key:
        gtk += (gtk << 5) + ord(ch)
    return str(gtk & 0x7FFFFFFF)


# ---------------------------------------------------------------------------
# Qzone external request (HTTPS, allowlisted domains only)
# ---------------------------------------------------------------------------

def qzone_request(open_req, url, params, data, cookies, gtk, uin):
    enforce_qzone_domain(url)
    if params:
        url += "?" + urllib.parse.urlencode(params)
    headers = {
        "User-Agent": "Mozilla/5.0",
        "Referer": "https://user.qzone.qq.com/" + uin,
        "Origin": "https://user.qzone.qq.com",
        "Cookie": "; ".join("{}={}".format(k, v) for k, v in cookies.items()),
    }
    if data is not None:
        headers["Content-Type"] = "application/x-www-form-urlencoded"
        body = urllib.parse.urlencode(data).encode("utf-8")
    else:
        body = None
    req = urllib.request.Request(url, data=body, headers=headers)
    try:
        with open_req(req, timeout=60) as r:
            raw = r.read().decode("utf-8", "replace")
    except QzonePublisherError:
        raise
    except Exception:
        raise QzonePublisherError("network", "NON_JSON_RESPONSE")
    return parse_jsonp(raw)


def mood_url(account, tid):
    return "https://user.qzone.qq.com/{}/mood/{}".format(account, tid)


# ---------------------------------------------------------------------------
# Locking
# ---------------------------------------------------------------------------

def acquire_lock(path):
    """Create an O_EXCL lock file. Raises if it already exists (no overwrite)."""
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    try:
        fd = os.open(str(p), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        os.close(fd)
    except FileExistsError:
        raise QzonePublisherError("lock", "ATTEMPT_LOCK_EXISTS")


def fingerprint(account, text, image_sha256):
    h = hashlib.sha256()
    h.update(account.encode("utf-8"))
    h.update(b"\x00")
    h.update(text.encode("utf-8"))
    h.update(b"\x00")
    h.update(image_sha256.encode("utf-8"))
    return h.hexdigest()


# ---------------------------------------------------------------------------
# Manifest I/O (safe fields only)
# ---------------------------------------------------------------------------

MANIFEST_FILE = "manifest.json"
ATTEMPT_LOCK = "attempt.lock"


def write_manifest(job_dir, manifest):
    Path(job_dir).mkdir(parents=True, exist_ok=True)
    (Path(job_dir) / MANIFEST_FILE).write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8"
    )


def read_manifest(job_dir):
    p = Path(job_dir) / MANIFEST_FILE
    if not p.exists():
        raise QzonePublisherError("manifest", "MANIFEST_MISSING")
    return json.loads(p.read_text(encoding="utf-8"))


def public_result(m):
    """Return ONLY safe fields (no credentials, no secrets)."""
    return {
        "account": m.get("account"),
        "status": m.get("status"),
        "stage": m.get("stage"),
        "tid": m.get("tid"),
        "url": m.get("url"),
        "visibility_policy": m.get("visibility_policy"),
        "request_digest": m.get("request_digest"),
        "image_sha256": m.get("image_sha256"),
        "image_count": m.get("image_count"),
        "error_stage": m.get("error_stage"),
        "error_category": m.get("error_category"),
        "verify_status": m.get("verify_status"),
    }


# ---------------------------------------------------------------------------
# Job stages
# ---------------------------------------------------------------------------

def prepare_job(request, job_dir, state_dir, dryrun):
    """FULLY OFFLINE prepare.

    Validates inputs, computes the image SHA-256, and writes a per-job
    manifest.json containing a `request_digest`. It does NOT acquire any
    user-level lock, so it never occupies the user's publish lock. The
    fingerprint lock is taken later, in publish_job, after the explicit
    confirm gates and before any network operation.
    """
    try:
        account = str(request["account"])
        text = str(request["text"])
        image_path = str(request["image_path"])
    except (KeyError, TypeError):
        raise QzonePublisherError("prepare", "MISSING_FIELD")

    config_path = str(request.get("config_path", DEFAULT_CONFIG_PATH))
    loopback_port = int(request.get("loopback_port", 6099))
    napcat_host = str(request.get("napcat_host", DEFAULT_NAPCAT_HOST))

    enforce_loopback(napcat_host)
    img = Path(image_path)
    if not img.is_absolute():
        raise QzonePublisherError("prepare", "IMAGE_PATH_NOT_ABSOLUTE")
    if not img.exists():
        raise QzonePublisherError("prepare", "IMAGE_NOT_FOUND")

    image_sha256 = compute_sha256(image_path)
    request_digest = compute_request_digest(
        account, text, image_sha256, API_DEFAULT_VISIBILITY
    )
    manifest = {
        "account": account,
        "text": text,
        "image_path": image_path,
        "config_path": config_path,
        "loopback_port": loopback_port,
        "napcat_host": napcat_host,
        "image_sha256": image_sha256,
        "visibility_policy": API_DEFAULT_VISIBILITY,
        "request_digest": request_digest,
        "status": "prepared",
        "stage": "prepared",
        "tid": None,
        "url": None,
        "image_count": None,
        "error_stage": None,
        "error_category": None,
        "verify_status": None,
    }
    write_manifest(job_dir, manifest)
    # NOTE: no fingerprint lock is created here on purpose. prepare stays
    # offline and never holds the user's publish lock.
    return manifest


def _refuse(manifest, job_dir, stage, category):
    manifest.update(
        status="refused",
        stage=stage,
        error_stage=stage,
        error_category=category,
    )
    write_manifest(job_dir, manifest)
    return manifest


def _fail(manifest, job_dir, stage, category):
    manifest.update(
        status="rejected",
        stage=stage,
        error_stage=stage,
        error_category=category,
    )
    write_manifest(job_dir, manifest)
    return manifest


def publish_job(
    job_dir,
    confirm_publish,
    confirm_account,
    confirm_visibility=None,
    confirm_digest=None,
    state_dir=DEFAULT_STATE_DIR,
    open_req=None,
):
    open_req = open_req or open_request
    manifest = read_manifest(job_dir)

    # --- Explicit confirmation gates (NONE of these touches the network) ---
    if not confirm_publish or confirm_account is None:
        return _refuse(manifest, job_dir, "confirm", "MISSING_CONFIRM")
    if str(confirm_account) != str(manifest["account"]):
        return _refuse(manifest, job_dir, "confirm", "ACCOUNT_CONFIRM_MISMATCH")
    if confirm_visibility is None:
        return _refuse(manifest, job_dir, "confirm", "VISIBILITY_CONFIRM_MISSING")
    if confirm_visibility != API_DEFAULT_VISIBILITY:
        return _refuse(manifest, job_dir, "confirm", "VISIBILITY_CONFIRM_MISMATCH")

    # The user must explicitly confirm the preview digest. Recompute from the
    # manifest contents and require strict equality. This is a preview/
    # content-integrity confirmation, NOT cryptographic authentication.
    expected_digest = compute_request_digest(
        manifest["account"],
        manifest["text"],
        manifest["image_sha256"],
        manifest.get("visibility_policy", API_DEFAULT_VISIBILITY),
    )
    if confirm_digest is None:
        return _refuse(manifest, job_dir, "confirm", "DIGEST_CONFIRM_MISSING")
    if not hmac.compare_digest(expected_digest, confirm_digest):
        return _refuse(manifest, job_dir, "confirm", "DIGEST_MISMATCH")

    # --- User-level fingerprint lock: AFTER confirms, BEFORE network ---
    # Permanent (never auto-deleted): blocks cross-job duplicate publication of
    # the exact same content. It is taken here, not in prepare, so prepare
    # stays offline and never occupies the user's publish lock.
    fp = fingerprint(manifest["account"], manifest["text"], manifest["image_sha256"])
    try:
        acquire_lock(Path(state_dir) / ("fp_" + fp + ".lock"))
    except QzonePublisherError:
        return _refuse(manifest, job_dir, "lock", "FINGERPRINT_EXISTS")

    host = manifest.get("napcat_host", DEFAULT_NAPCAT_HOST)
    enforce_loopback(host)

    # Per-job O_EXCL attempt lock: prevents double-send and auto-retry.
    try:
        acquire_lock(Path(job_dir) / ATTEMPT_LOCK)
    except QzonePublisherError:
        return _refuse(manifest, job_dir, "lock", "ATTEMPT_LOCK_EXISTS")

    # Re-validate image hash before any network send (image sha re-check).
    try:
        current = compute_sha256(manifest["image_path"])
    except Exception:
        return _fail(manifest, job_dir, "image_hash", "IMAGE_UNREADABLE")
    if current != manifest["image_sha256"]:
        return _fail(manifest, job_dir, "image_hash", "IMAGE_HASH_MISMATCH")

    # Build in-memory session (no disk/result persistence of credentials).
    try:
        session = build_session(
            manifest["config_path"], manifest["loopback_port"], host, open_req
        )
    except QzonePublisherError as e:
        return _fail(manifest, job_dir, e.stage, e.category)
    except Exception:
        return _fail(manifest, job_dir, "auth", "AUTH_UNKNOWN")

    if str(session["uin"]) != str(manifest["account"]):
        return _fail(manifest, job_dir, "auth", "ACCOUNT_MISMATCH")
    if not session["online"]:
        return _fail(manifest, job_dir, "auth", "ACCOUNT_OFFLINE")
    cookies = session["cookies"]
    cuin = str(cookies.get("uin", "")).lstrip("o")
    if cuin and cuin != str(manifest["account"]):
        return _fail(manifest, job_dir, "auth", "COOKIE_ACCOUNT_MISMATCH")
    key = cookies.get("p_skey") or cookies.get("skey")
    if not key:
        return _fail(manifest, job_dir, "auth", "NO_QZONE_CREDENTIAL")
    gtk = compute_gtk(key)

    # Preflight: read the space; stop if it fails.
    try:
        feeds = qzone_request(
            open_req,
            MSGLIST_URL,
            {
                "g_tk": gtk,
                "uin": manifest["account"],
                "ftype": 0,
                "sort": 0,
                "pos": 0,
                "num": 5,
                "format": "json",
                "code_version": 1,
            },
            None,
            cookies,
            gtk,
            manifest["account"],
        )
    except QzonePublisherError as e:
        return _fail(manifest, job_dir, e.stage, e.category)
    except Exception:
        return _fail(manifest, job_dir, "preflight", "PREFLIGHT_UNKNOWN")
    if feeds.get("code") != 0:
        return _fail(manifest, job_dir, "preflight", "PREFLIGHT_FAILED")

    # Online duplicate guard: if the same text already exists, stop. We do NOT
    # claim the image was verified -- only that a duplicate was found.
    existing = next(
        (x for x in (feeds.get("msglist") or []) if x.get("content") == manifest["text"]),
        None,
    )
    if existing:
        manifest.update(status="duplicate_skipped", duplicate_text_found=True)
        if existing.get("tid"):
            manifest["tid"] = existing["tid"]
            manifest["url"] = mood_url(manifest["account"], existing["tid"])
        write_manifest(job_dir, manifest)
        return manifest

    # Upload the single image (base64).
    try:
        upload = qzone_request(
            open_req,
            UPLOAD_URL,
            None,
            {
                "filename": "filename",
                "uploadtype": "1",
                "albumtype": "7",
                "skey": cookies.get("skey", ""),
                "uin": manifest["account"],
                "p_skey": key,
                "output_type": "json",
                "base64": "1",
                "picfile": base64.b64encode(
                    Path(manifest["image_path"]).read_bytes()
                ).decode("ascii"),
            },
            cookies,
            gtk,
            manifest["account"],
        )
    except QzonePublisherError as e:
        return _fail(manifest, job_dir, e.stage, e.category)
    except Exception:
        return _fail(manifest, job_dir, "upload", "UPLOAD_FAILED")
    if upload.get("ret") != 0:
        return _fail(manifest, job_dir, "upload", "UPLOAD_FAILED")

    d = upload["data"]
    bo = d["url"].split("&bo=", 1)[1]
    rich = ",{},{},{},{},{},{},,{},{}".format(
        d["albumid"], d["lloc"], d["sloc"], d["type"],
        d["height"], d["width"], d["height"], d["width"],
    )
    publish_data = {
        "syn_tweet_verson": "1",
        "paramstr": "1",
        "who": "1",
        "con": manifest["text"],
        "feedversion": "1",
        "ver": "1",
        "ugc_right": "1",
        "to_sign": "0",
        "hostuin": manifest["account"],
        "code_version": "1",
        "format": "json",
        "qzreferrer": "https://user.qzone.qq.com/" + manifest["account"],
        "pic_bo": bo,
        "richtype": "1",
        "richval": rich,
    }

    # Persist "unknown" BEFORE sending the publish request.
    manifest.update(status="publish_outcome_unknown", stage="publish_attempted")
    write_manifest(job_dir, manifest)

    # Send the publish request.
    try:
        resp = qzone_request(
            open_req,
            PUBLISH_URL,
            {"g_tk": gtk, "uin": manifest["account"]},
            publish_data,
            cookies,
            gtk,
            manifest["account"],
        )
    except QzonePublisherError as e:
        return _fail(manifest, job_dir, e.stage, e.category)
    except Exception:
        return _fail(manifest, job_dir, "publish", "PUBLISH_UNKNOWN")

    if resp.get("code") != 0:
        return _fail(manifest, job_dir, "publish", "PUBLISH_REJECTED")

    tid = resp.get("tid") or (resp.get("data") or {}).get("tid")
    if not tid:
        # Success code but no tid -> stays unknown; manual check required.
        manifest.update(status="publish_outcome_unknown", no_tid=True)
        write_manifest(job_dir, manifest)
        return manifest

    # Has tid -> published_unverified (verify stage marks it verified).
    manifest.update(
        status="published_unverified",
        tid=tid,
        url=mood_url(manifest["account"], tid),
    )
    write_manifest(job_dir, manifest)
    return manifest


def verify_job(job_dir, open_req=None):
    open_req = open_req or open_request
    manifest = read_manifest(job_dir)
    host = manifest.get("napcat_host", DEFAULT_NAPCAT_HOST)
    enforce_loopback(host)

    # Read-only: never re-sends. Builds a session only to read the space.
    # NOTE: only the 5 most recent feeds are read. If the tid is not found,
    # that does NOT prove the item was not published (it may simply be outside
    # the recent window); the status is left as published_unverified.
    try:
        session = build_session(
            manifest["config_path"], manifest["loopback_port"], host, open_req
        )
        key = session["cookies"].get("p_skey") or session["cookies"].get("skey")
        gtk = compute_gtk(key) if key else ""
        feeds = qzone_request(
            open_req,
            MSGLIST_URL,
            {
                "g_tk": gtk,
                "uin": manifest["account"],
                "ftype": 0,
                "sort": 0,
                "pos": 0,
                "num": 5,
                "format": "json",
                "code_version": 1,
            },
            None,
            session["cookies"],
            gtk,
            manifest["account"],
        )
    except QzonePublisherError as e:
        manifest.update(error_stage=e.stage, error_category=e.category,
                        verify_status="inconclusive")
        write_manifest(job_dir, manifest)
        return manifest
    except Exception:
        manifest.update(verify_status="inconclusive")
        write_manifest(job_dir, manifest)
        return manifest

    if feeds.get("code") != 0:
        manifest.update(verify_status="preflight_failed")
        write_manifest(job_dir, manifest)
        return manifest

    msglist = feeds.get("msglist") or []
    tid = manifest.get("tid")
    matched = None
    if tid:
        matched = next(
            (x for x in msglist if str(x.get("tid")) == str(tid)), None
        )

    if matched and matched.get("content") == manifest.get("text"):
        # Matched by tid + full text. Require EXACTLY ONE image.
        pics = matched.get("pic", []) or []
        if len(pics) == 1:
            manifest.update(
                status="verified",
                image_count=1,
                verify_status="matched",
            )
            if not manifest.get("url"):
                manifest["url"] = mood_url(manifest["account"], tid)
        else:
            # Not exactly one image -> stay unverified, flag the mismatch.
            manifest.update(
                status="published_unverified",
                image_count=len(pics),
                verify_status="image_count_mismatch",
            )
            if not manifest.get("url"):
                manifest["url"] = mood_url(manifest["account"], tid)
    else:
        # No match within the 5 most recent feeds: do NOT assert not-published.
        manifest.update(
            verify_status="no_match" if not matched else "content_mismatch"
        )
    write_manifest(job_dir, manifest)
    return manifest


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

# Statuses that represent a clean (non-error) completion of a CLI stage. These
# map to exit code 0. Everything else (error / refused / rejected) is non-zero.
_OK_STATUSES = frozenset({
    "prepared",
    "published_unverified",
    "verified",
    "duplicate_skipped",
    "publish_outcome_unknown",
})


def _exit_code(manifest):
    if manifest.get("status") in _OK_STATUSES and \
            manifest.get("verify_status") != "inconclusive":
        return 0
    return 1


def _try_write(job_dir, manifest):
    try:
        if job_dir:
            write_manifest(job_dir, manifest)
    except Exception:
        pass


def _run_stage(job_dir, fn):
    """Run a stage fn that returns a manifest dict.

    Normalizes ALL exceptions to a safe, secret-free JSON result and never
    lets a traceback escape. Returns (manifest, exit_code).
    """
    try:
        manifest = fn()
        return manifest, _exit_code(manifest)
    except QzonePublisherError as e:
        manifest = {
            "status": "error",
            "stage": e.stage,
            "error_stage": e.stage,
            "error_category": e.category,
        }
        _try_write(job_dir, manifest)
        return manifest, 1
    except Exception:
        manifest = {
            "status": "error",
            "stage": "unexpected",
            "error_stage": "unexpected",
            "error_category": "UNEXPECTED_ERROR",
        }
        _try_write(job_dir, manifest)
        return manifest, 1


def load_request(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def cmd_prepare(args):
    manifest, code = _run_stage(
        args.job_dir,
        lambda: prepare_job(
            load_request(args.request), args.job_dir, args.state_dir, args.dryrun
        ),
    )
    print(json.dumps(public_result(manifest), ensure_ascii=False, indent=2))
    return code


def cmd_publish(args):
    manifest, code = _run_stage(
        args.job_dir,
        lambda: publish_job(
            args.job_dir,
            args.confirm_publish,
            args.confirm_account,
            confirm_visibility=args.confirm_visibility,
            confirm_digest=args.confirm_digest,
            state_dir=args.state_dir,
        ),
    )
    print(json.dumps(public_result(manifest), ensure_ascii=False, indent=2))
    return code


def cmd_verify(args):
    manifest, code = _run_stage(
        args.job_dir, lambda: verify_job(args.job_dir)
    )
    print(json.dumps(public_result(manifest), ensure_ascii=False, indent=2))
    return code


def build_parser():
    p = argparse.ArgumentParser(
        description="Qzone single-image + text publisher (NapCat-assisted)."
    )
    sub = p.add_subparsers(dest="command", required=True)

    pp = sub.add_parser("prepare", help="Offline planning step (no locks taken).")
    pp.add_argument("--request", required=True)
    pp.add_argument("--job-dir", required=True)
    pp.add_argument("--state-dir", default=DEFAULT_STATE_DIR)
    pp.add_argument("--dryrun", action="store_true",
                    help="Deprecated/no-op: prepare never takes a lock.")
    pp.set_defaults(func=cmd_prepare)

    pb = sub.add_parser("publish", help="Publish (requires explicit confirms).")
    pb.add_argument("--job-dir", required=True)
    pb.add_argument("--state-dir", default=DEFAULT_STATE_DIR)
    pb.add_argument("--confirm-publish", action="store_true")
    pb.add_argument("--confirm-account", default=None)
    pb.add_argument("--confirm-visibility", default=None,
                    help="Must be exactly 'api-default-public-risk'.")
    pb.add_argument("--confirm-digest", default=None,
                    help="Hex digest shown by prepare; recomputed and compared.")
    pb.set_defaults(func=cmd_publish)

    pv = sub.add_parser("verify", help="Read-only verification; never re-sends.")
    pv.add_argument("--job-dir", required=True)
    pv.set_defaults(func=cmd_verify)
    return p


def main(argv=None):
    try:
        args = build_parser().parse_args(argv)
        return args.func(args)
    except SystemExit:
        # argparse errors (bad args) -- let the system exit code stand; the
        # message is argparse's own usage text, not a raw traceback.
        raise
    except Exception:
        # Last-resort normalization (should be unreachable thanks to _run_stage).
        print(json.dumps(
            {"status": "error", "error_category": "UNEXPECTED_ERROR"},
            ensure_ascii=False,
        ))
        return 1


if __name__ == "__main__":
    sys.exit(main())
