# Protocol & Provenance Notes (references/protocol.md)

## Source and license

- The original working one-shot script was adapted by the user from the public
  project **`Zhalslar/astrbot_plugin_qzone`** (URL used **only as a field
  reference** for the Qzone CGI parameters).
- **No source code from that project was copied into this skill.** The publisher
  logic in `scripts/qzone_publisher.py` was rewritten from scratch based on the
  observed working behavior of the user's script.
- The upstream project's license is **not verified/known** to the authors of this
  skill. This skill therefore makes **no claim of being licensed under any
  specific open-source license derived from that project**. If you redistribute
  this skill, treat it as independently written; do not assert an upstream
  license grant that has not been confirmed.

## Trust boundary: NapCat (local) vs Qzone (remote)

Two distinct credential/transport layers are involved. Both are handled with the
minimum necessary scope.

### Layer 1 — NapCat WebUI (loopback only)
- Base URL: `http://127.0.0.1:<loopback_port>/api`
- The host is **enforced to be exactly `127.0.0.1`**. The literal `localhost`,
  IPv6 loopback (`::1`, `[::1]`), and any other loopback IP (e.g. `127.0.0.2`)
  are all rejected before any request is made (`enforce_loopback`). Only the
  IPv4 literal `127.0.0.1` is accepted.
- Authentication uses the NapCat WebUI config file
  (`C:/NapCat/napcat/config/webui.json` by default, overridable via the request
  JSON `config_path`). The `token` field is read once into memory, hashed with
  `sha256(token + ".napcat")`, and sent to `/auth/login`. The returned
  `Credential` is kept **only in memory**.
- Endpoints used:
  - `POST /api/auth/login` — exchange hashed token for a session credential.
  - `POST /api/QQLogin/GetQQLoginInfo` — read `uin` and `online` status.
  - `POST /api/Debug/call` with `action=get_cookies`,
    `params.domain=user.qzone.qq.com` — obtain the Qzone cookies.
- Credentials (the `Credential`, cookies, `skey`/`p_skey`, computed `g_tk`) are
  **never written to disk or to command output**.

### Layer 2 — Qzone CGI (fixed HTTPS domains only)
- All external requests go through `enforce_qzone_domain`, which permits only:
  - `https://user.qzone.qq.com` (feeds preflight + publish, via proxy domain)
  - `https://up.qzone.qq.com` (image upload)
- Requests use **HTTPS only**; non-HTTPS URLs are rejected.
- The urllib transport uses an opener with **no environment proxy** and **no
  redirect following** (`ProxyHandler({})` + a redirect handler that raises).
- Endpoints used (field reference from the upstream project):
  - `GET .../emotion_cgi_msglist_v6` — read recent feeds (preflight + verify).
  - `POST .../cgi_upload_image` — upload a single base64-encoded image.
  - `POST .../emotion_cgi_publish_v6` — publish the mood (text + richval image).
- The publish request includes the standard Qzone form fields
  (`syn_tweet_verson`, `paramstr`, `who`, `con`, `hostuin`, `ugc_right`,
  `pic_bo`, `richtype`, `richval`, etc.). These are **data fields**, not copied
  code; they mirror the upstream API contract.

## g_tk computation
`g_tk` is the BKDR-style hash of the Qzone login key (`p_skey` or `skey`):
```
gtk = 5381
for ch in key: gtk += (gtk << 5) + ord(ch)
gtk = str(gtk & 0x7fffffff)
```
This matches the conventional Qzone client computation.

## Visibility / privacy
- This first version does **not** implement a user-selectable privacy or
  visibility setting. The publication uses whatever visibility the underlying
  API applies by default (effectively **public**). Do not advertise "specify
  privacy" capability.
- `publish` requires the explicit flag `--confirm-visibility api-default-public-risk`.
  This forces the operator to acknowledge that fine-grained visibility is NOT
  guaranteed. **If the user requires a private post, refuse to publish with this
  skill** and direct them to an official client.
- The `request_digest` printed by `prepare` and confirmed at `publish` is a plain
  SHA-256 over `account + text + image_sha256 + visibility_policy`. It is a
  **content-integrity / preview-confirmation aid only**: the user previews the
  manifest, confirms the digest matches, and `publish` re-checks both the digest
  and the image SHA-256. It is **NOT** an HMAC and **NOT** a cryptographic
  signature. It does **NOT** authenticate the publisher and does **NOT** protect
  against a malicious local attacker who can tamper with files or memory. Do not
  describe it as identity authentication, tamper-proofing, or local-attack
  defense.

## verify: exactly-one-image and the recent-5 window
- `verify` matches the published item by `tid` + full text, then requires
  **exactly one** image. With 0 or 2+ images it stays `published_unverified`
  (`verify_status=image_count_mismatch`) and is NOT marked verified.
- `verify` reads **only the 5 most recent feeds** (`num=5`). If the `tid` is not
  found among them, that must **NOT** be treated as proof that the item was not
  published — it may simply lie outside the recent window. `verify` therefore
  leaves the status as `published_unverified` and never asserts "not published".

## Risk control / captcha
- These endpoints are **unofficial** and may be subject to Tencent risk control.
- If a captcha / risk-control challenge is encountered (e.g., the API returns an
  error indicating verification is required), **stop immediately** and do not
  retry automatically. Manual intervention is required.
- Never attempt to bypass risk control.

## Locking: fingerprint moved to publish
- The per-job `O_EXCL` attempt lock still prevents double-send / auto-retry.
- The user-level fingerprint lock (`account + text + image hash`) is now taken in
  `publish`, **after** the explicit confirm gates (`--confirm-publish`,
  `--confirm-account`, `--confirm-visibility`, `--confirm-digest`) and **before**
  any network egress. `prepare` is fully offline and never creates this lock, so
  it does not occupy the user's publish lock. The fingerprint lock is permanent
  (never auto-deleted), which blocks cross-job duplicate publication of identical
  content.
