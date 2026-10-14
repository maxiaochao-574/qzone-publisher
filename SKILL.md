---
name: qzone-publisher
description: |
  This skill should be used when the user wants to publish a Qzone (QQ 空间)
  mood/talk with a single image plus text, assisted by a local NapCat instance.
  It supports ONLY verified single-image + text publication via a three-step
  offline-safe workflow (prepare then publish then verify). Use it for requests
  such as "发一条QQ空间带图说说", "publish a Qzone mood with one photo", or
  "把这张图连同文字发到QQ空间". It does NOT support video, multiple images, or a
  user-selectable privacy setting. The underlying Qzone API is unofficial and may
  be subject to platform risk control.
agent_created: true
---

# Qzone Publisher (single image + text)

## Overview

Publish a single image plus text to Qzone (QQ 空间) through a local NapCat
instance. The skill wraps a proven working flow into a safe, auditable CLI with
three stages:

1. **prepare** — fully offline: validates inputs, computes the image SHA-256 and
   a `request_digest`, and writes a `manifest.json`. It does NOT acquire any
   user-level lock, so it never occupies the user's publish lock.
2. **publish** — requires four explicit confirmations (`--confirm-publish`,
   `--confirm-account`, `--confirm-visibility api-default-public-risk`,
   `--confirm-digest <hex>`); only AFTER all confirm gates does it acquire the
   permanent user-level fingerprint lock and reach the network. It uploads the
   image and publishes. An `unknown` outcome is persisted *before* sending, and
   the per-job attempt lock is never auto-deleted or auto-retried.
3. **verify** — read-only re-check of the published tid, full text, and image
   count (must be exactly 1). It never re-sends.

## Trigger words / 触发词

- 中文：发QQ空间、QQ空间说说、带图说说、发空间动态、发布QQ空间、空间发图配文
- English：publish to Qzone, Qzone mood, QQ zone talk, post a Qzone photo with
  text, NapCat Qzone publish, single-image Qzone post

## Explicit authorization flow (IMPORTANT / 授权流程)

The publication posts to the user's real social account. Follow this exactly:

- **Explicitly authorized complete product:** If the user has clearly approved
  the final text, the final image, and the known API-default visibility policy
  for the *current, complete* item, `publish` may be executed directly (with the
  required `--confirm-publish`, `--confirm-account <UIN>`,
  `--confirm-visibility api-default-public-risk`, and `--confirm-digest <hex>`
  flags).
- **Vague or open-ended request:** If the request is a general "publish
  something" without an approved final text + image + visibility, **do NOT
  publish**. First run `prepare` (or `prepare --dryrun`), show the user the
  resolved `manifest.json` (account, text, image SHA-256, visibility policy,
  and the `request_digest`), and obtain explicit confirmation of the exact text,
  image, account, and visibility before running `publish`.
- `publish` will refuse to execute unless the confirms are supplied and the
  confirmed account matches the manifest. This is a hard safety gate, not
  advisory.

### `--confirm-visibility api-default-public-risk` (mandatory)

The underlying Qzone API applies a default visibility that is effectively
**public**. Fine-grained / private visibility is **NOT** supported or
guaranteed by this skill. Before every publish you MUST pass
`--confirm-visibility api-default-public-risk`, and you MUST make sure the user
understands:

- The skill cannot guarantee any specific fine-grained visibility.
- If the user requires a **private** post, **refuse to publish** with this
  skill and tell them to use an official client instead.

### `--confirm-digest <hex>` (mandatory, NOT a signature)

`prepare` computes a `request_digest` (SHA-256 over
`account + text + image_sha256 + visibility_policy`) and prints it. The user
previews the manifest, confirms it matches their intent, and passes that exact
hex to `--confirm-digest`. At publish time the digest is recomputed from the
manifest and compared for strict equality; the image SHA-256 is also re-checked
against the recorded value.

**This digest is a content-integrity / preview-confirmation aid only.** It is a
plain SHA-256, NOT an HMAC and NOT a cryptographic signature. It does **NOT**
authenticate the publisher, and it does **NOT** defend against a malicious local
attacker who can tamper with files or memory. Do not describe it as identity
authentication, tamper-proofing, or protection against local attacks.

## Input schema (request JSON for `prepare`)

`prepare` reads a request JSON file containing:

| field           | type   | required | meaning                                              |
|-----------------|--------|----------|------------------------------------------------------|
| `account`       | string | yes      | QQ UIN of the publishing account.                    |
| `text`          | string | yes      | Mood/talk body text.                                 |
| `image_path`    | string | yes      | **Absolute** local path to the single image.         |
| `config_path`   | string | no       | NapCat WebUI config; default `C:/NapCat/napcat/config/webui.json`. |
| `loopback_port` | int    | no       | NapCat loopback port; default `6099`.                |
| `napcat_host`   | string | no       | NapCat host; MUST be exactly `127.0.0.1`; default `127.0.0.1`. |

## Full command examples

```bash
# 1) Prepare (fully offline). Writes job-dir/manifest.json only. NO lock taken.
python scripts/qzone_publisher.py prepare \
  --request request.json \
  --job-dir ./jobs/job001 \
  --state-dir ./state

# Dry-run prepare: identical offline behavior (prepare never takes a lock).
python scripts/qzone_publisher.py prepare \
  --request request.json \
  --job-dir ./jobs/job001 \
  --state-dir ./state --dryrun

# 2) Publish. REQUIRES all four confirms; refuses otherwise. The permanent
#    fingerprint lock is taken here, only AFTER the confirms and BEFORE network.
python scripts/qzone_publisher.py publish \
  --job-dir ./jobs/job001 \
  --state-dir ./state \
  --confirm-publish --confirm-account 10001 \
  --confirm-visibility api-default-public-risk \
  --confirm-digest <hex printed by prepare>

# 3) Verify (read-only; never re-sends).
python scripts/qzone_publisher.py verify --job-dir ./jobs/job001
```

`request.json` example:
```json
{
  "account": "10001",
  "text": "今天的夕阳。",
  "image_path": "C:/abs/path/to/sunset.jpg",
  "config_path": "C:/NapCat/napcat/config/webui.json",
  "loopback_port": 6099
}
```

## Dependencies

- Python 3.8+ **standard library only** (no third-party packages).
- A locally running **NapCat** instance on `127.0.0.1:<loopback_port>` with the
  WebUI enabled and a valid `config/webui.json`.
- Outbound HTTPS access from the local machine to `user.qzone.qq.com` and
  `up.qzone.qq.com` (only these two domains; non-HTTPS and other hosts are
  blocked by the script).

## First-version limitations (v1)

- **Single image + text only.** No video, no multiple images, no album selection.
- **No user-selectable privacy/visibility.** Publication uses the default API
  visibility (effectively public). Do not claim "specify privacy" capability.
- The Qzone endpoints are **unofficial / reverse-engineered** and may break
  without notice; they may also trigger **platform risk control / captcha**.
- Network egress is intentionally constrained: NapCat is loopback-only; external
  requests are limited to the two HTTPS Qzone domains; environment proxies are
  ignored; redirects are rejected.
- Credentials (NapCat token, session credential, Qzone cookies, `skey`/`p_skey`,
  `g_tk`) are held **only in memory** and are never written to disk or to
  command output. Errors expose only a stage name + a whitelisted category.
- Safety locks:
  - per-job `O_EXCL` attempt lock (prevents double-send / auto-retry);
  - a **permanent** user-level fingerprint lock (`account + text + image hash`)
    acquired in `publish` (after the confirm gates, before network) to prevent
    cross-job duplicates. `prepare` does NOT create this lock.
  - `request_digest` (SHA-256 over account/text/image_sha256/visibility) shown
    by `prepare` and confirmed at `publish` for content-integrity preview only
    (see above — not a signature).
- A publish that returns success but no `tid` stays `publish_outcome_unknown`
  (manual check required). A publish with a `tid` is `published_unverified` until
  `verify` confirms it.
- **verify requires exactly one image.** If the published item has 0 or 2+
  images, it stays `published_unverified` with `verify_status=image_count_mismatch`
  and is NOT marked verified.
- **verify reads only the 5 most recent feeds.** If the tid is not found there,
  that does NOT prove the item was not published (it may simply be outside the
  recent window). `verify` therefore leaves the status as `published_unverified`
  and never asserts "not published".
- If the preflight space read fails, publishing stops. If identical text is
  already found, the run stops as `duplicate_skipped` and does **not** claim the
  image was verified — it only blocks a duplicate for the user to inspect.

## Platform / risk notes

- These are **unofficial APIs**. Tencent may rate-limit, reject, or challenge
  (captcha) such requests at any time.
- **Never attempt to bypass risk control or captcha.** If a challenge is
  encountered, stop and ask the user to resolve it manually; do not auto-retry.
- Treat the published content as public by default. Confirm visibility with the
  user if it matters (and refuse if private visibility is required).

## References

- `references/protocol.md` — transport/provenance details, the g_tk computation,
  the trust boundary (NapCat loopback vs Qzone remote), the visibility note, the
  `request_digest` clarification, the recent-5 verify limitation, and the
  license/attribution note (source project URL used as field reference only; no
  project code copied; upstream license not asserted).
- `scripts/qzone_publisher.py` — the implementation.
