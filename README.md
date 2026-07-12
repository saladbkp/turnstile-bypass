# Cloudflare Turnstile Bypass — Solve Once, Replay Forever

Bypass Cloudflare Turnstile / CloudFront WAF challenges for bulk lookups with **0% block rate**.

## How It Works

Turnstile has two layers:

1. **Challenge layer** — JavaScript widget validates the browser is real
2. **Session layer** — on success, sets a server-side cookie (`_ss`, `cf_clearance`, etc.)

The trick: **solve the challenge once with a real browser, save the cookie, then replay it with `curl` for unlimited requests.**

### Why It Works

| Detection | Bypass |
|---|---|
| Turnstile checks **headless mode** (no GPU, no display, missing APIs) | Use **headed browser + Xvfb virtual display** — looks like a real desktop |
| Turnstile checks `navigator.webdriver === true` | Launch Chromium with `--disable-blink-features=AutomationControlled` |
| CloudFront/Cloudflare validates session cookie per request | **Save `_ss` cookie** after solve, replay with `curl` |
| Cloudflare fingerprints **User-Agent** and ties it to the session | Use the **exact same UA string** in both Playwright and `curl` |
| Rate limiting on rapid requests | **0.6s delay** between requests (~1,600 req/hr) — sweet spot |

### The Flow

```
┌─────────────────────────────────────────────────────────┐
│  1. Xvfb :99              (virtual display)             │
│  2. Playwright headed      (real browser on Xvfb)       │
│  3. Click Turnstile widget (solve challenge)            │
│  4. Export cookies         (save _ss to JSON)           │
│  5. curl + cookies         (bulk requests, 0% block)    │
│  6. Auto-refresh           (re-solve when 302/403)      │
└─────────────────────────────────────────────────────────┘
```

## Install

```bash
# Dependencies
pip install playwright
playwright install chromium
sudo apt-get install -y xvfb curl

# Start virtual display (once)
Xvfb :99 -screen 0 1280x720x24 -ac &
export DISPLAY=:99
```

## Usage

### 1. Solve Turnstile and save cookies

```bash
python3 solver.py solve \
  --url https://target.com/some-page \
  --out cookies.json \
  --domain-filter target.com
```

### 2. Use cookies with curl

```bash
# Get cookie string
COOKIES=$(python3 solver.py print --cookies cookies.json)

# Make requests
curl -s \
  -H "Cookie: $COOKIES" \
  -H "User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/148.0.0.0 Safari/537.36" \
  --compressed \
  'https://target.com/lookup/John-Smith'
```

### 3. Test if cookies are still valid

```bash
python3 solver.py test \
  --url https://target.com/some-page \
  --cookies cookies.json
```

### 4. Bulk lookup with auto cookie refresh

```bash
python3 solver.py bulk \
  --url-template 'https://target.com/name/{slug}' \
  --input slugs.txt \
  --cookies cookies.json \
  --out results.csv \
  --delay 0.6 \
  --domain-filter target.com \
  --extract 'phone="telephone"\s*:\s*\["?\+1-(\d{3}-\d{3}-\d{4})'
```

## Key Details

### Cookie Lifetime

| Service | Cookie | TTL |
|---|---|---|
| CloudFront WAF | `_ss` | 7–30 days |
| Cloudflare Turnstile | `cf_clearance` | 30 min – 24 hr |
| hCaptcha | `hc_accessibility` | 1 day |
| Akamai Bot Manager | `_abck` | 1 hour |

The `_ss` cookie has a 30-day expiry but the **server-side session can invalidate earlier** (~24 hours observed). The auto-refresh handles this.

### Block Detection — Watch for 302!

Some sites don't return `403` when cookies expire — they **302 redirect to `/challenge`**. Always check both:

```python
# WRONG — misses 302 redirect blocks
if code == 403 or 'challenge' in body:

# RIGHT
if code in (403, 302) or 'challenge' in body:
```

### The 0.6s Delay

0.6 seconds between requests is the sweet spot:
- **Faster than 0.3s** → risk of IP-based rate limiting
- **Slower than 1.0s** → unnecessarily slow
- **0.6s** = ~1,600 req/hr, zero blocks over 290K+ requests tested

### User-Agent Must Match

Cloudflare ties the session cookie to the UA string used during the solve. If curl sends a different UA, you get blocked. Always use the same UA in both Playwright and curl.

## Proven Results

Tested on ThatsThem (CloudFront WAF + Turnstile):

- **290,000+ requests** over multiple days
- **0% block rate** (30 auto-refreshed blocks across entire run)
- **93–99% data hit rate**
- **~880 req/hr** sustained
- **3 automatic cookie refreshes** — zero manual intervention

## Limitations

- IP-based rate limits still apply on some sites (regardless of cookies)
- Akamai `_abck` rotates aggressively (1hr) — needs more frequent refresh
- Some Turnstile deployments use `managed` mode (invisible) — no widget to click; wait 20s and let it auto-solve
- If the site fingerprints TLS (JA3/JA4), curl's fingerprint differs from Chrome — use [`curl-impersonate`](https://github.com/lwthiker/curl-impersonate) instead

## License

MIT

## 人话

发现可以用 headed browser +xvfb monitor access
因为 turnstile 会check headless mode 所以 xvfb monitor 可以bypass
然后还会check navigator webdriver = true, 所以一定要 --disable-blink-features=automationcontrolled
解锁了 要靠cookie save 了 `_ss`  然后就用curl access
记住这个0.6 delay 最美
ua 一点要一样在 curl 因为cloudflare 会记住
