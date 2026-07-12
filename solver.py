#!/usr/bin/env python3
"""
Cloudflare Turnstile / CloudFront WAF cookie solver.

Solves the challenge ONCE with Playwright headed mode on Xvfb,
exports cookies for replay with curl. Achieves 0% block rate
on bulk lookups by separating challenge-solve from data fetching.

Usage:
  # Solve and save cookies
  python3 turnstile_cookie_solver.py solve --url https://target.com/page --out cookies.json

  # Print cookie string for curl
  python3 turnstile_cookie_solver.py print --cookies cookies.json

  # Test if cookies still work
  python3 turnstile_cookie_solver.py test --url https://target.com/page --cookies cookies.json

  # Bulk lookup with auto-refresh
  python3 turnstile_cookie_solver.py bulk --url-template 'https://target.com/name/{slug}' \
    --input names.txt --cookies cookies.json --out results.csv --delay 0.6

Prerequisites:
  pip install playwright && playwright install chromium
  apt-get install -y xvfb  (or use existing Xvfb on :99)
"""
import argparse, csv, json, os, re, signal, subprocess, sys, time

UA = ('Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 '
      '(KHTML, like Gecko) Chrome/148.0.0.0 Safari/537.36')

def ensure_xvfb(display=':99'):
    try:
        result = subprocess.run(['pgrep', '-a', 'Xvfb'], capture_output=True, text=True)
        if display in result.stdout:
            return display
    except:
        pass
    subprocess.Popen(
        ['Xvfb', display, '-screen', '0', '1280x720x24', '-ac'],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
    )
    time.sleep(1)
    return display

def solve_turnstile(url, cookie_file, display=':99', domain_filter=None, timeout=60):
    display = ensure_xvfb(display)
    os.environ['DISPLAY'] = display

    from playwright.sync_api import sync_playwright
    with sync_playwright() as p:
        browser = p.chromium.launch(
            headless=False,
            args=[
                '--no-sandbox',
                '--disable-blink-features=AutomationControlled',
                f'--display={display}'
            ]
        )
        ctx = browser.new_context(user_agent=UA)
        page = ctx.new_page()

        print(f'[solve] Loading {url}', flush=True)
        page.goto(url, timeout=30000)
        page.wait_for_timeout(5000)

        if 'challenge' in page.url.lower():
            print('[solve] Challenge detected, solving...', flush=True)
            page.wait_for_timeout(3000)

            # Try Turnstile widget
            for selector in ['#turnstile-widget', 'iframe[src*="turnstile"]',
                             '.cf-turnstile', '[data-sitekey]']:
                el = page.locator(selector)
                if el.count() > 0:
                    box = el.first.bounding_box()
                    if box:
                        page.mouse.click(
                            box['x'] + box['width'] / 2,
                            box['y'] + box['height'] / 2
                        )
                        print(f'[solve] Clicked {selector}', flush=True)
                        break

            page.wait_for_timeout(15000)

        cookies = ctx.cookies()
        if domain_filter:
            cookies = [c for c in cookies if domain_filter in c.get('domain', '')]

        with open(cookie_file, 'w') as f:
            json.dump(cookies, f, indent=2)

        print(f'[solve] Saved {len(cookies)} cookies to {cookie_file}', flush=True)

        # Show key cookie TTLs
        for c in cookies:
            if c.get('httpOnly'):
                exp = c.get('expires', -1)
                if exp > 0:
                    remaining = (exp - time.time()) / 86400
                    print(f'  {c["name"]:20s} expires in {remaining:.1f} days', flush=True)

        browser.close()
    return cookies

def load_cookie_str(cookie_file):
    with open(cookie_file) as f:
        cookies = json.load(f)
    return '; '.join(f'{c["name"]}={c["value"]}' for c in cookies)

def curl_get(url, cookie_str, timeout=10):
    try:
        r = subprocess.run(
            ['curl', '-s', '-w', '\n%{http_code}',
             '-H', f'Cookie: {cookie_str}',
             '-H', f'User-Agent: {UA}',
             '--compressed', '--max-time', str(timeout),
             url],
            capture_output=True, text=True, timeout=timeout + 5
        )
        lines = r.stdout.rstrip().split('\n')
        code = lines[-1]
        body = '\n'.join(lines[:-1])
        return int(code), body
    except Exception as e:
        return 0, str(e)

def test_cookies(url, cookie_file):
    cookie_str = load_cookie_str(cookie_file)
    code, body = curl_get(url, cookie_str)
    blocked = code == 403 or 'challenge' in body[:500].lower()
    print(f'[test] HTTP {code} | blocked={blocked} | body_len={len(body)}', flush=True)
    return not blocked

def bulk_lookup(url_template, input_file, cookie_file, output_file,
                delay=0.6, refresh_url=None, domain_filter=None,
                extract_patterns=None):
    cookie_str = load_cookie_str(cookie_file)

    with open(input_file) as f:
        slugs = [line.strip() for line in f if line.strip()]

    new_file = not os.path.exists(output_file) or os.path.getsize(output_file) == 0
    fout = open(output_file, 'a', newline='')
    writer = csv.writer(fout)
    if new_file:
        cols = ['slug', 'http_code'] + list((extract_patterns or {}).keys())
        writer.writerow(cols)

    ok = 0
    blocks = 0
    consecutive_blocks = 0
    start = time.time()

    running = True
    def stop(sig, frame):
        nonlocal running
        running = False
    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)

    for i, slug in enumerate(slugs):
        if not running:
            break

        url = url_template.replace('{slug}', slug)
        code, body = curl_get(url, cookie_str)

        if code in (403, 302) or (code == 200 and 'challenge' in body[:500].lower()):
            consecutive_blocks += 1
            blocks += 1
            if consecutive_blocks >= 5:
                print(f'[bulk] Blocked x{consecutive_blocks}, refreshing...', flush=True)
                rurl = refresh_url or url_template.replace('{slug}', 'test-test')
                solve_turnstile(rurl, cookie_file, domain_filter=domain_filter)
                cookie_str = load_cookie_str(cookie_file)
                consecutive_blocks = 0
                time.sleep(3)
            else:
                time.sleep(2)
            continue

        consecutive_blocks = 0
        ok += 1

        row = [slug, code]
        for name, pattern in (extract_patterns or {}).items():
            m = re.findall(pattern, body)
            row.append(m[0] if m else '')
        writer.writerow(row)

        if ok % 50 == 0:
            fout.flush()

        if (i + 1) % 100 == 0:
            elapsed = time.time() - start
            rate = ok / max(elapsed, 1) * 3600
            print(f'[{i+1}/{len(slugs)}] ok={ok} blk={blocks} '
                  f'rate={rate:.0f}/hr', flush=True)

        time.sleep(delay)

    fout.close()
    elapsed = (time.time() - start) / 3600
    print(f'[done] ok={ok} blocks={blocks} elapsed={elapsed:.1f}h', flush=True)

def main():
    parser = argparse.ArgumentParser(description='Turnstile cookie solver + bulk lookup')
    sub = parser.add_subparsers(dest='cmd')

    s = sub.add_parser('solve', help='Solve Turnstile and save cookies')
    s.add_argument('--url', required=True)
    s.add_argument('--out', default='cookies.json')
    s.add_argument('--domain-filter', default=None, help='Only keep cookies matching this domain substring')
    s.add_argument('--display', default=':99')

    t = sub.add_parser('print', help='Print cookie string for curl')
    t.add_argument('--cookies', default='cookies.json')

    v = sub.add_parser('test', help='Test if cookies still work')
    v.add_argument('--url', required=True)
    v.add_argument('--cookies', default='cookies.json')

    b = sub.add_parser('bulk', help='Bulk lookup with auto-refresh')
    b.add_argument('--url-template', required=True, help='URL with {slug} placeholder')
    b.add_argument('--input', required=True, help='File with one slug per line')
    b.add_argument('--cookies', default='cookies.json')
    b.add_argument('--out', default='results.csv')
    b.add_argument('--delay', type=float, default=0.6)
    b.add_argument('--refresh-url', default=None)
    b.add_argument('--domain-filter', default=None)
    b.add_argument('--extract', nargs='*', default=[], help='name=regex pairs for extraction')

    args = parser.parse_args()

    if args.cmd == 'solve':
        solve_turnstile(args.url, args.out, args.display, args.domain_filter)
    elif args.cmd == 'print':
        print(load_cookie_str(args.cookies))
    elif args.cmd == 'test':
        ok = test_cookies(args.url, args.cookies)
        sys.exit(0 if ok else 1)
    elif args.cmd == 'bulk':
        patterns = {}
        for pair in args.extract:
            name, regex = pair.split('=', 1)
            patterns[name] = regex
        bulk_lookup(args.url_template, args.input, args.cookies, args.out,
                    args.delay, args.refresh_url, args.domain_filter, patterns)
    else:
        parser.print_help()

if __name__ == '__main__':
    main()
