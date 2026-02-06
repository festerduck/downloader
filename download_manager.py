#!/usr/bin/env python3
"""Download Manager CLI (authorized downloads only).

Usage:
  python download_manager.py --in urls.txt --out downloads --state audit.json
  python download_manager.py --in urls.txt --out downloads --header "Authorization: Bearer TOKEN" --max-concurrency 16

Features:
- Reads URLs (one per line or multiple per line) and downloads concurrently.
- Adaptive concurrency (AIMD) with per-host politeness caps.
- Retries retryable failures with exponential backoff + jitter.
- Resumes partial .part files using HTTP Range when supported.
- Progress logging every 2s and JSON audit output.
"""
import argparse, asyncio, contextlib, hashlib, json, math, os, random, re, ssl, time
from collections import Counter, deque
from pathlib import Path
from urllib.parse import urlparse, unquote

import aiofiles
import aiohttp

URL_RE = re.compile(r"https?://\S+")


def parse_args():
    p = argparse.ArgumentParser(description="Adaptive async download manager")
    p.add_argument("--in", dest="infile", required=True)
    p.add_argument("--out", required=True)
    p.add_argument("--concurrency", type=int, default=4)
    p.add_argument("--min-concurrency", type=int, default=1)
    p.add_argument("--max-concurrency", type=int, default=32)
    p.add_argument("--per-host", type=int, default=2)
    p.add_argument("--timeout", type=float, default=30)
    p.add_argument("--retries", type=int, default=4)
    p.add_argument("--window", type=float, default=5)
    p.add_argument("--user-agent", default="DownloadManager/1.0")
    p.add_argument("--header", action="append", default=[])
    p.add_argument("--cookies", help="Netscape cookie jar path")
    p.add_argument("--dry-run", action="store_true")
    p.add_argument("--force", action="store_true")
    p.add_argument("--state", required=True)
    p.add_argument("--checksums", help="Optional sha256 file: '<sha256> <filename>' per line")
    return p.parse_args()


def load_urls(path: str):
    urls = []
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        urls.extend(URL_RE.findall(line))
    return urls


def parse_headers(items):
    h = {}
    for item in items:
        if ":" not in item:
            continue
        k, v = item.split(":", 1)
        h[k.strip()] = v.strip()
    return h


def load_netscape_cookies(path):
    out = {}
    if not path:
        return out
    for line in Path(path).read_text(encoding="utf-8", errors="ignore").splitlines():
        if not line or line.startswith("#"):
            continue
        parts = line.split("\t")
        if len(parts) >= 7:
            out[parts[5]] = parts[6]
    return out


def load_checksums(path):
    m = {}
    if not path:
        return m
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        parts = line.split()
        if len(parts) >= 2:
            m[parts[1].lstrip("*./")] = parts[0].lower()
    return m


def file_name_for(url):
    name = unquote(Path(urlparse(url).path).name) or "download.bin"
    return re.sub(r"[^A-Za-z0-9._-]", "_", name)


def classify_http(status):
    if status in (401, 403): return "auth", False
    if status == 404: return "not_found", False
    if status == 429: return "rate_limit", True
    if status in (408,) or 500 <= status <= 599: return "transient", True
    if 200 <= status < 300: return "ok", False
    return "http_error", False


class Manager:
    def __init__(self, args, urls):
        self.a, self.urls = args, deque(urls)
        self.out = Path(args.out); self.out.mkdir(parents=True, exist_ok=True)
        self.results, self.inflight = [], set()
        self.host_busy = Counter()
        self.cur = max(args.min_concurrency, min(args.concurrency, args.max_concurrency))
        self.ema_latency, self.alpha = None, 0.2
        self.window_events = []
        self.cooldown_until = 0.0
        self.counts = Counter()
        self.checksums = load_checksums(args.checksums)

    async def head_len(self, session, url):
        try:
            async with session.head(url, allow_redirects=True) as r:
                if r.status < 400 and r.headers.get("Content-Length"):
                    return int(r.headers["Content-Length"])
        except Exception:
            return None
        return None

    async def download_one(self, session, url):
        t0 = time.time(); retries = 0
        host = urlparse(url).netloc
        name = file_name_for(url)
        final = self.out / name
        part = self.out / (name + ".part")
        expected = await self.head_len(session, url)

        if final.exists() and not self.a.force and expected is not None and final.stat().st_size == expected:
            return {"url": url, "status": "skipped", "http_status": 0, "bytes": final.stat().st_size, "seconds": 0, "retries": 0, "final_filepath": str(final), "error": ""}

        if self.a.dry_run:
            return {"url": url, "status": "planned", "http_status": 0, "bytes": 0, "seconds": 0, "retries": 0, "final_filepath": str(final), "error": "dry-run"}

        while True:
            offset = part.stat().st_size if part.exists() else 0
            headers = {"User-Agent": self.a.user_agent}
            headers.update(parse_headers(self.a.header))
            if offset > 0:
                headers["Range"] = f"bytes={offset}-"
            try:
                async with session.get(url, headers=headers) as r:
                    kind, retryable = classify_http(r.status)
                    if r.status == 429:
                        ra = r.headers.get("Retry-After")
                        wait = float(ra) if ra and ra.isdigit() else 1.5
                        self.window_events.append("rate_limit")
                        await asyncio.sleep(wait)
                        raise RuntimeError("429")
                    if kind != "ok":
                        raise RuntimeError(f"http:{r.status}:{kind}:{int(retryable)}")

                    if offset > 0 and r.status == 200:
                        part.unlink(missing_ok=True)
                        offset = 0
                    mode = "ab" if offset and r.status == 206 else "wb"
                    got = offset
                    async with aiofiles.open(part, mode) as f:
                        async for chunk in r.content.iter_chunked(1 << 16):
                            await f.write(chunk)
                            got += len(chunk)
                    exp = expected
                    if exp is None and r.headers.get("Content-Length"):
                        exp = int(r.headers["Content-Length"]) + (offset if r.status == 206 else 0)
                    if exp is not None and got != exp:
                        raise RuntimeError(f"size_mismatch:{got}!={exp}")
                    part.replace(final)
                    ch = self.checksums.get(final.name)
                    if ch:
                        h = hashlib.sha256()
                        async with aiofiles.open(final, "rb") as f:
                            while b := await f.read(1 << 16):
                                h.update(b)
                        if h.hexdigest().lower() != ch:
                            raise RuntimeError("checksum_mismatch")
                    dt = time.time() - t0
                    return {"url": url, "status": "ok", "http_status": r.status, "bytes": got, "seconds": round(dt, 3), "retries": retries, "final_filepath": str(final), "error": ""}
            except (aiohttp.ClientConnectorError,) as e:
                err, retryable = f"dns_tls:{e.__class__.__name__}", False
            except (aiohttp.ClientSSLError, ssl.SSLError) as e:
                err, retryable = f"dns_tls:{e.__class__.__name__}", False
            except asyncio.TimeoutError:
                err, retryable = "timeout", True
            except RuntimeError as e:
                s = str(e)
                if s.startswith("http:"):
                    _, sc, k, rt = s.split(":")
                    err, retryable = k, rt == "1"
                elif s == "429":
                    err, retryable = "rate_limit", True
                else:
                    err, retryable = s, True
            except Exception as e:
                err, retryable = f"error:{e.__class__.__name__}", False

            retries += 1
            self.window_events.append(err)
            if retries > self.a.retries or not retryable:
                dt = time.time() - t0
                return {"url": url, "status": "failed", "http_status": 0, "bytes": part.stat().st_size if part.exists() else 0, "seconds": round(dt, 3), "retries": retries - 1, "final_filepath": str(final), "error": err}
            base = 0.7 * (2 ** (retries - 1))
            await asyncio.sleep(min(20, base + random.uniform(0, 0.8)))

    async def worker_task(self, session, url):
        host = urlparse(url).netloc
        self.host_busy[host] += 1
        t0 = time.time()
        try:
            res = await self.download_one(session, url)
            dt = time.time() - t0
            self.ema_latency = dt if self.ema_latency is None else (self.alpha * dt + (1 - self.alpha) * self.ema_latency)
            return res
        finally:
            self.host_busy[host] -= 1

    async def progress_loop(self):
        while self.urls or self.inflight:
            print(f"pending={len(self.urls)} inflight={len(self.inflight)} ok={self.counts['ok']} failed={self.counts['failed']} skipped={self.counts['skipped']} conc={self.cur} ema={0 if self.ema_latency is None else round(self.ema_latency,2)}")
            await asyncio.sleep(2)

    def adapt(self):
        now = time.time()
        if now < self.cooldown_until:
            self.window_events.clear(); return
        events = set(self.window_events)
        if "rate_limit" in events:
            self.cur = max(self.a.min_concurrency, math.floor(self.cur * 0.5))
            self.cooldown_until = now + 15
        elif any(e in events for e in ("transient", "timeout")):
            self.cur = max(self.a.min_concurrency, math.floor(self.cur * 0.7))
            self.cooldown_until = now + 8
        elif (self.ema_latency or 0) <= 8:
            self.cur = min(self.a.max_concurrency, self.cur + 1)
        self.window_events.clear()

    async def run(self):
        timeout = aiohttp.ClientTimeout(total=self.a.timeout)
        cookies = load_netscape_cookies(self.a.cookies)
        hdrs = {"User-Agent": self.a.user_agent, **parse_headers(self.a.header)}
        connector = aiohttp.TCPConnector(limit=0, ttl_dns_cache=300)
        async with aiohttp.ClientSession(timeout=timeout, headers=hdrs, cookies=cookies, connector=connector) as session:
            prog = asyncio.create_task(self.progress_loop())
            last_window = time.time()
            while self.urls or self.inflight:
                launched = False
                while self.urls and len(self.inflight) < self.cur:
                    url = self.urls[0]
                    host = urlparse(url).netloc
                    if self.host_busy[host] >= self.a.per_host:
                        break
                    self.urls.popleft()
                    t = asyncio.create_task(self.worker_task(session, url))
                    self.inflight.add(t)
                    launched = True
                if not self.inflight:
                    await asyncio.sleep(0.05)
                    continue
                done, _ = await asyncio.wait(self.inflight, timeout=0.3, return_when=asyncio.FIRST_COMPLETED)
                for d in done:
                    self.inflight.remove(d)
                    res = d.result()
                    self.results.append(res)
                    self.counts[res["status"]] += 1
                    if res["status"] == "failed":
                        self.window_events.append(res["error"])
                if not done and not launched:
                    await asyncio.sleep(0.05)
                if time.time() - last_window >= self.a.window:
                    self.adapt()
                    last_window = time.time()
            prog.cancel()
            with contextlib.suppress(Exception):
                await prog


async def main():
    args = parse_args()
    urls = load_urls(args.infile)
    if not urls:
        print("No URLs found.")
        return 2
    mgr = Manager(args, urls)
    await mgr.run()
    summary = {
        "total": len(urls),
        "ok": mgr.counts["ok"],
        "failed": mgr.counts["failed"],
        "skipped": mgr.counts["skipped"],
        "planned": mgr.counts["planned"],
        "final_concurrency": mgr.cur,
        "ema_latency": mgr.ema_latency,
    }
    Path(args.state).write_text(json.dumps({"summary": summary, "results": mgr.results}, indent=2), encoding="utf-8")
    return 0 if mgr.counts["failed"] == 0 else 2


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
