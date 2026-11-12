"""OUROBOREX backend - live threat-intel ingestion, explainable ThreatScore, SignalGraph, SSE stream.

Run:  uvicorn main:app --port 8000      (open http://localhost:8000)
Env:  DEMO=1 (synthetic events, no internet)  REFRESH_SECONDS=120  HOME_LATLON="lat,lon"
"""
import asyncio, json, math, os, random, sqlite3, time
from contextlib import closing
from datetime import datetime, timezone, timedelta
from pathlib import Path

import httpx
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from fastapi.staticfiles import StaticFiles

FEED = "https://feodotracker.abuse.ch/downloads/ipblocklist.json"  # keyless, abuse.ch botnet C2 list
GEO_URL = "http://ip-api.com/batch?fields=status,query,lat,lon,country,countryCode,city"  # keyless
REFRESH = int(os.getenv("REFRESH_SECONDS", "120"))
HOME = [float(x) for x in os.getenv("HOME_LATLON", "20,0").split(",")]
DEMO = os.getenv("DEMO", "0") == "1"
DB = os.getenv("DB_PATH", str(Path(__file__).resolve().parent / "ouroborex.db"))
SRC_REP = {"feodo": 0.9, "demo": 0.5}

IND: dict = {}      # ip -> indicator
GEO: dict = {}      # ip -> geo cache
TREND: list = []    # [[ts, total]]
SUBS: set = set()
STATUS = {"mode": "demo" if DEMO else "starting", "last_ok": None, "error": None}

PLACES = [("US", "United States", 37.7, -122.4), ("DE", "Germany", 50.1, 8.7), ("NL", "Netherlands", 52.4, 4.9),
          ("RU", "Russia", 55.7, 37.6), ("CN", "China", 39.9, 116.4), ("BR", "Brazil", -23.5, -46.6),
          ("IN", "India", 19.0, 72.8), ("FR", "France", 48.9, 2.35), ("GB", "United Kingdom", 51.5, -0.1),
          ("SG", "Singapore", 1.35, 103.8), ("JP", "Japan", 35.7, 139.7), ("ZA", "South Africa", -26.2, 28.0)]
FAMS = ["Emotet", "QakBot", "Dridex", "TrickBot", "BazarLoader", "IcedID"]


def now_iso():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def ts_of(x):
    s = x.get("last_online") or x.get("first_seen") or ""
    for f in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d"):
        try:
            return datetime.strptime(s, f).replace(tzinfo=timezone.utc).timestamp()
        except ValueError:
            pass
    return time.time()


def score(v, fam_n):
    """P = 100*(0.40R + 0.25F + 0.20I + 0.15C) - deterministic and explainable."""
    h = max(0.0, (time.time() - v["seen_ts"]) / 3600)
    R = SRC_REP.get(v["src"], 0.5)                  # source reputation
    F = math.exp(-h / 72)                           # freshness (72h decay)
    I = 1.0 if v["status"] == "online" else 0.35    # infrastructure activity
    C = min(1.0, fam_n / 10)                        # corroboration: same-family indicators
    return round(100 * (0.40 * R + 0.25 * F + 0.20 * I + 0.15 * C)), {"R": R, "F": round(F, 2), "I": I, "C": round(C, 2)}


def enriched():
    fam = {}
    for v in IND.values():
        fam[v["fam"]] = fam.get(v["fam"], 0) + 1
    out = []
    for v in IND.values():
        P, parts = score(v, fam[v["fam"]])
        out.append({**v, "score": P, "parts": parts})
    return sorted(out, key=lambda z: -z["score"])


def emit(v):
    n = sum(1 for z in IND.values() if z["fam"] == v["fam"])
    ev = {"type": "indicator", "ip": v["ip"], "lat": v["lat"], "lon": v["lon"], "fam": v["fam"],
          "cc": v["cc"], "score": score(v, n)[0]}
    for q in list(SUBS):
        try:
            q.put_nowait(ev)
        except asyncio.QueueFull:
            pass


async def geolocate(c, ips):
    for i in range(0, len(ips), 100):
        r = await c.post(GEO_URL, json=ips[i:i + 100])
        r.raise_for_status()
        for g in r.json():
            if g.get("status") == "success":
                GEO[g["query"]] = g
        await asyncio.sleep(4.5)  # free tier: 15 batch calls / minute


async def pull():
    async with httpx.AsyncClient(timeout=25, headers={"User-Agent": "ouroborex/0.1"}) as c:
        r = await c.get(FEED)
        r.raise_for_status()
        data = r.json()
        rows = data if isinstance(data, list) else data.get("data", [])
        rows = sorted(rows, key=ts_of, reverse=True)[:400]
        await geolocate(c, [x["ip_address"] for x in rows if x["ip_address"] not in GEO])
    fresh = {}
    for x in rows:
        g = GEO.get(x["ip_address"])
        if not g:
            continue
        fresh[x["ip_address"]] = {
            "ip": x["ip_address"], "port": x.get("port"), "status": x.get("status", "unknown"),
            "fam": x.get("malware") or "unknown", "asn": f"AS{x.get('as_number') or '?'}",
            "asname": x.get("as_name"), "cc": g["countryCode"], "country": g["country"],
            "city": g.get("city"), "lat": g["lat"], "lon": g["lon"], "seen_ts": ts_of(x), "src": "feodo"}
    if not fresh:
        raise RuntimeError("feed returned no geolocated indicators; keeping previous data")
    had = any(v["src"] == "feodo" for v in IND.values())
    new = [k for k in fresh if k not in IND or IND[k]["src"] == "demo"]
    IND.clear()
    IND.update(fresh)
    if had:
        for k in new[:15]:
            emit(IND[k])


def demo_add(n):
    for _ in range(n):
        cc, country, lat, lon = random.choice(PLACES)
        ip = ".".join(str(random.randint(11, 223)) for _ in range(4))
        v = {"ip": ip, "port": random.choice([443, 8080, 447, 995]), "status": random.choice(["online", "online", "offline"]),
             "fam": random.choice(FAMS), "asn": f"AS{random.randint(1000, 60000)}", "asname": "demo-net",
             "cc": cc, "country": country, "city": "-", "lat": lat + random.uniform(-3, 3), "lon": lon + random.uniform(-3, 3),
             "seen_ts": time.time() - random.randint(0, 200) * 3600, "src": "demo"}
        IND[ip] = v
        emit(v)
    while len(IND) > 400:
        IND.pop(next(iter(IND)))


def _conn():
    c = sqlite3.connect(DB)
    c.execute("create table if not exists ind(ip text primary key, data text)")
    c.execute("create table if not exists trend(ts integer primary key, n integer)")
    return c


def load():
    """Restore last live indicators + trend so a restart never shows an empty dashboard."""
    with closing(_conn()) as c:
        for (d,) in c.execute("select data from ind"):
            v = json.loads(d)
            IND[v["ip"]] = v
        TREND.extend([list(r) for r in c.execute("select ts,n from trend order by ts desc limit 120")][::-1])
    if IND:
        STATUS["mode"] = "cached"


def save(rows, trend):
    with closing(_conn()) as c, c:
        c.execute("delete from ind")
        c.executemany("insert into ind values(?,?)", rows)
        c.executemany("insert or replace into trend values(?,?)", trend)


async def persist():
    rows = [(v["ip"], json.dumps(v)) for v in list(IND.values()) if v["src"] == "feodo"]
    await asyncio.to_thread(save, rows, [tuple(t) for t in TREND[-120:]])


async def runner():
    last = 0.0
    while True:
        if not DEMO and time.time() - last >= REFRESH:
            last = time.time()
            try:
                await pull()
                STATUS.update(mode="live", last_ok=now_iso(), error=None)
                await persist()
            except Exception as e:  # network down, rate limit, bad payload
                STATUS["error"] = f"{type(e).__name__}: {str(e)[:100]}"
        if DEMO or (STATUS["mode"] not in ("live", "cached") and not IND):
            STATUS["mode"] = "demo"
            demo_add(80 if len(IND) < 80 else random.randint(1, 2))
        TREND.append([int(time.time()), len(IND)])
        del TREND[:-120]
        await asyncio.sleep(5)


app = FastAPI(title="OUROBOREX")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["GET"])


@app.on_event("startup")
async def _start():
    if not DEMO:
        await asyncio.to_thread(load)
    asyncio.create_task(runner())


@app.get("/api/v1/health")
async def health():
    return {"ok": True, **STATUS, "indicators": len(IND)}


@app.get("/api/v1/snapshot")
async def snapshot():
    pts = enriched()
    top = pts[:120]
    els, seen = [], set()

    def node(i, label, typ, sc=0):
        if i not in seen:
            seen.add(i)
            els.append({"data": {"id": i, "label": label, "type": typ, "score": sc}})

    def edge(a, b, rel):
        els.append({"data": {"id": f"{a}>{b}", "source": a, "target": b, "rel": rel}})

    for p in top:
        ip, fam, asn, cc = f"ip:{p['ip']}", f"fam:{p['fam']}", f"asn:{p['asn']}", f"cc:{p['cc']}"
        node(ip, p["ip"], "ip", p["score"]); node(fam, p["fam"], "fam"); node(asn, p["asn"], "asn"); node(cc, p["cc"], "cc")
        edge(ip, fam, "serves"); edge(ip, asn, "hosted-in")
        if f"{asn}>{cc}" not in {e["data"]["id"] for e in els}:
            edge(asn, cc, "located-in")
    cc_n, fam_n = {}, {}
    for p in pts:
        cc_n[p["cc"]] = cc_n.get(p["cc"], 0) + 1
        fam_n[p["fam"]] = fam_n.get(p["fam"], 0) + 1
    srt = lambda d: sorted(d.items(), key=lambda kv: -kv[1])[:6]
    return {"status": STATUS, "home": HOME,
            "stats": {"total": len(pts), "online": sum(p["status"] == "online" for p in pts),
                      "high": sum(p["score"] >= 70 for p in pts), "families": len(fam_n), "countries": len(cc_n)},
            "top": pts[:6], "points": pts, "countries": srt(cc_n), "families": srt(fam_n),
            "trend": TREND, "graph": els}


@app.get("/api/v1/stream")
async def stream():
    q: asyncio.Queue = asyncio.Queue(maxsize=200)
    SUBS.add(q)

    async def gen():
        try:
            yield "retry: 3000\n\n"
            while True:
                try:
                    ev = await asyncio.wait_for(q.get(), 15)
                except asyncio.TimeoutError:
                    yield ": ping\n\n"
                    continue
                yield f"data: {json.dumps(ev)}\n\n"
        finally:
            SUBS.discard(q)

    return StreamingResponse(gen(), media_type="text/event-stream", headers={"Cache-Control": "no-cache"})


app.mount("/", StaticFiles(directory=str(Path(__file__).resolve().parent.parent / "frontend"), html=True), name="ui")
