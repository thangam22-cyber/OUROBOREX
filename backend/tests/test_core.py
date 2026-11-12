import asyncio, os, sys, time
os.environ["DEMO"] = "1"
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import main


def mk(status="online", age_h=1, fam="Emotet", ip="1.2.3.4", asn="AS1", cc="US"):
    return {"ip": ip, "port": 443, "status": status, "fam": fam, "asn": asn, "asname": "x", "cc": cc,
            "country": "c", "city": "-", "lat": 1.0, "lon": 2.0, "seen_ts": time.time() - age_h * 3600, "src": "feodo"}


def test_fresh_online_outscores_stale_offline():
    assert main.score(mk(), 5)[0] > main.score(mk("offline", 500), 5)[0]


def test_score_bounds_and_parts():
    p, parts = main.score(mk(), 50)
    assert 0 <= p <= 100 and set(parts) == {"R", "F", "I", "C"}


def test_ts_parsing():
    assert main.ts_of({"last_online": "2025-01-02"}) == main.ts_of({"first_seen": "2025-01-02 00:00:00"})


def test_snapshot_graph_is_consistent():
    main.IND.clear()
    for i in range(30):
        main.IND[f"9.9.9.{i}"] = mk(ip=f"9.9.9.{i}", asn=f"AS{i % 3}")
    snap = asyncio.run(main.snapshot())
    ids = [e["data"]["id"] for e in snap["graph"]]
    assert len(ids) == len(set(ids))
    assert snap["stats"]["total"] == 30 and len(snap["top"]) == 6


def test_persistence_roundtrip(tmp_path):
    main.DB = str(tmp_path / "t.db")
    main.IND.clear(); main.TREND.clear()
    main.IND["1.1.1.1"] = mk(ip="1.1.1.1"); main.TREND.append([1, 1])
    asyncio.run(main.persist())
    main.IND.clear(); main.TREND.clear()
    main.load()
    assert "1.1.1.1" in main.IND and main.STATUS["mode"] == "cached"
