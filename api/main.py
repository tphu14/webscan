"""
api/main.py - FastAPI backend v2 (WebSocket fix)

Thay đổi so với v1:
- Bỏ monkey-patch console.print (gây race condition + WebSocket disconnect)
- Dùng asyncio.Queue + periodic ping để giữ WebSocket alive
- Scanner chạy trong thread riêng (run_in_executor) để không block event loop
- Progress được emit qua queue từ thread an toàn
"""
import asyncio, json, sys, os, threading
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Depends, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session
from pydantic import BaseModel

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from api.database import init_db, get_db, ScanJob, Vulnerability, SessionLocal

app = FastAPI(title="WebVulnScanner API", version="3.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], allow_methods=["*"],
    allow_headers=["*"], allow_credentials=True,
)

# Global thread pool cho scanner (max 3 concurrent scans)
_executor = ThreadPoolExecutor(max_workers=3)

# scan_id → asyncio.Queue  (bridge từ scanner thread → WebSocket)
_queues: dict[int, asyncio.Queue] = {}
_active: set[int] = set()


@app.on_event("startup")
def startup():
    init_db()


# ── Pydantic model ────────────────────────────────────────────────────────────
class ScanRequest(BaseModel):
    target:         str
    depth:          int  = 3
    pages:          int  = 50
    timeout:        int  = 10
    scan_sqli:      bool = True
    scan_xss:       bool = True
    scan_files:     bool = True
    scan_redirect:  bool = True
    scan_headers:   bool = True
    scan_time_sqli: bool = True
    scan_ssrf:      bool = True
    scan_csrf:      bool = True
    scan_idor:      bool = True
    scan_jwt:       bool = True
    scan_cors:      bool = True
    scan_graphql:   bool = True
    scan_api:       bool = True
    scan_ssti:      bool = True
    scan_lfi:       bool = True
    scan_xxe:       bool = True
    scan_subdomain: bool = True


# ── Scanner thread (blocking) ─────────────────────────────────────────────────
def _scanner_thread(scan_id: int, req: ScanRequest, loop: asyncio.AbstractEventLoop):
    """
    Chạy scanner trong thread riêng.
    Dùng loop.call_soon_threadsafe để đưa messages vào queue một cách an toàn.
    """
    db = SessionLocal()

    def emit(msg_type: str, data: dict):
        """Thread-safe emit vào asyncio queue."""
        msg = json.dumps({"type": msg_type, "data": data})
        loop.call_soon_threadsafe(_queues[scan_id].put_nowait, msg)

    try:
        job = db.query(ScanJob).filter(ScanJob.id == scan_id).first()
        job.status = "running"
        db.commit()
        _active.add(scan_id)

        emit("status", {"message": f"Scan #{scan_id} started — target: {req.target}"})
        emit("log",    {"message": f"Modules: {sum(1 for k,v in req.model_dump().items() if k.startswith('scan_') and v)}/17 active"})

        # ── Capture scanner output via custom console ─────────────────────────
        import io
        from rich.console import Console as RichConsole

        # StringIO buffer để capture rich output
        buf = io.StringIO()
        scan_console = RichConsole(file=buf, highlight=False, markup=False, width=120)

        # Patch console trong tất cả modules để dùng scan_console
        import importlib
        import modules.sqli, modules.xss, modules.ssrf, modules.csrf
        import modules.idor, modules.cors, modules.graphql, modules.jwt_analyzer
        import modules.api_fuzzer, modules.ssti, modules.lfi, modules.xxe
        import modules.subdomain_takeover, modules.sqli_blind_time
        import modules.sensitive_files, modules.headers, modules.open_redirect

        _mods = [
            modules.sqli, modules.xss, modules.ssrf, modules.csrf,
            modules.idor, modules.cors, modules.graphql, modules.jwt_analyzer,
            modules.api_fuzzer, modules.ssti, modules.lfi, modules.xxe,
            modules.subdomain_takeover, modules.sqli_blind_time,
            modules.sensitive_files, modules.headers, modules.open_redirect,
        ]
        # Save original consoles
        _originals = {}
        for mod in _mods:
            if hasattr(mod, 'console'):
                _originals[mod] = mod.console
                mod.console = scan_console

        # Also patch scanner_v2's console
        try:
            import scanner_v2 as sv2
            _originals['sv2'] = sv2.console
            sv2.console = scan_console
        except Exception:
            pass

        # Flush buffer periodically in a side thread
        flush_stop = threading.Event()

        def flush_loop():
            while not flush_stop.is_set():
                flush_stop.wait(0.5)  # flush every 500ms
                _flush_buf(buf, emit)

        flush_thread = threading.Thread(target=flush_loop, daemon=True)
        flush_thread.start()

        # ── Run scanner ───────────────────────────────────────────────────────
        try:
            from scanner_v2 import Scanner
        except ImportError:
            from scanner import Scanner

        start = datetime.utcnow()

        # Scanner uses asyncio internally — run its own event loop in this thread
        sub_loop = asyncio.new_event_loop()
        asyncio.set_event_loop(sub_loop)

        scanner = Scanner(
            target=req.target,
            max_depth=req.depth, max_pages=req.pages, timeout=req.timeout,
            scan_sqli=req.scan_sqli, scan_xss=req.scan_xss,
            scan_files=req.scan_files, scan_redirect=req.scan_redirect,
            scan_headers=req.scan_headers, scan_time_sqli=req.scan_time_sqli,
            scan_ssrf=req.scan_ssrf, scan_csrf=req.scan_csrf,
            scan_idor=req.scan_idor, scan_jwt=req.scan_jwt,
            scan_cors=req.scan_cors, scan_graphql=req.scan_graphql,
            scan_api=req.scan_api, scan_ssti=req.scan_ssti,
            scan_lfi=req.scan_lfi, scan_xxe=req.scan_xxe,
            scan_subdomain=req.scan_subdomain,
        )

        results = sub_loop.run_until_complete(scanner.run())
        sub_loop.close()

        duration = (datetime.utcnow() - start).total_seconds()

        # Stop flush loop and do final flush
        flush_stop.set()
        flush_thread.join(timeout=2)
        _flush_buf(buf, emit)

        # Restore original consoles
        for mod, orig in _originals.items():
            if mod == 'sv2':
                try:
                    import scanner_v2 as sv2
                    sv2.console = orig
                except Exception:
                    pass
            else:
                mod.console = orig

        # ── Save results ──────────────────────────────────────────────────────
        vulns = results["vulnerabilities"]
        sev = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for v in vulns:
            sev[v.get("severity", "LOW")] = sev.get(v.get("severity", "LOW"), 0) + 1

        risk_score = sev["CRITICAL"]*10 + sev["HIGH"]*7 + sev["MEDIUM"]*4 + sev["LOW"]

        for v in vulns:
            db.add(Vulnerability(
                scan_id=scan_id, type=v.get("type",""),
                severity=v.get("severity","LOW"), url=v.get("url",""),
                parameter=v.get("parameter"), payload=v.get("payload"),
                evidence=v.get("evidence"), confidence=v.get("confidence", 0.75),
                cvss_score=v.get("cvss_score"), cvss_vector=v.get("cvss_vector"),
                cwe=v.get("cwe"),
            ))

        job.status      = "done"
        job.finished_at = datetime.utcnow()
        job.duration    = duration
        job.total_vulns = len(vulns)
        job.critical    = sev["CRITICAL"]
        job.high        = sev["HIGH"]
        job.medium      = sev["MEDIUM"]
        job.low         = sev["LOW"]
        job.risk_score  = risk_score
        job.raw_count   = results.get("raw_count", len(vulns))
        db.commit()

        emit("done", {
            "scan_id": scan_id, "total": len(vulns),
            "critical": sev["CRITICAL"], "high": sev["HIGH"],
            "medium": sev["MEDIUM"], "low": sev["LOW"],
            "risk_score": risk_score, "duration": round(duration),
        })

    except Exception as e:
        import traceback
        err = f"{e}\n{traceback.format_exc()[-500:]}"
        try:
            job = db.query(ScanJob).filter(ScanJob.id == scan_id).first()
            if job:
                job.status    = "failed"
                job.error_msg = str(e)
                db.commit()
        except Exception:
            pass
        emit("error", {"message": str(e)})
    finally:
        _active.discard(scan_id)
        db.close()
        # Signal WebSocket to close
        loop.call_soon_threadsafe(_queues[scan_id].put_nowait, None)


def _flush_buf(buf, emit):
    """Flush StringIO buffer → emit log lines."""
    import re
    content = buf.getvalue()
    if not content:
        return
    buf.truncate(0)
    buf.seek(0)
    for line in content.splitlines():
        # Strip ANSI escape codes
        clean = re.sub(r'\x1b\[[0-9;]*m', '', line).strip()
        # Strip rich markup like [bold red]
        clean = re.sub(r'\[/?[a-z _]+\]', '', clean).strip()
        if clean:
            emit("log", {"message": clean})


# ── REST API ──────────────────────────────────────────────────────────────────
@app.post("/api/scans", status_code=201)
async def create_scan(req: ScanRequest, bg: BackgroundTasks, db: Session = Depends(get_db)):
    if not req.target.startswith(("http://", "https://")):
        raise HTTPException(400, "Target must start with http:// or https://")

    job = ScanJob(target=req.target, options=req.model_dump_json())
    db.add(job); db.commit(); db.refresh(job)

    loop = asyncio.get_event_loop()
    _queues[job.id] = asyncio.Queue()

    # Run scanner in thread pool (non-blocking)
    loop.run_in_executor(_executor, _scanner_thread, job.id, req, loop)

    return {"scan_id": job.id, "status": "pending"}


@app.get("/api/scans")
def list_scans(db: Session = Depends(get_db)):
    jobs = db.query(ScanJob).order_by(ScanJob.started_at.desc()).all()
    return [_job_dict(j) for j in jobs]


@app.get("/api/scans/{scan_id}")
def get_scan(scan_id: int, db: Session = Depends(get_db)):
    job = db.query(ScanJob).filter(ScanJob.id == scan_id).first()
    if not job: raise HTTPException(404, "Scan not found")
    vulns = db.query(Vulnerability).filter(Vulnerability.scan_id == scan_id).all()
    r = _job_dict(job)
    r["vulnerabilities"] = [_vuln_dict(v) for v in vulns]
    return r


@app.delete("/api/scans/{scan_id}")
def delete_scan(scan_id: int, db: Session = Depends(get_db)):
    if scan_id in _active:
        raise HTTPException(409, "Cannot delete a running scan")
    db.query(Vulnerability).filter(Vulnerability.scan_id == scan_id).delete()
    db.query(ScanJob).filter(ScanJob.id == scan_id).delete()
    db.commit()
    return {"deleted": scan_id}


@app.get("/api/scans/compare/{id1}/{id2}")
def compare_scans(id1: int, id2: int, db: Session = Depends(get_db)):
    j1 = db.query(ScanJob).filter(ScanJob.id == id1).first()
    j2 = db.query(ScanJob).filter(ScanJob.id == id2).first()
    if not j1 or not j2: raise HTTPException(404, "Scan not found")
    v1 = {f"{v.type}|{v.url}|{v.parameter}" for v in db.query(Vulnerability).filter(Vulnerability.scan_id==id1).all()}
    v2 = {f"{v.type}|{v.url}|{v.parameter}" for v in db.query(Vulnerability).filter(Vulnerability.scan_id==id2).all()}
    return {
        "scan1": _job_dict(j1), "scan2": _job_dict(j2),
        "new_in_scan2":   list(v2 - v1),
        "fixed_in_scan2": list(v1 - v2),
        "persisting":     list(v1 & v2),
        "improvement":    len(v1 - v2) - len(v2 - v1),
    }


@app.get("/api/stats")
def stats(db: Session = Depends(get_db)):
    jobs  = db.query(ScanJob).filter(ScanJob.status == "done").all()
    vulns = db.query(Vulnerability).all()
    counts: dict = {}
    for v in vulns: counts[v.type] = counts.get(v.type, 0) + 1
    top = sorted(counts.items(), key=lambda x: -x[1])[:5]
    return {
        "total_scans": len(jobs), "total_vulns": len(vulns),
        "critical": sum(j.critical for j in jobs),
        "high":     sum(j.high for j in jobs),
        "medium":   sum(j.medium for j in jobs),
        "low":      sum(j.low for j in jobs),
        "avg_risk": round(sum(j.risk_score for j in jobs) / max(len(jobs), 1), 1),
        "top_vuln_types": top,
    }


# ── WebSocket ─────────────────────────────────────────────────────────────────
@app.websocket("/ws/scan/{scan_id}")
async def ws_progress(ws: WebSocket, scan_id: int):
    await ws.accept()

    # Wait up to 5s for queue to be created (race condition on fast connections)
    for _ in range(10):
        if scan_id in _queues:
            break
        await asyncio.sleep(0.5)

    q = _queues.get(scan_id)
    if not q:
        await ws.send_text(json.dumps({"type":"error","data":{"message":"Scan queue not found"}}))
        await ws.close(); return

    try:
        while True:
            try:
                # 30s timeout per message — send ping to keep WS alive
                msg = await asyncio.wait_for(q.get(), timeout=30)
            except asyncio.TimeoutError:
                # Send ping to keep connection alive
                try:
                    await ws.send_text(json.dumps({"type":"ping","data":{}}))
                except Exception:
                    break
                continue

            if msg is None:  # Sentinel: scan finished
                break
            try:
                await ws.send_text(msg)
            except Exception:
                break
    except WebSocketDisconnect:
        pass
    finally:
        try:
            await ws.close()
        except Exception:
            pass


# ── Static UI ─────────────────────────────────────────────────────────────────
UI_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "ui")
if os.path.exists(UI_DIR):
    app.mount("/assets", StaticFiles(directory=os.path.join(UI_DIR, "assets")), name="assets")

    @app.get("/")
    def root():    return FileResponse(os.path.join(UI_DIR, "index.html"))
    @app.get("/scan")
    def scan_pg(): return FileResponse(os.path.join(UI_DIR, "scan.html"))
    @app.get("/history")
    def hist_pg(): return FileResponse(os.path.join(UI_DIR, "history.html"))


# ── Helpers ───────────────────────────────────────────────────────────────────
def _job_dict(j):
    return {
        "id": j.id, "target": j.target, "status": j.status,
        "started_at":  j.started_at.isoformat()  if j.started_at  else None,
        "finished_at": j.finished_at.isoformat() if j.finished_at else None,
        "duration": j.duration, "total_vulns": j.total_vulns,
        "critical": j.critical, "high": j.high,
        "medium": j.medium, "low": j.low,
        "risk_score": j.risk_score, "raw_count": j.raw_count,
        "error_msg": j.error_msg,
    }

def _vuln_dict(v):
    return {
        "id": v.id, "scan_id": v.scan_id, "type": v.type,
        "severity": v.severity, "url": v.url, "parameter": v.parameter,
        "payload": v.payload, "evidence": v.evidence,
        "confidence": v.confidence, "cvss_score": v.cvss_score,
        "cvss_vector": v.cvss_vector, "cwe": v.cwe,
    }