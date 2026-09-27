#!/usr/bin/env python3
from __future__ import annotations
import html, json, sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
import streamlit as st

ROOT = Path(__file__).resolve().parents[1]
DB = ROOT / "outputs" / "telemetry.db"
ANALYSIS = ROOT / "outputs" / "analysis-status.json"
TELEMETRY = ROOT / "outputs" / "telemetry-status.json"
MODEL = "ntro-clean-traffic-v1"
FRESH = 30
DISPLAY = {
    "BENIGN":"BENIGN","RECONNAISSANCE":"RECONNAISSANCE",
    "INITIAL_ACCESS_PATTERN":"INITIAL_ACCESS","LATERAL_MOVEMENT":"LATERAL_MOVEMENT",
    "C2_BEACON_PATTERN":"C2_BEACON","EXFILTRATION_LIKE":"EXFILTRATION_LIKE",
    "DDOS_LOW":"DDOS_LOW","DDOS_MEDIUM":"DDOS_MEDIUM","DDOS_HIGH":"DDOS_HIGH",
    "UNKNOWN":"UNKNOWN / ABSTAIN",
}

st.set_page_config(page_title="AegisNet-WM Live Inference", page_icon="⌁", layout="wide", initial_sidebar_state="collapsed")
st.markdown("""
<style>
html,body,[data-testid="stAppViewContainer"],[data-testid="stMain"]{background:#040705!important}
[data-testid="stHeader"],[data-testid="stToolbar"],[data-testid="stSidebar"]{display:none!important}
.block-container{max-width:1500px;padding:1.2rem 1.6rem 2rem}
.term{border:1px solid #17391f;border-radius:12px;overflow:hidden;background:#050806;box-shadow:0 0 42px rgba(0,255,96,.055)}
.bar{display:flex;justify-content:space-between;padding:12px 16px;background:#0a100c;border-bottom:1px solid #17391f;color:#9fffae;font:700 14px ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;letter-spacing:.08em}
.body{min-height:650px;padding:18px 20px 24px;color:#9fffae;font:15px/1.58 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;white-space:pre-wrap}
.dim{color:#587a61}.ok{color:#61ff82}.warn{color:#ffd166}.bad{color:#ff5c72;font-weight:700}.cyan{color:#5ce1e6}.prompt{color:#61ff82;font-weight:700}
.dot{width:9px;height:9px;border-radius:50%;display:inline-block;margin-right:8px;background:#61ff82;box-shadow:0 0 10px #61ff82}.dotbad{background:#ff5c72;box-shadow:none}
.cursor{display:inline-block;width:9px;height:16px;background:#61ff82;margin-left:4px;vertical-align:-2px;animation:blink 1s steps(2,start) infinite}@keyframes blink{50%{opacity:0}}
.help{margin-top:15px;border:1px solid #17391f;border-radius:10px;padding:14px 16px;background:#071009;color:#8bbf94;font:13px/1.6 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}.help b{color:#c9ffd1}.help code{color:#e6ffe9;background:#0b150d;padding:2px 5px;border-radius:4px}
</style>""", unsafe_allow_html=True)

def jload(path: Path)->dict[str,Any]:
    try:
        x=json.loads(path.read_text(encoding="utf-8"))
        return x if isinstance(x,dict) else {}
    except Exception:
        return {}

def dt(v: Any):
    if not v:return None
    try:
        x=datetime.fromisoformat(str(v))
        return x if x.tzinfo else x.replace(tzinfo=timezone.utc)
    except Exception:return None

def clock(v: Any)->str:
    x=dt(v)
    return x.astimezone().strftime("%H:%M:%S") if x else "--:--:--"

def hbytes(v: float)->str:
    n=float(v or 0)
    for s in ("B","KB","MB","GB"):
        if abs(n)<1024 or s=="GB": return f"{n:.1f}{s}"
        n/=1024
    return f"{n:.1f}GB"

def live_rows(limit=16):
    if not DB.exists(): return []
    c=sqlite3.connect(f"file:{DB.as_posix()}?mode=ro",uri=True); c.row_factory=sqlite3.Row
    try:
        if not c.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='analysis_predictions'").fetchone(): return []
        q=c.execute("""SELECT id,created_at,event_time,predicted_label,confidence,cyber_risk,risk_band,probabilities_json,state_json,
                              operator_state,operator_reason
                       FROM analysis_predictions WHERE source='LIVE' ORDER BY id DESC LIMIT ?""",(limit,)).fetchall()
        return [dict(r) for r in reversed(q)]
    finally:c.close()

def latest_forecast():
    if not DB.exists(): return None
    c=sqlite3.connect(f"file:{DB.as_posix()}?mode=ro",uri=True); c.row_factory=sqlite3.Row
    try:
        if not c.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='forecast_predictions'").fetchone(): return None
        row=c.execute("SELECT * FROM forecast_predictions ORDER BY id DESC LIMIT 1").fetchone()
        return dict(row) if row else None
    finally:c.close()

def js(v: Any):
    try:
        x=json.loads(str(v or "{}")); return x if isinstance(x,dict) else {}
    except Exception:return {}

def esc(s: Any)->str:return html.escape(str(s))
def line(ts,level,text,css=""):
    return f'<span class="dim">[{esc(ts)}]</span> <span class="{css}">{esc(level):<8}</span> {esc(text)}'

@st.fragment(run_every=1.0)
def terminal():
    a=jload(ANALYSIS); t=jload(TELEMETRY); rows=live_rows(); forecast_row=latest_forecast()
    now=datetime.now().astimezone().strftime("%H:%M:%S")
    online=a.get("state") in {"RUNNING","RUNNING_WITH_ERROR"}
    latest=rows[-1] if rows else None
    event=dt(latest.get("event_time")) if latest else None
    age=max(0.0,(datetime.now(timezone.utc)-event).total_seconds()) if event else None
    fresh=latest is not None and age is not None and age<=FRESH
    if fresh:
        label=str(latest.get("predicted_label") or "UNKNOWN"); conf=float(latest.get("confidence") or 0); risk=float(latest.get("cyber_risk") or 0)
        band=str(latest.get("risk_band") or "UNKNOWN"); state=js(latest.get("state_json"))
    else:
        label=str(a.get("predicted_label") or "UNKNOWN"); conf=float(a.get("confidence") or 0); risk=float(a.get("cyber_risk") or 0)
        band=str(a.get("risk_band") or "NO_DATA"); state={}
    uncertain=label=="UNKNOWN"
    attack=label not in {"BENIGN","UNKNOWN"}
    operator_state=str(a.get("operator_state") or (latest.get("operator_state") if latest else "UNKNOWN") or "UNKNOWN")
    css="bad" if operator_state=="ALERT" else ("warn" if operator_state in {"WATCH","UNVERIFIED","RECOVERING","DEGRADED"} else "ok")
    out=[]
    out.append('<span class="cyan">AEGISNET-WM // AIR-GAPPED LIVE INFERENCE CONSOLE</span>')
    out.append('<span class="dim">'+"─"*94+'</span>')
    out.append(f'<span class="dim">engine</span>  <span class="{"ok" if online else "bad"}>{"ONLINE" if online else "OFFLINE"}</span>    <span class="dim">pid</span> {esc(a.get("pid","---"))}    <span class="dim">mode</span> {esc(a.get("mode","UNKNOWN"))}    <span class="dim">model</span> {MODEL}')
    collector_health=str(t.get("health") or ("UNKNOWN" if not t else "LEGACY"))
    collector_css="ok" if collector_health=="HEALTHY" else "warn"
    out.append(f'<span class="dim">collector</span> <span class="{collector_css}">{esc(collector_health)}</span>    <span class="dim">window</span> 10s    <span class="dim">refresh</span> 1s    <span class="dim">freshness</span> {FRESH}s')
    out.append("")
    health={
        "ALERT":"ATTACK CONFIRMED — LOCAL DETECTOR AUTHORITY",
        "WATCH":"ATTACK EVIDENCE — CONFIRMING ACROSS WINDOWS",
        "RECOVERING":"RECOVERY — WAITING FOR BENIGN CONFIRMATION",
        "UNVERIFIED":"MODEL UNCERTAIN — DECISION WITHHELD",
        "DEGRADED":"VISIBILITY DEGRADED — DO NOT ASSUME BENIGN",
        "NORMAL":"NETWORK STABLE",
    }.get(operator_state,"MODEL STATE UNKNOWN")
    out.append(line(now,"HEALTH",health,css))
    out.append(line(now,"OP-STATE",operator_state,css))
    if a.get("operator_reason"):
        out.append(line(now,"OP-REASON",str(a.get("operator_reason")),"dim"))
    out.append(line(now,"STATE",DISPLAY.get(label,label),css))
    out.append(line(now,"CONF",f"{conf:.1%}" if fresh else "no fresh inference","cyan"))
    risk_prefix="raw-model " if uncertain else ""
    out.append(line(now,"RISK",f"{risk_prefix}{risk:.1%} / {band}",css))
    if fresh:
        out.append(line(now,"SIGNAL",f'src={int(float(state.get("unique_src_ips",0) or 0))} dst={int(float(state.get("unique_dst_ips",0) or 0))} flows={int(float(state.get("flow_count",0) or 0))} pkts={int(float(state.get("packet_count",0) or 0))} bytes={hbytes(state.get("byte_count",0))} ports={int(float(state.get("unique_dst_ports",0) or 0))} iat={float(state.get("iat_mean_ms",0) or 0):.1f}ms',"warn" if attack else "ok"))
        probs=js(latest.get("probabilities_json")); top=sorted(probs.items(),key=lambda x:float(x[1]),reverse=True)[:3]
        out.append(line(now,"TOP-3"," | ".join(f"{DISPLAY.get(k,k)}={float(v):.1%}" for k,v in top),"cyan"))
    else:
        msg="no live prediction yet" if age is None else f"last controlled traffic is stale ({age:.0f}s old)"
        out.append(line(now,"INFO",msg+"; waiting for fresh NetFlow","dim"))

    out += ["", '<span class="dim">PROTOTYPE STAGE FORECAST</span>', '<span class="dim">'+"─"*94+'</span>']
    forecast_fresh=False
    forecast={}
    if forecast_row:
        ftime=dt(forecast_row.get("event_time"))
        fage=max(0.0,(datetime.now(timezone.utc)-ftime).total_seconds()) if ftime else None
        forecast_fresh=fage is not None and fage<=FRESH
        forecast=js(forecast_row.get("forecast_json")) if forecast_fresh else {}
    if forecast:
        fill=float(forecast.get("history_fill_ratio") or 0)
        out.append(line(now,"HISTORY",f"temporal context {fill:.0%} full · evidence={forecast.get('evidence_status','unknown')}","cyan"))
        prod=forecast.get("production_guard") or {}
        if prod:
            ood=prod.get("ood") or {}
            tele=prod.get("telemetry") or {}
            out.append(line(
                now,"PROD-GATE",
                f"{prod.get('status','UNKNOWN')} · advisory={bool(prod.get('advisory_eligible'))} · telemetry={tele.get('status','UNKNOWN')} · OOD={ood.get('status','UNKNOWN')}",
                "ok" if prod.get("advisory_eligible") else "warn",
            ))
            if prod.get("reasons"):
                out.append(line(now,"WITHHOLD","; ".join(str(x) for x in prod.get("reasons") or []),"warn"))
        for key,item in sorted((forecast.get("horizons") or {}).items(),key=lambda kv:int(kv[0])):
            seconds=int(item.get("seconds") or int(key)*10)
            pred=str(item.get("predicted_class") or "UNKNOWN")
            conf=float(item.get("confidence") or 0)
            future_attack=float(item.get("future_attack_probability") or 0)
            change=float(item.get("state_change_probability") or 0)
            onset=float(item.get("attack_onset_probability") or 0)
            infil=float(item.get("infiltration_probability") or 0)
            victim=str(item.get("predicted_victim") or "NONE")
            path=" -> ".join(item.get("topology_path") or []) or "n/a"
            mitre=item.get("mitre") or {}
            label="ABSTAIN" if item.get("abstain") else DISPLAY.get(pred,pred)
            cssh="warn" if item.get("abstain") else ("ok" if pred=="BENIGN" else "bad")
            out.append(line(now,f"+{seconds}s",f"{label:<22} conf={conf:>6.1%} attack={future_attack:>6.1%} change={change:>6.1%} onset={onset:>6.1%} infil={infil:>6.1%}",cssh))
            out.append(line(now,"TARGET",f"victim={victim:<5} path={path}","dim"))
            technique=mitre.get("technique_id") or "n/a"
            tactic=mitre.get("tactic_id") or "n/a"
            top=(item.get("top_features") or [{}])[0]
            if top:
                out.append(line(now,"EVIDENCE",f"MITRE {tactic}/{technique} · top_driver={top.get('feature','n/a')} attr={float(top.get('attribution') or 0):.4f}","dim"))
            recommendations=item.get("operator_recommendations") or []
            if recommendations:
                out.append(line(now,"ACTION",str(recommendations[0]),"dim"))
        if forecast.get("audit_hash"):
            out.append(line(now,"AUDIT",f"hash={str(forecast.get('audit_hash'))[:16]}… report={forecast.get('report_path','n/a')}","dim"))

        next_stage=forecast.get("next_stage_forecast") or {}
        if next_stage and not next_stage.get("error"):
            predicted=str(next_stage.get("predicted_next_stage") or "UNKNOWN")
            stage_conf=float(next_stage.get("confidence") or 0)
            changed=bool(next_stage.get("stage_change_predicted"))
            out.append(line(
                now,
                "NEXT-STG",
                f"{DISPLAY.get(predicted,predicted)} conf={stage_conf:.1%} change={'yes' if changed else 'no'} · shadow evidence",
                "warn" if changed else "cyan",
            ))

        shadow=forecast.get("shadow_real_models") or {}
        if shadow:
            out += ["", '<span class="dim">REAL-DATA SHADOW FORECAST · NO ALERT AUTHORITY</span>', '<span class="dim">'+"─"*94+'</span>']
            models=shadow.get("models") or {}
            for model_name in ("GENIS","CTU13","CICIDS2017"):
                model=models.get(model_name)
                if not model or model.get("error"):
                    continue
                pieces=[]
                for seconds,item in sorted((model.get("horizons") or {}).items(),key=lambda kv:int(kv[0])):
                    probability=float(item.get("future_attack_probability") or 0)
                    threshold=float(item.get("native_threshold") or 0)
                    native="native-alert" if item.get("native_alert") else "native-ok"
                    pieces.append(f"+{int(seconds)}s {probability:.1%} (thr {threshold:.1%}, {native})")
                out.append(line(now,model_name," | ".join(pieces),"cyan"))
            consensus=shadow.get("consensus") or {}
            for seconds,item in sorted(consensus.items(),key=lambda kv:int(kv[0])):
                out.append(line(now,"CONSENSUS",f"+{int(seconds)}s mean={float(item.get('mean_probability') or 0):.1%} max={float(item.get('max_probability') or 0):.1%} native-votes={int(item.get('native_alert_votes') or 0)}/{int(item.get('model_count') or 0)} · SHADOW ONLY","warn"))
            eve_cal=shadow.get("eve_calibration") or {}
            if eve_cal and not eve_cal.get("error"):
                for seconds,item in sorted((eve_cal.get("horizons") or {}).items(),key=lambda kv:int(kv[0])):
                    probability=float(item.get("calibrated_attack_probability") or 0)
                    threshold=float(item.get("threshold") or 0)
                    watch_threshold=float(item.get("watch_threshold") or threshold)
                    if item.get("operator_advisory"):
                        status="ADVISORY"
                    elif item.get("shadow_alert"):
                        status="SHADOW-HIT"
                    elif item.get("shadow_watch"):
                        status="WATCH"
                    else:
                        status="quiet"
                    out.append(line(now,"EVE-CAL",f"+{int(seconds)}s {probability:.1%} · watch {watch_threshold:.1%} · alert {threshold:.1%} · {status}","warn" if status in {"WATCH","SHADOW-HIT"} else ("bad" if status=="ADVISORY" else "cyan")))
                out.append(line(now,"PROMOTE",f"eligible={bool(eve_cal.get('promotion_eligible'))} · manual review required · alert authority=false","dim"))
            out.append(line(now,"GUARD","cross-domain public-model thresholds cannot change NETWORK STABLE/ATTACK state","dim"))
    else:
        out.append(line(now,"FORECAST","waiting for fresh temporal history","dim"))
    out+=["",'<span class="dim">LIVE PREDICTION STREAM</span>','<span class="dim">'+"─"*94+'</span>']
    cutoff=datetime.now(timezone.utc).timestamp()-180
    recent=[r for r in rows if dt(r.get("event_time")) and dt(r.get("event_time")).timestamp()>=cutoff]
    if recent:
        for r in recent[-9:]:
            lab=str(r.get("predicted_label") or "UNKNOWN"); c=float(r.get("confidence") or 0); rr=float(r.get("cyber_risk") or 0)
            stream_css="warn" if lab=="UNKNOWN" else ("ok" if lab=="BENIGN" else "bad")
            out.append(line(clock(r.get("event_time")),"PREDICT",f"{DISPLAY.get(lab,lab):<22} conf={c:>6.1%} risk={rr:>6.1%}",stream_css))
    else:
        out.append(line(now,"PREDICT","NO FRESH CONTROLLED TRAFFIC — decision withheld","warn"))
    out+=["",'<span class="prompt">aegis@analysis:~$</span> monitoring<span class="cursor"></span>']
    dot="dot" if online else "dot dotbad"
    st.markdown(f'<div class="term"><div class="bar"><span><span class="{dot}"></span>LIVE ANALYSIS</span><span>{now}</span></div><div class="body">'+"<br>".join(out)+'</div></div>',unsafe_allow_html=True)

terminal()
st.markdown("""<div class="help"><b>BOUNDED DDoS LAB</b><br>
APP-DC victim: <code>/home/gns3/ddos-victim.sh</code><br>
LOW: CLIENT-BR1 → <code>/home/gns3/ddos-low.sh</code><br>
MEDIUM: CLIENT-BR1 + CLIENT-BR2 → <code>/home/gns3/ddos-medium.sh</code> at the same time<br>
HIGH: CLIENT-BR1 + CLIENT-BR2 + SERVICE-HUB → <code>/home/gns3/ddos-high.sh</code> at the same time<br>
Stop victim: <code>kill $(cat /tmp/aegis-ddos-victim.pid)</code><br>
Fixed target: APP-DC 10.20.10.10 UDP/9993. Source scripts are bounded and terminate automatically.</div>""",unsafe_allow_html=True)
