import streamlit as st
import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score
import threat_intel as ti

st.set_page_config(page_title="Sentinel AI", page_icon="🛡️", layout="wide")

st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=Space+Grotesk:wght@500;600;700&display=swap');
:root{--bg:#080d18;--panel:#111a2b;--line:#26344a;--text:#f4f7ff;--muted:#c0cce0;--accent:#a3e635;--blue:#38bdf8}
html,body,[class*="css"]{font-family:'Inter',sans-serif}
/* Color-only accessibility fix: keep widget names readable on the dark background */
[data-testid="stSlider"] label,[data-testid="stToggle"] label,[data-testid="stWidgetLabel"] p,[data-testid="stWidgetLabel"] label{color:#f1f5f9!important}
[data-testid="stSlider"] [data-testid="stMarkdownContainer"] p{color:#f1f5f9!important}
[data-testid="stSlider"] [data-baseweb="slider"] div[role="slider"]{background-color:#a3e635!important;border-color:#a3e635!important}
[data-testid="stSlider"] [data-baseweb="slider"] div[data-testid="stTickBar"]{background-color:#a3e635!important}
[data-testid="stToggle"] [data-baseweb="switch"] div{background-color:#a3e635!important}
.stApp{background:radial-gradient(ellipse at 5% 0%,#173a42 0%,transparent 30%),radial-gradient(ellipse at 100% 0%,#24234c 0%,transparent 30%),var(--bg);color:var(--text)}
[data-testid="stSidebar"]{background:linear-gradient(180deg,#101b2d,#0a1220);border-right:1px solid #2b3b50}
[data-testid="stSidebar"] *{color:#dce8fa}
[data-testid="stSidebar"] [data-testid="stRadio"] label{padding:9px 12px;border-radius:10px;margin:3px 0}
[data-testid="stSidebar"] [data-testid="stRadio"] label:hover{background:#1c2a3f}
h1,h2,h3{font-family:'Space Grotesk',sans-serif!important;color:#f4f8ff!important;letter-spacing:-.4px}
.hero{padding:30px 32px;border-radius:24px;background:linear-gradient(115deg,#172c3d,#1b2544 65%,#2a2143);border:1px solid #43536b;margin:10px 0 28px;box-shadow:0 18px 45px #0003}
.eyebrow{color:var(--accent);letter-spacing:2.2px;font-size:11px;font-weight:800}
.hero-title{font-size:38px;font-weight:800;line-height:1.12;margin:10px 0 12px;color:#fff}
.muted{color:var(--muted);font-size:13px;line-height:1.6}
.panel,.metric{padding:22px;border-radius:18px;background:linear-gradient(145deg,#121e31,#0e1727);border:1px solid #2b3a50;margin-bottom:16px;box-shadow:0 12px 28px #0002}
.metric{min-height:106px;border-top:2px solid #a3e635}
.metric-label{color:#9aabc4;font-size:12px;font-weight:600;text-transform:uppercase;letter-spacing:.7px}
.metric-value{font-size:27px;font-weight:800;color:#f8fbff;margin-top:9px}
.pill{display:inline-block;padding:6px 11px;border-radius:999px;font-size:10px;font-weight:800;letter-spacing:.7px;background:#a3e63518;color:#c4f76a;border:1px solid #a3e65555}
div.stButton>button{width:100%;border:0;border-radius:12px;padding:13px 16px;color:#10170a;font-weight:800;background:linear-gradient(90deg,#c4f76a,#78e4c2);transition:all .2s}
div.stButton>button:hover{background:linear-gradient(90deg,#d7ff8e,#8cf3d4);box-shadow:0 6px 22px #a3e63522;transform:translateY(-1px)}
[data-testid="stMetric"]{background:#121e31;border:1px solid #2b3a50;padding:15px;border-radius:14px}
[data-testid="stProgressBar"]>div>div{background:linear-gradient(90deg,#a3e635,#38bdf8)}
.stAlert{border-radius:13px}
hr{border-color:#2b3a50}
footer{visibility:hidden}
</style>
""", unsafe_allow_html=True)

@st.cache_resource
def train_model():
    rng=np.random.default_rng(42); n=3000
    failed=rng.integers(0,45,n); requests=rng.integers(1,180,n)
    ports=rng.integers(1,35,n); sent=rng.integers(1,9000,n); odd=rng.integers(0,2,n)
    score=(failed>=12)*2+(requests>=75)*2+(ports>=12)*2+(sent>=5000)+odd
    y=(score>=4).astype(int); flip=rng.random(n)<.035; y[flip]=1-y[flip]
    X=pd.DataFrame({"failed_logins":failed,"requests_per_minute":requests,"unique_ports":ports,"bytes_sent_kb":sent,"unusual_hour":odd})
    xtr,xte,ytr,yte=train_test_split(X,y,test_size=.25,random_state=42,stratify=y)
    model=RandomForestClassifier(n_estimators=120,max_depth=8,random_state=42,class_weight="balanced")
    model.fit(xtr,ytr); pred=model.predict(xte)
    scores={"Accuracy":accuracy_score(yte,pred),"Precision":precision_score(yte,pred,zero_division=0),"Recall":recall_score(yte,pred,zero_division=0),"F1-score":f1_score(yte,pred,zero_division=0)}
    return model,scores

model,metrics=train_model()

def agent_decision(v,abuse=None,vt=None):
    row=pd.DataFrame([v]); p=float(model.predict_proba(row)[0][1])
    if p>=.75 or (v["failed_logins"]>=20 and v["requests_per_minute"]>=90):
        level,action,why="HIGH","Simulate temporary IP block + create alert","Several warning signals were found. The agent chooses a high-priority response."
    elif p>=.40 or v["failed_logins"]>=8:
        level,action,why="MEDIUM","Raise warning + keep monitoring","Some warning signals were found. The agent asks for attention."
    else:
        level,action,why="LOW","Log activity + continue monitoring","The input looks closer to normal examples in this demo dataset."
    floor=ti.intel_floor(abuse,vt)
    order={"LOW":0,"MEDIUM":1,"HIGH":2}
    if floor and order[floor]>order[level]:
        level=floor
        action="Simulate temporary IP block + create alert" if floor=="HIGH" else "Raise warning + keep monitoring"
        why="Threat-intelligence feeds (AbuseIPDB / VirusTotal) flagged this source, so the agent raised the risk level."
    elif floor:
        why+=" Threat-intelligence feeds also flagged this source."
    return p,level,action,why

def render_intel(abuse,vt):
    if abuse is not None:
        if abuse.get("ok"):
            st.markdown(f"**AbuseIPDB** — `{abuse['ip']}`")
            c=st.columns(3); c[0].metric("Abuse confidence",f"{abuse['score']}%"); c[1].metric("Reports (90d)",abuse["reports"]); c[2].metric("Country",abuse["country"])
            st.caption(f"ISP: {abuse['isp']} · Usage: {abuse['usage']} · Domain: {abuse['domain']} · Last reported: {abuse['last_reported']}")
        else: st.warning(abuse["error"])
    if vt is not None:
        if vt.get("ok"):
            st.markdown(f"**VirusTotal** — {vt['kind']}: `{vt['indicator']}`")
            c=st.columns(4); c[0].metric("Malicious",vt["malicious"]); c[1].metric("Suspicious",vt["suspicious"]); c[2].metric("Harmless",vt["harmless"]); c[3].metric("Undetected",vt["undetected"])
            st.caption(f"Reputation: {vt['reputation']} · Owner: {vt['owner']} · Country: {vt['country']}")
        else: st.warning(vt["error"])

with st.sidebar:
    st.markdown("## 🛡️ SENTINEL **AI**")
    st.markdown('<span class="pill">AUTONOMOUS SECURITY AGENT</span>',unsafe_allow_html=True)
    st.markdown(" ")
    st.caption("WORKSPACE")
    page=st.radio("Go to",["🧭  Threat Console","🌐  Threat Intelligence","📊  Model Insights","⚙️  Agent Workflow","🎓  Project Details"],label_visibility="collapsed")
    page_map={"🧭  Threat Console":"Live Analysis","🌐  Threat Intelligence":"Threat Intel","📊  Model Insights":"Model Performance","⚙️  Agent Workflow":"How It Works","🎓  Project Details":"About Project"}
    page=page_map[page]
    st.divider()
    st.markdown('<div style="padding:14px;border-radius:14px;background:#a3e63512;border:1px solid #a3e63535"><div style="color:#c4f76a;font-weight:700">● DEMO SYSTEM READY</div><div style="font-size:12px;color:#9aabc4;margin-top:6px">Local simulation · No live traffic</div></div>',unsafe_allow_html=True)
    st.markdown(" ")
    st.caption("Sentinel AI uses synthetic sample data. No real network is monitored or blocked.")
    st.caption("API KEYS")
    for _n,_ok in ti.key_status().items(): st.caption(("🟢 " if _ok else "⚪ ")+_n+(" configured" if _ok else " not set (optional)"))

st.markdown('<div class="hero"><div class="eyebrow">AI-POWERED SECURITY • FINAL YEAR PROJECT</div><div class="hero-title">Cyber Threat Detection<br> & Intelligent Response</div><div class="muted">One intelligent agent uses Machine Learning to estimate risk, select a response, and explain its decision.</div></div>',unsafe_allow_html=True)

if page=="Live Analysis":
    st.subheader("🔎 Threat console")
    st.markdown('<p class="muted">Change the example values and click Analyze. These are not live network readings.</p>',unsafe_allow_html=True)
    a,b=st.columns([1,1],gap="large")
    with a:
        st.markdown('<div class="panel">',unsafe_allow_html=True); st.markdown("### Activity signals")
        failed=st.slider("Failed login attempts",0,50,3)
        req=st.slider("Requests per minute",1,200,20)
        ports=st.slider("Different ports contacted",1,40,2)
        sent=st.slider("Data sent (KB)",1,10000,800,step=100)
        odd=st.toggle("Activity happened at an unusual hour",False)
        src_ip=st.text_input("Source IP (optional, enables AbuseIPDB / VirusTotal check)","",placeholder="e.g. 203.0.113.45")
        run=st.button("✦ ANALYZE ACTIVITY")
        st.markdown('</div>',unsafe_allow_html=True)
    values={"failed_logins":failed,"requests_per_minute":req,"unique_ports":ports,"bytes_sent_kb":sent,"unusual_hour":int(odd)}
    if run or "result" not in st.session_state:
        abuse=vt=None; ip=src_ip.strip()
        if ip:
            if ti.is_valid_ip(ip):
                with st.spinner("Checking threat intelligence..."):
                    abuse=ti.check_abuseipdb(ip); vt=ti.check_virustotal(ip)
            else: abuse={"ok":False,"error":"Source IP is not a valid IPv4/IPv6 address; threat-intel check skipped."}
        st.session_state.result=agent_decision(values,abuse,vt); st.session_state.activity_values=values; st.session_state.intel=(abuse,vt)
    p,risk,action,why=st.session_state.result; vals=st.session_state.activity_values
    with b:
        st.markdown('<div class="panel">',unsafe_allow_html=True); st.markdown("### Agent decision")
        color={"LOW":"#5eead4","MEDIUM":"#fbbf24","HIGH":"#fb7185"}[risk]
        st.markdown(f'<div class="muted">CURRENT RISK LEVEL</div><div style="font-size:38px;font-weight:800;color:{color}">{risk}</div>',unsafe_allow_html=True)
        st.progress(min(max(p,0),1),text=f"ML suspicious score: {p:.0%} (demo estimate)")
        st.markdown(f"**Selected action**\n\n{action}")
        st.markdown(f'<p class="muted">{why}</p>',unsafe_allow_html=True)
        st.info("Blocking is simulated only. No real IP or device is changed.")
        _ab,_vt=st.session_state.get("intel",(None,None))
        if _ab is not None or _vt is not None: render_intel(_ab,_vt)
        st.markdown('</div>',unsafe_allow_html=True)
    st.subheader("📌 Input summary")
    cols=st.columns(4)
    for col,(label,value) in zip(cols,[("Failed logins",vals["failed_logins"]),("Requests / min",vals["requests_per_minute"]),("Unique ports",vals["unique_ports"]),("Data sent",f'{vals["bytes_sent_kb"]:,} KB')]):
        col.markdown(f'<div class="metric"><div class="metric-label">{label}</div><div class="metric-value">{value}</div></div>',unsafe_allow_html=True)

elif page=="Threat Intel":
    st.subheader("🌐 Threat intelligence lookup")
    st.markdown('<p class="muted">Look up real reputation data from AbuseIPDB and VirusTotal. Keys are read from Streamlit Secrets and never shown.</p>',unsafe_allow_html=True)
    ks=ti.key_status()
    if not any(ks.values()):
        st.warning("No API keys configured. Add ABUSEIPDB_API_KEY and VIRUSTOTAL_API_KEY in Streamlit Secrets (App → Settings → Secrets). The rest of the dashboard still works without them.")
    tab1,tab2=st.tabs(["AbuseIPDB · IP check","VirusTotal · IP / domain / URL / hash"])
    with tab1:
        ip=st.text_input("IP address",key="ab_ip",placeholder="e.g. 118.25.6.39")
        if st.button("Check with AbuseIPDB"):
            with st.spinner("Contacting AbuseIPDB..."): render_intel(ti.check_abuseipdb(ip),None)
    with tab2:
        ind=st.text_input("Indicator",key="vt_ind",placeholder="IP, domain, https://url or file hash")
        if st.button("Check with VirusTotal"):
            with st.spinner("Contacting VirusTotal..."): render_intel(None,ti.check_virustotal(ind))
    st.info("Free API tiers have rate limits (VirusTotal ~4 requests/min). Errors are shown here instead of crashing the app.")

elif page=="Model Performance":
    st.subheader("📊 Model insights")
    st.warning("Scores are measured on held-out synthetic demo data; they are not real-world security performance claims.")
    cols=st.columns(4)
    for col,(name,val) in zip(cols,metrics.items()):
        col.markdown(f'<div class="metric"><div class="metric-label">{name}</div><div class="metric-value">{val:.1%}</div></div>',unsafe_allow_html=True)
    st.markdown("**Accuracy:** correct demo predictions overall.  \n**Precision:** how often suspicious predictions were correct.  \n**Recall:** how much suspicious demo activity it found.  \n**F1-score:** combines precision and recall.")

elif page=="How It Works":
    st.subheader("⚙️ Agent workflow")
    for n,title,desc in [("01","Observe","Read example activity values."),("02","Predict","Random Forest estimates whether activity resembles suspicious examples."),("03","Decide","One agent combines the prediction with risk rules."),("04","Act","Selects logging, warning, or simulated blocking."),("05","Verify","A future version can inspect later logs to check whether the response helped.")]:
        st.markdown(f'<div class="panel"><span class="pill">STEP {n}</span><h3>{title}</h3><p class="muted">{desc}</p></div>',unsafe_allow_html=True)
    st.info("This starter version uses manually entered demo signals. Automatic log ingestion and response verification are future improvements.")

else:
    st.subheader("🎓 Project details")
    st.write("**Goal:** Demonstrate one intelligent agent that uses ML predictions to choose a response to potentially suspicious activity.")
    st.write("**Technology:** Python, Streamlit, Pandas, NumPy, Scikit-learn, Requests, AbuseIPDB API, VirusTotal API.")
    st.write("**Model:** Random Forest classifier.")
    st.write("**Agent type:** One model-assisted, rule-guided intelligent agent.")
    st.warning("The model is trained on synthetic data generated in this code. This is an educational prototype, not a production security product.")
    st.markdown("#### Future improvements")
    st.write("1. Train on a public intrusion-detection dataset.\n2. Add CSV upload and data cleaning.\n3. Store decision history.\n4. Compare multiple ML models.\n5. Test responses in an isolated lab.")

st.divider()
# Footer tagline removed as requested.
