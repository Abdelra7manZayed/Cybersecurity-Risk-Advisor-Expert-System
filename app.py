import streamlit as st
import plotly.graph_objects as go
import plotly.express as px

# ─── Page Config ────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="Cybersecurity Risk Advisor",
    page_icon="🛡️",
    layout="wide",
)

# ─── Custom CSS ─────────────────────────────────────────────────────────────
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;600&family=IBM+Plex+Sans:wght@300;400;600;700&display=swap');

html, body, [class*="css"] {
    font-family: 'IBM Plex Sans', sans-serif;
}

.main { background-color: #0d1117; }

.risk-header {
    background: linear-gradient(135deg, #0d1117 0%, #161b22 100%);
    border: 1px solid #30363d;
    border-radius: 12px;
    padding: 28px 32px;
    margin-bottom: 24px;
}

.risk-header h1 {
    font-family: 'IBM Plex Mono', monospace;
    font-size: 26px;
    color: #e6edf3;
    margin: 0 0 6px 0;
    letter-spacing: -0.5px;
}

.risk-header p {
    color: #8b949e;
    font-size: 14px;
    margin: 0;
}

.metric-card {
    background: #161b22;
    border: 1px solid #30363d;
    border-radius: 10px;
    padding: 18px 20px;
    text-align: center;
}

.metric-label {
    font-size: 12px;
    color: #8b949e;
    text-transform: uppercase;
    letter-spacing: 1px;
    margin-bottom: 8px;
}

.metric-value {
    font-family: 'IBM Plex Mono', monospace;
    font-size: 32px;
    font-weight: 600;
    line-height: 1;
}

.risk-card {
    background: #161b22;
    border: 1px solid #30363d;
    border-left-width: 4px;
    border-radius: 10px;
    padding: 18px 20px;
    margin-bottom: 14px;
}

.risk-card h4 {
    font-family: 'IBM Plex Mono', monospace;
    font-size: 15px;
    color: #e6edf3;
    margin: 0 0 10px 0;
}

.risk-card p { color: #8b949e; font-size: 13px; margin: 4px 0; }
.risk-card .advice { color: #58a6ff; font-size: 13px; margin-top: 10px; }

.badge {
    display: inline-block;
    padding: 2px 10px;
    border-radius: 20px;
    font-size: 11px;
    font-weight: 600;
    font-family: 'IBM Plex Mono', monospace;
}

.trace-box {
    background: #0d1117;
    border: 1px solid #30363d;
    border-radius: 8px;
    padding: 16px;
    font-family: 'IBM Plex Mono', monospace;
    font-size: 12px;
    color: #8b949e;
}

.trace-line { margin: 4px 0; color: #58a6ff; }
.trace-arrow { color: #3fb950; }

div[data-testid="stSidebar"] {
    background-color: #0d1117;
    border-right: 1px solid #30363d;
}

div[data-testid="stSidebar"] .stCheckbox label { color: #c9d1d9; font-size: 13px; }
div[data-testid="stSidebar"] .stSlider label { color: #8b949e; font-size: 12px; }
</style>
""", unsafe_allow_html=True)

# ─── Knowledge Base ──────────────────────────────────────────────────────────
SEVERITY_WEIGHTS = {"Low": 25, "Medium": 50, "High": 75, "Critical": 100}

KNOWLEDGE_BASE = {
    "account_compromise": {
        "rule_name": "R1 — Account Compromise",
        "risk": "Account Compromise Risk",
        "conditions": ["weak_password", "no_mfa"],
        "severity": "High",
        "rule_cf": 0.90,
        "reason": "A weak password combined with missing MFA makes unauthorized access much easier.",
        "advice": "Use strong unique passwords, enable MFA, and review account activity regularly.",
    },
    "malware_infection": {
        "rule_name": "R2 — Malware Infection",
        "risk": "Malware Infection Risk",
        "conditions": ["outdated_os", "antivirus_disabled"],
        "severity": "High",
        "rule_cf": 0.85,
        "reason": "An outdated system without active antivirus is highly exposed to malware.",
        "advice": "Update the OS, enable antivirus protection, and run a full malware scan.",
    },
    "phishing_attack": {
        "rule_name": "R3 — Phishing Attack",
        "risk": "Phishing Attack Risk",
        "conditions": ["suspicious_email_clicked", "low_security_awareness"],
        "severity": "Medium",
        "rule_cf": 0.80,
        "reason": "Clicking a suspicious link with low awareness increases phishing success probability.",
        "advice": "Reset affected passwords, report the email, and provide phishing awareness training.",
    },
    "public_wifi": {
        "rule_name": "R4 — Public Wi-Fi Risk",
        "risk": "Public Wi-Fi Risk",
        "conditions": ["public_wifi_used", "no_vpn"],
        "severity": "Medium",
        "rule_cf": 0.75,
        "reason": "Using public Wi-Fi without a VPN can expose traffic to interception.",
        "advice": "Avoid sensitive transactions on public Wi-Fi and use a trusted VPN.",
    },
    "brute_force": {
        "rule_name": "R5 — Brute Force Attack",
        "risk": "Brute Force Attack Risk",
        "conditions": ["failed_logins >= 5"],
        "severity": "High",
        "rule_cf": 0.85,
        "reason": "High failed login attempts indicate password guessing or automated attacks.",
        "advice": "Enable account lockout, review login logs, use MFA, and block suspicious IPs.",
    },
    "ransomware_data_loss": {
        "rule_name": "R6 — Ransomware & Data Loss",
        "risk": "Ransomware and Data Loss Risk",
        "conditions": ["ransomware_detected", "no_backup"],
        "severity": "Critical",
        "rule_cf": 0.95,
        "reason": "Ransomware without reliable backups creates a catastrophic data loss situation.",
        "advice": "Isolate systems, preserve evidence, restore from clean backups, initiate incident response.",
    },
    "data_breach": {
        "rule_name": "R7 — Data Breach",
        "risk": "Data Breach Risk",
        "conditions": ["data_breach"],
        "severity": "Critical",
        "rule_cf": 0.95,
        "reason": "A confirmed data breach requires immediate containment and response.",
        "advice": "Contain the incident, rotate credentials, notify responsible teams, investigate exposed data.",
    },
    "remote_access_exposure": {
        "rule_name": "R8 — Remote Access Exposure",
        "risk": "Remote Access Exposure Risk",
        "conditions": ["open_rdp", "weak_password"],
        "severity": "High",
        "rule_cf": 0.88,
        "reason": "Open RDP with weak passwords is a common path for unauthorized remote access.",
        "advice": "Close public RDP, restrict by IP, enable VPN, and enforce strong authentication.",
    },
    # ── Extra rules (improvements) ──
    "no_backup_risk": {
        "rule_name": "R9 — Missing Backup",
        "risk": "Data Loss Risk (No Backup)",
        "conditions": ["no_backup"],
        "severity": "Medium",
        "rule_cf": 0.70,
        "reason": "Even without ransomware, missing backups leaves data unrecoverable after any incident.",
        "advice": "Implement a 3-2-1 backup strategy: 3 copies, 2 media types, 1 offsite.",
    },
    "open_rdp_alone": {
        "rule_name": "R10 — Exposed RDP Port",
        "risk": "Remote Access Exposure Risk (Open RDP)",
        "conditions": ["open_rdp"],
        "severity": "Medium",
        "rule_cf": 0.72,
        "reason": "An open RDP port is a well-known attack surface regardless of password strength.",
        "advice": "Close public RDP access and use VPN-based access instead.",
    },
}

SCENARIOS = {
    "custom": {"label": "🔧 Custom Scenario", "issues": {}, "failed_logins": 0},
    "low": {
        "label": "🟢 Low Risk User",
        "issues": {"low_security_awareness": 0.55},
        "failed_logins": 1,
    },
    "medium": {
        "label": "🟡 Medium Risk User",
        "issues": {"weak_password": 0.75, "no_mfa": 0.80, "public_wifi_used": 0.70, "no_vpn": 0.70},
        "failed_logins": 3,
    },
    "high": {
        "label": "🔴 High Risk User",
        "issues": {
            "weak_password": 0.90, "no_mfa": 0.85, "outdated_os": 0.80,
            "antivirus_disabled": 0.85, "suspicious_email_clicked": 0.80,
            "low_security_awareness": 0.80, "open_rdp": 0.75,
        },
        "failed_logins": 8,
    },
    "critical": {
        "label": "💀 Critical — Ransomware Case",
        "issues": {
            "ransomware_detected": 0.95, "no_backup": 0.90, "data_breach": 0.90,
            "open_rdp": 0.85, "antivirus_disabled": 0.80,
        },
        "failed_logins": 15,
    },
}

ISSUE_LABELS = {
    "weak_password": "Weak Password",
    "no_mfa": "No Multi-Factor Authentication",
    "outdated_os": "Outdated Operating System",
    "antivirus_disabled": "Antivirus Disabled",
    "suspicious_email_clicked": "Suspicious Email Clicked",
    "public_wifi_used": "Public Wi-Fi Used",
    "no_vpn": "No VPN",
    "ransomware_detected": "Ransomware Detected",
    "no_backup": "No Backup",
    "data_breach": "Data Breach Detected",
    "open_rdp": "Open RDP Port",
    "low_security_awareness": "Low Security Awareness",
}

ISSUE_CATEGORIES = {
    "🔐 Account & Identity": ["weak_password", "no_mfa", "low_security_awareness"],
    "🖥️ System & Malware": ["outdated_os", "antivirus_disabled", "ransomware_detected", "no_backup"],
    "📧 Email & Phishing": ["suspicious_email_clicked"],
    "🌐 Network & Remote Access": ["public_wifi_used", "no_vpn", "open_rdp"],
    "💾 Data Protection": ["data_breach"],
}

SEVERITY_COLORS = {
    "Critical": "#f85149",
    "High": "#ff7b44",
    "Medium": "#e3b341",
    "Low": "#3fb950",
}

LEVEL_COLORS = {
    "Critical Risk": "#f85149",
    "High Risk": "#ff7b44",
    "Medium Risk": "#e3b341",
    "Low Risk": "#3fb950",
}


# ─── Engine Logic ────────────────────────────────────────────────────────────
def calculate_final_cf(rule_cf, *fact_cfs):
    if not fact_cfs:
        return round(rule_cf, 2)
    return round(rule_cf * min(fact_cfs), 2)


def classify_overall_risk(score):
    if score >= 75:
        return "Critical Risk"
    if score >= 50:
        return "High Risk"
    if score >= 25:
        return "Medium Risk"
    return "Low Risk"


def calculate_overall_score(risks):
    if not risks:
        return 0.0, "Low Risk"
    components = [SEVERITY_WEIGHTS[r["severity"]] * r["confidence"] for r in risks]
    max_comp = max(components)
    rest = sum(components) - max_comp
    score = max_comp * 0.70 + rest * 0.30
    score = min(100.0, round(score, 2))
    return score, classify_overall_risk(score)


def run_engine(issue_cfs: dict, failed_logins: int, failed_logins_cf: float) -> dict:
    detected = []
    trace = []

    def fire(key, *cfs):
        item = KNOWLEDGE_BASE[key]
        confidence = calculate_final_cf(item["rule_cf"], *cfs)
        detected.append({
            "rule": item["rule_name"],
            "risk": item["risk"],
            "severity": item["severity"],
            "confidence": confidence,
            "reason": item["reason"],
            "advice": item["advice"],
        })
        trace.append(
            f"{item['rule_name']} → {item['risk']} | "
            f"Severity: {item['severity']} | CF: {confidence}"
        )

    def has(*keys):
        return all(k in issue_cfs for k in keys)

    def cf(*keys):
        return [issue_cfs[k] for k in keys if k in issue_cfs]

    # R1
    if has("weak_password", "no_mfa"):
        fire("account_compromise", *cf("weak_password", "no_mfa"))
    # R2
    if has("outdated_os", "antivirus_disabled"):
        fire("malware_infection", *cf("outdated_os", "antivirus_disabled"))
    # R3
    if has("suspicious_email_clicked", "low_security_awareness"):
        fire("phishing_attack", *cf("suspicious_email_clicked", "low_security_awareness"))
    # R4
    if has("public_wifi_used", "no_vpn"):
        fire("public_wifi", *cf("public_wifi_used", "no_vpn"))
    # R5
    if failed_logins >= 5:
        fire("brute_force", failed_logins_cf)
    # R6
    if has("ransomware_detected", "no_backup"):
        fire("ransomware_data_loss", *cf("ransomware_detected", "no_backup"))
    # R7
    if has("data_breach"):
        fire("data_breach", *cf("data_breach"))
    # R8
    if has("open_rdp", "weak_password"):
        fire("remote_access_exposure", *cf("open_rdp", "weak_password"))
    # R9 (improvement)
    if "no_backup" in issue_cfs and "ransomware_detected" not in issue_cfs:
        fire("no_backup_risk", *cf("no_backup"))
    # R10 (improvement)
    if "open_rdp" in issue_cfs and "weak_password" not in issue_cfs:
        fire("open_rdp_alone", *cf("open_rdp"))

    score, level = calculate_overall_score(detected)

    if not trace:
        trace.append("No rules fired — current indicators show low cybersecurity risk.")

    return {
        "overall_score": score,
        "overall_level": level,
        "detected_risks": detected,
        "explanation_trace": trace,
    }


# ─── Chart Helpers ──────────────────────────────────────────────────────────
DARK_BG   = "#0d1117"
CARD_BG   = "#161b22"
BORDER    = "#30363d"
TEXT_MAIN = "#e6edf3"
TEXT_SUB  = "#8b949e"

def _plotly_layout(title="", height=300):
    return dict(
        title=dict(text=title, font=dict(color=TEXT_MAIN, size=14, family="IBM Plex Mono"), x=0.5),
        paper_bgcolor=DARK_BG,
        plot_bgcolor=CARD_BG,
        font=dict(color=TEXT_SUB, family="IBM Plex Sans"),
        margin=dict(l=24, r=24, t=40, b=24),
        height=height,
    )


def gauge_chart(score, level, level_color):
    fig = go.Figure(go.Indicator(
        mode="gauge+number",
        value=score,
        number={"suffix": "/100", "font": {"color": level_color, "size": 36, "family": "IBM Plex Mono"}},
        gauge={
            "axis": {"range": [0, 100], "tickcolor": TEXT_SUB, "tickfont": {"color": TEXT_SUB}},
            "bar": {"color": level_color, "thickness": 0.25},
            "bgcolor": CARD_BG,
            "bordercolor": BORDER,
            "steps": [
                {"range": [0,  25], "color": "#1a2e1a"},
                {"range": [25, 50], "color": "#2a2515"},
                {"range": [50, 75], "color": "#2a1e10"},
                {"range": [75, 100], "color": "#2a1010"},
            ],
            "threshold": {"line": {"color": level_color, "width": 3}, "value": score},
        },
    ))
    fig.update_layout(
        **_plotly_layout(f"Overall Risk Score — {level}", height=280),
    )
    return fig


def risks_bar_chart(risks):
    if not risks:
        return None
    names   = [r["risk"].replace(" Risk", "").replace(" and ", " & ") for r in risks]
    cfs     = [int(r["confidence"] * 100) for r in risks]
    colors  = [SEVERITY_COLORS.get(r["severity"], TEXT_SUB) for r in risks]
    severities = [r["severity"] for r in risks]

    fig = go.Figure()
    for i, (name, cf_val, color, sev) in enumerate(zip(names, cfs, colors, severities)):
        fig.add_trace(go.Bar(
            x=[cf_val],
            y=[name],
            orientation="h",
            marker=dict(color=color, opacity=0.85, line=dict(color=color, width=1)),
            text=f"{cf_val}% · {sev}",
            textposition="inside",
            textfont=dict(color="#fff", size=11, family="IBM Plex Mono"),
            name=sev,
            showlegend=False,
            hovertemplate=f"<b>{name}</b><br>Confidence: {cf_val}%<br>Severity: {sev}<extra></extra>",
        ))

    fig.update_layout(
        **_plotly_layout("Detected Risks — Confidence %", height=max(200, 60 * len(risks) + 60)),
        xaxis=dict(range=[0, 100], ticksuffix="%", gridcolor=BORDER, zerolinecolor=BORDER),
        yaxis=dict(autorange="reversed", gridcolor="rgba(0,0,0,0)"),
        bargap=0.3,
    )
    return fig


def severity_pie_chart(risks):
    if not risks:
        return None
    from collections import Counter
    counts = Counter(r["severity"] for r in risks)
    labels = list(counts.keys())
    values = list(counts.values())
    colors = [SEVERITY_COLORS.get(l, TEXT_SUB) for l in labels]

    fig = go.Figure(go.Pie(
        labels=labels,
        values=values,
        marker=dict(colors=colors, line=dict(color=DARK_BG, width=2)),
        textfont=dict(family="IBM Plex Mono", size=12),
        hole=0.5,
        hovertemplate="<b>%{label}</b>: %{value} rule(s)<extra></extra>",
    ))
    fig.update_layout(**_plotly_layout("Severity Distribution", height=280))
    return fig


def category_radar_chart(active_issues):
    """Show how many issues exist per ISSUE_CATEGORIES category."""
    if not active_issues:
        return None
    cats  = list(ISSUE_CATEGORIES.keys())
    scores = []
    for issues_list in ISSUE_CATEGORIES.values():
        activated = [iss for iss in issues_list if iss in active_issues]
        total = len(issues_list)
        pct = int(round(len(activated) / total * 100)) if total else 0
        scores.append(pct)

    # close the loop
    cats_loop   = cats + [cats[0]]
    scores_loop = scores + [scores[0]]

    fig = go.Figure(go.Scatterpolar(
        r=scores_loop,
        theta=cats_loop,
        fill="toself",
        fillcolor="rgba(248,81,73,0.15)",
        line=dict(color="#f85149", width=2),
        hovertemplate="%{theta}: %{r}%<extra></extra>",
    ))
    fig.update_layout(
        **_plotly_layout("Risk Coverage by Category", height=320),
        polar=dict(
            bgcolor=CARD_BG,
            radialaxis=dict(
                visible=True, range=[0, 100], ticksuffix="%",
                gridcolor=BORDER, tickfont=dict(color=TEXT_SUB, size=10),
            ),
            angularaxis=dict(gridcolor=BORDER, tickfont=dict(color=TEXT_MAIN, size=11)),
        ),
    )
    return fig


# ─── Session State ───────────────────────────────────────────────────────────
if "scenario" not in st.session_state:
    st.session_state.scenario = "custom"
if "issue_checks" not in st.session_state:
    st.session_state.issue_checks = {k: False for k in ISSUE_LABELS}
if "issue_cfs" not in st.session_state:
    st.session_state.issue_cfs = {k: 0.80 for k in ISSUE_LABELS}
if "failed_logins" not in st.session_state:
    st.session_state.failed_logins = 0
if "failed_logins_cf" not in st.session_state:
    st.session_state.failed_logins_cf = 0.85


def apply_scenario(key):
    s = SCENARIOS[key]
    for iss in ISSUE_LABELS:
        st.session_state.issue_checks[iss] = iss in s["issues"]
        st.session_state.issue_cfs[iss] = s["issues"].get(iss, 0.80)
    st.session_state.failed_logins = s["failed_logins"]
    st.session_state.scenario = key


# ─── Sidebar ─────────────────────────────────────────────────────────────────
with st.sidebar:
    st.markdown("### 🛡️ Cybersecurity Risk Advisor")
    st.markdown("---")

    # Scenario selector
    scenario_key = st.selectbox(
        "Quick Scenario",
        options=list(SCENARIOS.keys()),
        format_func=lambda k: SCENARIOS[k]["label"],
        index=list(SCENARIOS.keys()).index(st.session_state.scenario),
        key="scenario_select",
    )
    if scenario_key != st.session_state.scenario:
        apply_scenario(scenario_key)
        st.rerun()

    st.markdown("---")

    # Issue checkboxes + CF sliders
    for cat, issues in ISSUE_CATEGORIES.items():
        st.markdown(f"**{cat}**")
        for iss in issues:
            col1, col2 = st.columns([1, 1])
            with col1:
                checked = st.checkbox(
                    ISSUE_LABELS[iss],
                    value=st.session_state.issue_checks[iss],
                    key=f"chk_{iss}",
                )
                st.session_state.issue_checks[iss] = checked
            with col2:
                cf_val = st.slider(
                    "CF",
                    0.0, 1.0,
                    value=st.session_state.issue_cfs[iss],
                    step=0.05,
                    key=f"cf_{iss}",
                    disabled=not checked,
                    label_visibility="collapsed",
                )
                st.session_state.issue_cfs[iss] = cf_val
        st.markdown("")

    st.markdown("---")
    st.markdown("**🔐 Login Attack Indicator**")
    failed_logins = st.number_input(
        "Failed Login Attempts",
        min_value=0, max_value=200,
        value=st.session_state.failed_logins,
        key="failed_logins_input",
    )
    st.session_state.failed_logins = failed_logins

    fl_cf = st.slider(
        "Login CF",
        0.0, 1.0,
        value=st.session_state.failed_logins_cf,
        step=0.05,
        disabled=(failed_logins == 0),
        key="fl_cf_slider",
    )
    st.session_state.failed_logins_cf = fl_cf

    st.markdown("---")
    analyze = st.button("🔍 Analyze Risk", use_container_width=True, type="primary")
    reset = st.button("↺ Reset", use_container_width=True)
    if reset:
        apply_scenario("custom")
        st.session_state.failed_logins = 0
        st.session_state.failed_logins_cf = 0.85
        st.rerun()


# ─── Main Panel ──────────────────────────────────────────────────────────────
st.markdown("""
<div class="risk-header">
    <h1>🛡️ Cybersecurity Risk Advisor</h1>
    <p>Expert system using Certainty Factors (CF) and rule-based inference to classify cybersecurity risk.</p>
</div>
""", unsafe_allow_html=True)

if analyze:
    active_issues = {
        iss: st.session_state.issue_cfs[iss]
        for iss, checked in st.session_state.issue_checks.items()
        if checked
    }

    report = run_engine(active_issues, st.session_state.failed_logins, st.session_state.failed_logins_cf)

    score = int(round(report["overall_score"]))
    level = report["overall_level"]
    risks = report["detected_risks"]
    trace = report["explanation_trace"]
    level_color = LEVEL_COLORS.get(level, "#8b949e")

    # ── Metrics row ──
    c1, c2, c3 = st.columns(3)
    with c1:
        st.markdown(f"""
        <div class="metric-card">
            <div class="metric-label">Overall Risk Level</div>
            <div class="metric-value" style="color:{level_color};">{level}</div>
        </div>""", unsafe_allow_html=True)
    with c2:
        st.markdown(f"""
        <div class="metric-card">
            <div class="metric-label">Risk Score</div>
            <div class="metric-value" style="color:{level_color};">{score}<span style="font-size:16px;color:#8b949e;">/100</span></div>
        </div>""", unsafe_allow_html=True)
    with c3:
        st.markdown(f"""
        <div class="metric-card">
            <div class="metric-label">Rules Fired</div>
            <div class="metric-value" style="color:#e6edf3;">{len(risks)}</div>
        </div>""", unsafe_allow_html=True)

    st.markdown("<br>", unsafe_allow_html=True)
    st.progress(score / 100)

    # ── Charts row ──────────────────────────────────────────────────────────
    st.markdown("<br>", unsafe_allow_html=True)
    ch1, ch2, ch3 = st.columns([1, 1.4, 1])

    with ch1:
        gauge = gauge_chart(score, level, level_color)
        st.plotly_chart(gauge, use_container_width=True, config={"displayModeBar": False})

    with ch2:
        bar = risks_bar_chart(risks)
        if bar:
            st.plotly_chart(bar, use_container_width=True, config={"displayModeBar": False})
        else:
            st.markdown(
                "<div style='height:280px;display:flex;align-items:center;justify-content:center;"
                "color:#3fb950;font-family:IBM Plex Mono;font-size:13px;'>&#10003; No risks detected</div>",
                unsafe_allow_html=True,
            )

    with ch3:
        pie = severity_pie_chart(risks)
        if pie:
            st.plotly_chart(pie, use_container_width=True, config={"displayModeBar": False})

    # radar always full-width if we have active inputs
    radar = category_radar_chart(active_issues)
    if radar:
        st.plotly_chart(radar, use_container_width=True, config={"displayModeBar": False})

    st.markdown("<br>", unsafe_allow_html=True)

    if not risks:
        st.success("✅ No major risks detected. Current indicators show a low cybersecurity risk.")
    else:
        st.markdown("### Detected Risks")
        for risk in risks:
            sev_color = SEVERITY_COLORS.get(risk["severity"], "#8b949e")
            conf_pct = int(round(risk["confidence"] * 100))
            st.markdown(f"""
            <div class="risk-card" style="border-left-color:{sev_color};">
                <h4>{risk["risk"]}</h4>
                <p>
                    <b style="color:#e6edf3;">Rule:</b> {risk["rule"]} &nbsp;|&nbsp;
                    <b style="color:#e6edf3;">Severity:</b> <span style="color:{sev_color};font-weight:700;">{risk["severity"]}</span> &nbsp;|&nbsp;
                    <b style="color:#e6edf3;">CF:</b> {risk["confidence"]} ({conf_pct}%)
                </p>
                <div style="background:#0d1117;border-radius:6px;height:6px;width:100%;margin:8px 0;">
                    <div style="background:{sev_color};height:6px;width:{conf_pct}%;border-radius:6px;"></div>
                </div>
                <p><b style="color:#c9d1d9;">Why:</b> {risk["reason"]}</p>
                <p class="advice">💡 {risk["advice"]}</p>
            </div>
            """, unsafe_allow_html=True)

    # ── Explanation Trace ──
    st.markdown("### Explanation Trace")
    trace_lines = "".join([
        f'<div class="trace-line"><span class="trace-arrow">▶</span> {line}</div>'
        for line in trace
    ])
    st.markdown(f'<div class="trace-box">{trace_lines}</div>', unsafe_allow_html=True)

else:
    st.markdown("""
    <div style="
        background: #161b22;
        border: 1px dashed #30363d;
        border-radius: 12px;
        padding: 60px;
        text-align: center;
        color: #8b949e;
    ">
        <div style="font-size: 48px; margin-bottom: 16px;">🛡️</div>
        <div style="font-family: 'IBM Plex Mono', monospace; font-size: 16px; color: #c9d1d9; margin-bottom: 8px;">
            Ready to analyze
        </div>
        <div style="font-size: 13px;">
            Select the security indicators from the sidebar, then click <b style="color:#58a6ff;">Analyze Risk</b>.
        </div>
    </div>
    """, unsafe_allow_html=True)

    # ── KB Summary ──
    st.markdown("<br>", unsafe_allow_html=True)
    st.markdown("### Knowledge Base Summary")
    cols = st.columns(2)
    for i, (key, item) in enumerate(KNOWLEDGE_BASE.items()):
        sev_color = SEVERITY_COLORS.get(item["severity"], "#8b949e")
        with cols[i % 2]:
            st.markdown(f"""
            <div class="risk-card" style="border-left-color:{sev_color}; margin-bottom:10px;">
                <h4 style="font-size:13px;">{item["rule_name"]}</h4>
                <p><b style="color:#c9d1d9;">Conditions:</b> {", ".join(item["conditions"])}</p>
                <p>
                    <span style="color:{sev_color};font-weight:700;">{item["severity"]}</span>
                    &nbsp;·&nbsp; CF = {item["rule_cf"]}
                </p>
            </div>
            """, unsafe_allow_html=True)
