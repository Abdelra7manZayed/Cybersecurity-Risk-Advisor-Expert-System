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

def _base_layout(height=300, margin=None):
    m = margin or dict(l=32, r=32, t=48, b=32)
    return dict(
        paper_bgcolor=DARK_BG,
        plot_bgcolor=DARK_BG,
        font=dict(color=TEXT_SUB, family="IBM Plex Sans", size=12),
        margin=m,
        height=height,
    )


def gauge_chart(score, level, level_color):
    """Semi-circle gauge — number floats below the arc, no overlap."""
    fig = go.Figure()

    # Arc zones (background color bands)
    zone_colors = ["#1c2e1c", "#272314", "#2a1e10", "#2a1010"]
    zone_ranges = [(0, 25), (25, 50), (50, 75), (75, 100)]
    for (lo, hi), zc in zip(zone_ranges, zone_colors):
        fig.add_trace(go.Indicator(
            mode="gauge",
            value=lo,
            gauge={
                "axis": {"range": [0, 100], "visible": False},
                "bar": {"color": "rgba(0,0,0,0)", "thickness": 0},
                "bgcolor": "rgba(0,0,0,0)",
                "borderwidth": 0,
                "steps": [{"range": [lo, hi], "color": zc}],
            },
            domain={"x": [0, 1], "y": [0, 1]},
        ))

    # Main indicator — number positioned below arc
    fig.add_trace(go.Indicator(
        mode="gauge+number",
        value=score,
        number={
            "font": {"color": level_color, "size": 44, "family": "IBM Plex Mono"},
            "suffix": "",
            "valueformat": "d",
        },
        gauge={
            "axis": {
                "range": [0, 100],
                "tickvals": [0, 25, 50, 75, 100],
                "ticktext": ["0", "25", "50", "75", "100"],
                "tickcolor": BORDER,
                "tickfont": {"color": TEXT_SUB, "size": 10},
                "tickwidth": 1,
            },
            "bar": {"color": level_color, "thickness": 0.18},
            "bgcolor": "rgba(0,0,0,0)",
            "borderwidth": 0,
            "steps": [],
            "threshold": {
                "line": {"color": level_color, "width": 2},
                "thickness": 0.7,
                "value": score,
            },
        },
        domain={"x": [0, 1], "y": [0.1, 1]},
    ))

    # Level label below number, /100 tucked to the right of the score
    fig.add_annotation(
        text=level,
        x=0.5, y=0.04,
        xref="paper", yref="paper",
        showarrow=False,
        font=dict(color=level_color, size=12, family="IBM Plex Mono"),
    )
    fig.add_annotation(
        text="/ 100",
        x=0.73, y=0.22,
        xref="paper", yref="paper",
        showarrow=False,
        font=dict(color=TEXT_SUB, size=11, family="IBM Plex Mono"),
    )

    fig.update_layout(
        **_base_layout(height=260, margin=dict(l=20, r=20, t=36, b=16)),
        title=dict(
            text="Risk Score",
            font=dict(color=TEXT_MAIN, size=13, family="IBM Plex Mono"),
            x=0.5, y=0.97,
        ),
    )
    return fig


def risks_bar_chart(risks):
    """Horizontal bar per risk — label above bar, value outside to the right."""
    if not risks:
        return None

    # Sort by confidence descending
    risks_sorted = sorted(risks, key=lambda r: r["confidence"])
    names   = [r["risk"].replace(" Risk", "").replace(" and Data Loss", "") for r in risks_sorted]
    cfs     = [round(r["confidence"] * 100) for r in risks_sorted]
    colors  = [SEVERITY_COLORS.get(r["severity"], TEXT_SUB) for r in risks_sorted]
    sevs    = [r["severity"] for r in risks_sorted]

    bar_height = 36
    chart_h = max(240, bar_height * len(risks_sorted) + 100)

    fig = go.Figure()
    # Background track bars
    fig.add_trace(go.Bar(
        x=[100] * len(names),
        y=names,
        orientation="h",
        marker=dict(color="rgba(48,54,61,0.4)", line_width=0),
        hoverinfo="skip",
        showlegend=False,
    ))
    # Actual value bars
    fig.add_trace(go.Bar(
        x=cfs,
        y=names,
        orientation="h",
        marker=dict(
            color=colors,
            opacity=0.90,
            line_width=0,
        ),
        text=[f"{v}%" for v in cfs],
        textposition="outside",
        textfont=dict(color=TEXT_MAIN, size=12, family="IBM Plex Mono"),
        customdata=sevs,
        hovertemplate="<b>%{y}</b><br>Confidence: %{x}%<br>Severity: %{customdata}<extra></extra>",
        showlegend=False,
        cliponaxis=False,
    ))

    fig.update_layout(
        **_base_layout(height=chart_h, margin=dict(l=16, r=56, t=48, b=16)),
        title=dict(
            text="Detected Risks — Confidence",
            font=dict(color=TEXT_MAIN, size=13, family="IBM Plex Mono"),
            x=0.5, y=0.98,
        ),
        barmode="overlay",
        xaxis=dict(
            range=[0, 115],
            visible=False,
        ),
        yaxis=dict(
            autorange=True,
            tickfont=dict(color=TEXT_MAIN, size=11, family="IBM Plex Sans"),
            gridcolor="rgba(0,0,0,0)",
        ),
        bargap=0.40,
    )
    return fig


def severity_pie_chart(risks):
    """Donut chart — labels outside with leader lines, no inside text crowding."""
    if not risks:
        return None
    from collections import Counter
    order = ["Critical", "High", "Medium", "Low"]
    counts = Counter(r["severity"] for r in risks)
    labels = [s for s in order if s in counts]
    values = [counts[s] for s in labels]
    colors = [SEVERITY_COLORS[s] for s in labels]

    fig = go.Figure(go.Pie(
        labels=labels,
        values=values,
        marker=dict(colors=colors, line=dict(color=DARK_BG, width=3)),
        hole=0.60,
        textinfo="none",           # hide all inside text
        hovertemplate="<b>%{label}</b><br>%{value} rule(s) · %{percent}<extra></extra>",
        direction="clockwise",
        sort=False,
    ))

    # Custom legend-style annotations outside
    fig.update_traces(
        textposition="outside",
        texttemplate="%{label}<br><b>%{percent:.0%}</b>",
        textfont=dict(size=11, family="IBM Plex Mono", color=TEXT_MAIN),
        outsidetextfont=dict(size=10, family="IBM Plex Mono"),
        automargin=True,
    )

    fig.update_layout(
        **_base_layout(height=280, margin=dict(l=16, r=16, t=48, b=16)),
        title=dict(
            text="Severity Mix",
            font=dict(color=TEXT_MAIN, size=13, family="IBM Plex Mono"),
            x=0.5, y=0.98,
        ),
        showlegend=False,
    )
    return fig


def category_radar_chart(active_issues):
    """Radar showing % of issues activated per security category."""
    if not active_issues:
        return None

    # Clean short labels
    short_labels = {
        "🔐 Account & Identity": "Account &\nIdentity",
        "🖥️ System & Malware": "System &\nMalware",
        "📧 Email & Phishing": "Email &\nPhishing",
        "🌐 Network & Remote Access": "Network &\nRemote",
        "💾 Data Protection": "Data\nProtection",
    }
    cats = list(ISSUE_CATEGORIES.keys())
    display = [short_labels.get(c, c) for c in cats]
    scores = []
    for issues_list in ISSUE_CATEGORIES.values():
        activated = [iss for iss in issues_list if iss in active_issues]
        pct = round(len(activated) / len(issues_list) * 100) if issues_list else 0
        scores.append(pct)

    # Close the loop
    display_loop = display + [display[0]]
    scores_loop  = scores  + [scores[0]]

    fig = go.Figure()
    # Filled area
    fig.add_trace(go.Scatterpolar(
        r=scores_loop,
        theta=display_loop,
        fill="toself",
        fillcolor="rgba(248,81,73,0.12)",
        line=dict(color="#f85149", width=2),
        mode="lines+markers",
        marker=dict(size=6, color="#f85149", symbol="circle"),
        hovertemplate="%{theta}: %{r}%<extra></extra>",
        showlegend=False,
    ))

    fig.update_layout(
        **_base_layout(height=340, margin=dict(l=60, r=60, t=60, b=60)),
        title=dict(
            text="Risk Coverage by Category",
            font=dict(color=TEXT_MAIN, size=13, family="IBM Plex Mono"),
            x=0.5, y=0.98,
        ),
        polar=dict(
            bgcolor=CARD_BG,
            radialaxis=dict(
                visible=True,
                range=[0, 100],
                tickvals=[25, 50, 75, 100],
                ticktext=["25%", "50%", "75%", "100%"],
                gridcolor=BORDER,
                linecolor=BORDER,
                tickfont=dict(color=TEXT_SUB, size=9, family="IBM Plex Mono"),
                tickangle=0,
            ),
            angularaxis=dict(
                gridcolor=BORDER,
                linecolor=BORDER,
                tickfont=dict(color=TEXT_MAIN, size=11, family="IBM Plex Sans"),
                direction="clockwise",
            ),
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

    # ── Charts ──────────────────────────────────────────────────────────────
    st.markdown("<br>", unsafe_allow_html=True)

    # Row 1: Gauge (left) + Pie (right)
    ch1, ch2 = st.columns([1, 1])
    with ch1:
        gauge = gauge_chart(score, level, level_color)
        st.plotly_chart(gauge, use_container_width=True, config={"displayModeBar": False})
    with ch2:
        pie = severity_pie_chart(risks)
        if pie:
            st.plotly_chart(pie, use_container_width=True, config={"displayModeBar": False})

    # Row 2: Bar chart full-width
    bar = risks_bar_chart(risks)
    if bar:
        st.plotly_chart(bar, use_container_width=True, config={"displayModeBar": False})
    elif not risks:
        st.markdown(
            "<div style='padding:24px;text-align:center;color:#3fb950;"
            "font-family:IBM Plex Mono;font-size:13px;border:1px solid #30363d;"
            "border-radius:10px;background:#161b22;'>&#10003; No risks detected</div>",
            unsafe_allow_html=True,
        )

    # Row 3: Radar full-width
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
