import collections
import collections.abc

for name in ["Mapping", "MutableMapping", "Sequence", "Callable", "Hashable"]:
    if not hasattr(collections, name):
        setattr(collections, name, getattr(collections.abc, name))

import pandas as pd
import streamlit as st
from experta import Fact, KnowledgeEngine, Rule, MATCH, P


class SecurityIssue(Fact):
    pass


class LoginAttempts(Fact):
    pass


SEVERITY_WEIGHTS = {
    "Low": 25,
    "Medium": 50,
    "High": 75,
    "Critical": 100,
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
    "data_breach": "Data Breach",
    "open_rdp": "Open RDP Port",
    "low_security_awareness": "Low Security Awareness",
}

KNOWLEDGE_BASE = {
    "account_compromise": {
        "rule_name": "R1 - Account Compromise Risk",
        "risk": "Account Compromise Risk",
        "conditions": ["weak_password", "no_mfa"],
        "severity": "High",
        "rule_cf": 0.90,
        "advice": "Use strong unique passwords, enable MFA, and review account activity regularly.",
        "reason": "A weak password combined with missing MFA makes unauthorized access much easier.",
    },
    "malware_infection": {
        "rule_name": "R2 - Malware Infection Risk",
        "risk": "Malware Infection Risk",
        "conditions": ["outdated_os", "antivirus_disabled"],
        "severity": "High",
        "rule_cf": 0.85,
        "advice": "Update the operating system, enable antivirus protection, and run a full malware scan.",
        "reason": "An outdated system without active antivirus protection is more exposed to malware.",
    },
    "phishing_attack": {
        "rule_name": "R3 - Phishing Attack Risk",
        "risk": "Phishing Attack Risk",
        "conditions": ["suspicious_email_clicked", "low_security_awareness"],
        "severity": "Medium",
        "rule_cf": 0.80,
        "advice": "Reset affected passwords, report the email, and provide phishing awareness training.",
        "reason": "Clicking a suspicious email link with low awareness increases phishing success probability.",
    },
    "public_wifi": {
        "rule_name": "R4 - Public Wi-Fi Risk",
        "risk": "Public Wi-Fi Risk",
        "conditions": ["public_wifi_used", "no_vpn"],
        "severity": "Medium",
        "rule_cf": 0.75,
        "advice": "Avoid sensitive transactions on public Wi-Fi and use a trusted VPN.",
        "reason": "Using public Wi-Fi without VPN can expose traffic to interception.",
    },
    "brute_force": {
        "rule_name": "R5 - Brute Force Attack Risk",
        "risk": "Brute Force Attack Risk",
        "conditions": ["failed_login_attempts >= 5"],
        "severity": "High",
        "rule_cf": 0.85,
        "advice": "Enable account lockout, review login logs, use MFA, and block suspicious IP addresses.",
        "reason": "A high number of failed login attempts may indicate password guessing or automated attacks.",
    },
    "ransomware_data_loss": {
        "rule_name": "R6 - Ransomware and Data Loss Risk",
        "risk": "Ransomware and Data Loss Risk",
        "conditions": ["ransomware_detected", "no_backup"],
        "severity": "Critical",
        "rule_cf": 0.95,
        "advice": "Isolate affected systems, preserve evidence, restore from clean backups, and start incident response.",
        "reason": "Ransomware detection without reliable backups creates a serious data loss situation.",
    },
    "data_breach": {
        "rule_name": "R7 - Data Breach Risk",
        "risk": "Data Breach Risk",
        "conditions": ["data_breach"],
        "severity": "Critical",
        "rule_cf": 0.95,
        "advice": "Contain the incident, rotate credentials, notify responsible teams, and investigate exposed data.",
        "reason": "A reported data breach is a critical cybersecurity incident requiring immediate response.",
    },
    "remote_access_exposure": {
        "rule_name": "R8 - Remote Access Exposure Risk",
        "risk": "Remote Access Exposure Risk",
        "conditions": ["open_rdp", "weak_password"],
        "severity": "High",
        "rule_cf": 0.88,
        "advice": "Close public RDP access, restrict access by IP, enable VPN, and enforce strong authentication.",
        "reason": "Open RDP with weak passwords is a common path for unauthorized remote access.",
    },
}


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
        return 10.0, "Low Risk"

    components = []
    for risk in risks:
        components.append(SEVERITY_WEIGHTS[risk["severity"]] * risk["confidence"])

    score = max(components) * 0.70 + sum(components) * 0.30
    score = min(100.0, round(score, 2))
    return score, classify_overall_risk(score)


class CyberSecurityRiskAdvisor(KnowledgeEngine):
    def __init__(self):
        super().__init__()
        self.detected_risks = []
        self.trace = []

    def _add_risk(self, key, *fact_cfs):
        item = KNOWLEDGE_BASE[key]
        confidence = calculate_final_cf(item["rule_cf"], *fact_cfs)
        risk_record = {
            "rule": item["rule_name"],
            "risk": item["risk"],
            "severity": item["severity"],
            "confidence": confidence,
            "reason": item["reason"],
            "advice": item["advice"],
            "conditions": item["conditions"],
        }
        self.detected_risks.append(risk_record)
        self.trace.append(
            f"{item['rule_name']} fired -> {item['risk']} | "
            f"Severity: {item['severity']} | Confidence: {confidence}"
        )

    @Rule(SecurityIssue(name="ransomware_detected", status=True, cf=MATCH.cf1),
          SecurityIssue(name="no_backup", status=True, cf=MATCH.cf2), salience=100)
    def ransomware_and_data_loss_risk(self, cf1, cf2):
        self._add_risk("ransomware_data_loss", cf1, cf2)

    @Rule(SecurityIssue(name="data_breach", status=True, cf=MATCH.cf1), salience=95)
    def data_breach_risk(self, cf1):
        self._add_risk("data_breach", cf1)

    @Rule(SecurityIssue(name="weak_password", status=True, cf=MATCH.cf1),
          SecurityIssue(name="no_mfa", status=True, cf=MATCH.cf2), salience=85)
    def account_compromise_risk(self, cf1, cf2):
        self._add_risk("account_compromise", cf1, cf2)

    @Rule(SecurityIssue(name="outdated_os", status=True, cf=MATCH.cf1),
          SecurityIssue(name="antivirus_disabled", status=True, cf=MATCH.cf2), salience=80)
    def malware_infection_risk(self, cf1, cf2):
        self._add_risk("malware_infection", cf1, cf2)

    @Rule(LoginAttempts(count=P(lambda value: value >= 5), cf=MATCH.cf1), salience=75)
    def brute_force_attack_risk(self, cf1):
        self._add_risk("brute_force", cf1)

    @Rule(SecurityIssue(name="open_rdp", status=True, cf=MATCH.cf1),
          SecurityIssue(name="weak_password", status=True, cf=MATCH.cf2), salience=70)
    def remote_access_exposure_risk(self, cf1, cf2):
        self._add_risk("remote_access_exposure", cf1, cf2)

    @Rule(SecurityIssue(name="suspicious_email_clicked", status=True, cf=MATCH.cf1),
          SecurityIssue(name="low_security_awareness", status=True, cf=MATCH.cf2), salience=60)
    def phishing_attack_risk(self, cf1, cf2):
        self._add_risk("phishing_attack", cf1, cf2)

    @Rule(SecurityIssue(name="public_wifi_used", status=True, cf=MATCH.cf1),
          SecurityIssue(name="no_vpn", status=True, cf=MATCH.cf2), salience=55)
    def public_wifi_risk(self, cf1, cf2):
        self._add_risk("public_wifi", cf1, cf2)

    def get_report(self):
        score, level = calculate_overall_score(self.detected_risks)
        if not self.trace:
            self.trace.append("No high-confidence rule fired. Current indicators show a low cybersecurity risk.")
        return {
            "overall_score": score,
            "overall_level": level,
            "detected_risks": self.detected_risks,
            "explanation_trace": self.trace,
        }


def analyze_cybersecurity_risk(issue_confidences, failed_login_attempts=0, failed_login_cf=0.80):
    engine = CyberSecurityRiskAdvisor()
    engine.reset()
    for issue_name, cf in issue_confidences.items():
        engine.declare(SecurityIssue(name=issue_name, status=True, cf=float(cf)))
    engine.declare(LoginAttempts(count=int(failed_login_attempts), cf=float(failed_login_cf)))
    engine.run()
    return engine.get_report()


def get_risk_status(level):
    if level == "Low Risk":
        return "success", "Low risk: no critical rule fired, but basic security hygiene should continue."
    if level == "Medium Risk":
        return "warning", "Medium risk: some issues require attention and improvement."
    if level == "High Risk":
        return "error", "High risk: important security controls should be improved immediately."
    return "error", "Critical risk: immediate incident response is recommended."


def show_status_message(level):
    status_type, message = get_risk_status(level)
    if status_type == "success":
        st.success(message)
    elif status_type == "warning":
        st.warning(message)
    else:
        st.error(message)


def create_risk_dataframe(risks):
    if not risks:
        return pd.DataFrame()

    df = pd.DataFrame(risks)
    df["confidence_percent"] = (df["confidence"] * 100).round(1)
    return df


def show_metric_cards(report):
    detected_count = len(report["detected_risks"])
    highest_severity = "None"

    if detected_count > 0:
        severity_order = {"Low": 1, "Medium": 2, "High": 3, "Critical": 4}
        highest_severity = max(
            [risk["severity"] for risk in report["detected_risks"]],
            key=lambda severity: severity_order.get(severity, 0),
        )

    col1, col2, col3, col4 = st.columns(4)

    with col1:
        st.metric("Overall Risk Level", report["overall_level"])

    with col2:
        st.metric("Risk Score", f"{report['overall_score']} / 100")

    with col3:
        st.metric("Detected Risks", detected_count)

    with col4:
        st.metric("Highest Severity", highest_severity)


def show_risk_score_progress(report):
    score = float(report["overall_score"])
    st.subheader("Risk Score Progress")
    st.progress(int(score))
    st.caption("The score summarizes the final cybersecurity risk level from 0 to 100.")


def show_severity_distribution_chart(risks_df):
    st.subheader("Severity Distribution Chart")

    if risks_df.empty:
        st.info("No detected risks are available for severity distribution.")
        return

    severity_counts = risks_df["severity"].value_counts().reindex(
        ["Low", "Medium", "High", "Critical"],
        fill_value=0,
    )

    st.bar_chart(severity_counts)


def show_confidence_score_chart(risks_df):
    st.subheader("Confidence Score Chart")

    if risks_df.empty:
        st.info("No detected risks are available for confidence visualization.")
        return

    confidence_chart = risks_df[["risk", "confidence_percent"]].set_index("risk")
    st.bar_chart(confidence_chart)
    st.caption("Confidence values are calculated using the Certainty Factor equation.")


def show_risk_details_expanders(risks):
    st.subheader("Risk Details and Recommendations")

    if not risks:
        st.info("No major risk was detected based on the selected indicators.")
        return

    for risk in risks:
        title = f"{risk['risk']} | {risk['severity']} | Confidence: {risk['confidence'] * 100:.1f}%"

        with st.expander(title, expanded=False):
            st.write(f"**Rule Fired:** {risk['rule']}")
            st.write(f"**Severity:** {risk['severity']}")
            st.write(f"**Confidence:** {risk['confidence'] * 100:.1f}%")
            st.write(f"**Conditions:** {', '.join(risk['conditions'])}")
            st.write(f"**Why this risk was detected:** {risk['reason']}")
            st.write(f"**Recommended Actions:** {risk['advice']}")


def show_explanation_trace_timeline(trace):
    st.subheader("Explanation Trace Timeline")

    if not trace:
        st.info("No explanation trace is available.")
        return

    for index, step in enumerate(trace, start=1):
        with st.container():
            st.markdown(
                f"""
                <div style="
                    padding: 12px 16px;
                    margin-bottom: 10px;
                    border-left: 5px solid #2563eb;
                    border-radius: 10px;
                    background-color: rgba(37, 99, 235, 0.08);
                ">
                    <b>Step {index}</b><br>
                    {step}
                </div>
                """,
                unsafe_allow_html=True,
            )


st.set_page_config(page_title="Cybersecurity Risk Advisor", page_icon="🛡️", layout="wide")

st.title("🛡️ Cybersecurity Risk Advisor Expert System")
st.write(
    "A rule-based expert system that uses Experta, forward chaining, salience, "
    "certainty factors, and explanation tracing to assess cybersecurity risk."
)

st.sidebar.header("Security Indicators")
st.sidebar.write("Select the issues that apply, then set the confidence value for each selected issue.")

selected_issues = {}

for issue_name, label in ISSUE_LABELS.items():
    checked = st.sidebar.checkbox(label, value=False, key=f"check_{issue_name}")
    if checked:
        selected_issues[issue_name] = st.sidebar.slider(
            f"{label} confidence",
            min_value=0.0,
            max_value=1.0,
            value=0.80,
            step=0.05,
            key=f"cf_{issue_name}",
        )

failed_login_attempts = st.sidebar.number_input(
    "Failed Login Attempts",
    min_value=0,
    max_value=100,
    value=0,
    step=1,
)

failed_login_cf = 0.80

if failed_login_attempts >= 5:
    failed_login_cf = st.sidebar.slider(
        "Failed Login Attempts confidence",
        min_value=0.0,
        max_value=1.0,
        value=0.80,
        step=0.05,
    )

analyze_button = st.sidebar.button("Analyze Cybersecurity Risk", type="primary")

if analyze_button:
    report = analyze_cybersecurity_risk(selected_issues, failed_login_attempts, failed_login_cf)
    risks_df = create_risk_dataframe(report["detected_risks"])

    show_metric_cards(report)
    show_status_message(report["overall_level"])
    show_risk_score_progress(report)

    tab1, tab2, tab3 = st.tabs(
        ["📊 Visualizations", "🧾 Detected Risks", "🧠 Explanation Trace"]
    )

    with tab1:
        col1, col2 = st.columns(2)

        with col1:
            show_severity_distribution_chart(risks_df)

        with col2:
            show_confidence_score_chart(risks_df)

        if not risks_df.empty:
            st.subheader("Detected Risks Summary Table")
            st.dataframe(
                risks_df[["risk", "severity", "confidence_percent", "rule"]],
                use_container_width=True,
                hide_index=True,
            )

    with tab2:
        show_risk_details_expanders(report["detected_risks"])

    with tab3:
        show_explanation_trace_timeline(report["explanation_trace"])

else:
    st.info("Use the sidebar to select security indicators, then click Analyze Cybersecurity Risk.")
    st.markdown(
        """
        **Example critical case:** select `Ransomware Detected` and `No Backup`, then set both confidence values above 0.80.  
        **Example high-risk case:** select `Weak Password`, `No MFA`, and set failed login attempts to 8.
        """
    )
