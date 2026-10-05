import os
import json
import streamlit as st
import pandas as pd
from dotenv import load_dotenv
from google import genai
from google.genai import types
from pydantic import BaseModel, Field

# Load environment variables
load_dotenv()

# Page Setup
st.set_page_config(
    page_title="SHIELD | Cyber Threat & Log Analyzer",
    page_icon="🛡️",
    layout="wide",
)

st.title("🛡️ SHIELD")
st.caption("AI Incident Response Assistant & Security Log Auditor")

# Initialize Gemini API Client
api_key = os.getenv("GEMINI_API_KEY")

if not api_key:
    st.error("⚠️ GEMINI_API_KEY not found in .env file. Please check your configuration.")
    st.stop()


@st.cache_resource
def get_gemini_client(key: str):
    return genai.Client(api_key=key)


client = get_gemini_client(api_key)


# Pydantic Schema for Strict Security Report Parsing
class IndicatorOfCompromise(BaseModel):
    indicator: str = Field(description="Extracted IP address, user account, hash, process, or endpoint.")
    indicator_type: str = Field(
        description="Type: 'IP Address', 'User Account', 'Process Name', 'File Hash', or 'Domain'")
    threat_tag: str = Field(
        description="Suspicious activity tag (e.g., Brute Force Source, Privilege Escalation, Command Execution)")


class SecurityIncidentReport(BaseModel):
    attack_category: str = Field(
        description="Detected attack pattern (e.g., SSH Brute Force, SQL Injection, Ransomware Activity, Credential Stuffing)")
    threat_severity_score: int = Field(description="Threat score rating from 1 (Low) to 10 (Critical Incident)")
    risk_level: str = Field(description="Level label: 'Low', 'Medium', 'High', or 'CRITICAL'")
    summary: str = Field(description="2-3 sentence technical overview of what occurred in the log snippet.")
    extracted_iocs: list[IndicatorOfCompromise] = Field(
        description="List of extracted indicators of compromise (IoCs).")
    attack_chain_steps: list[str] = Field(description="Sequential breakdown of how the threat vector unfolded.")
    immediate_containment_steps: list[str] = Field(
        description="Step-by-step incident response containment actions (e.g., revoking tokens, firewall blocks).")
    remediation_recommendations: list[str] = Field(description="Long-term security strengthening recommendations.")


SYSTEM_INSTRUCTION = """
You are SHIELD, an expert SOC Tier 3 Security Analyst and Threat Hunter.
Analyze the provided security logs, event streams, or auth dumps.
Extract key Indicators of Compromise (IoCs), identify the attack vector, evaluate threat severity (1-10), and formulate containment/remediation steps.

Output ONLY valid JSON adhering strictly to the requested schema.
"""


def render_security_dashboard(report: dict):
    """Renders the structured JSON threat analysis into an interactive SOC dashboard."""

    # 1. High-Level Metrics
    score = report.get("threat_severity_score", 1)
    risk = report.get("risk_level", "Low").upper()
    category = report.get("attack_category", "Unknown Activity")

    m1, m2, m3 = st.columns(3)
    m1.metric(label="Attack Category", value=category)

    if score >= 8 or "CRITICAL" in risk or "HIGH" in risk:
        m2.metric(label="Threat Severity Score", value=f"{score}/10 🚨")
        m3.error(f"**Risk Level:** {risk}")
    elif score >= 5:
        m2.metric(label="Threat Severity Score", value=f"{score}/10 ⚠️")
        m3.warning(f"**Risk Level:** {risk}")
    else:
        m2.metric(label="Threat Severity Score", value=f"{score}/10 🟢")
        m3.success(f"**Risk Level:** {risk}")

    st.info(f"**Incident Summary:** {report.get('summary', '')}")
    st.divider()

    # 2. Extracted Indicators of Compromise (IoCs)
    st.subheader("🎯 Extracted Indicators of Compromise (IoCs)")
    iocs = report.get("extracted_iocs", [])
    if iocs:
        df_iocs = pd.DataFrame(iocs)
        df_iocs.columns = ["Indicator", "Type", "Threat Tag"]
        st.dataframe(df_iocs, use_container_width=True, hide_index=True)
    else:
        st.write("No distinct IoCs identified.")

    st.divider()

    # 3. Attack Chain & Containment Playbook
    col_chain, col_contain = st.columns(2)

    with col_chain:
        st.subheader("⛓️ Attack Chain Timeline")
        for idx, step in enumerate(report.get("attack_chain_steps", []), 1):
            st.markdown(f"**Step {idx}:** {step}")

    with col_contain:
        st.subheader("🔒 Immediate Containment Steps")
        for step in report.get("immediate_containment_steps", []):
            st.markdown(f"- 🛑 {step}")

    st.divider()

    # 4. Remediation Recommendations
    st.subheader("🛠️ Long-Term Remediation & Hardening")
    for rec in report.get("remediation_recommendations", []):
        st.markdown(f"- ✅ {rec}")


# Sidebar Controls
with st.sidebar:
    st.header("About SHIELD")
    st.info(
        "Paste auth logs, firewall logs, web server access logs, or SIEM events to generate an incident analysis report.")

# Main Input Interface
raw_logs = st.text_area(
    "Paste Security Logs / Event Data Here:",
    height=250,
    placeholder="Paste syslog, auth.log, Nginx access logs, or AWS CloudTrail JSON here..."
)

if st.button("🛡️ Audit Logs & Analyze Threat", type="primary", use_container_width=True):
    if not raw_logs.strip():
        st.warning("Please paste security logs before running analysis.")
    else:
        with st.spinner("Analyzing event patterns and extracting threat vectors"):
            try:
                response = client.models.generate_content(
                    model="gemini-3.5-flash-lite",
                    contents=[f"Audit these logs:\n{raw_logs}"],
                    config=types.GenerateContentConfig(
                        system_instruction=SYSTEM_INSTRUCTION,
                        temperature=0.1,
                        response_mime_type="application/json",
                        response_schema=SecurityIncidentReport,
                    ),
                )

                incident_data = json.loads(response.text)
                render_security_dashboard(incident_data)

            except Exception as e:
                st.error(f"Error during security analysis: {e}")