"""
Streamlit UI tab for the DPDP & IT Act Compliance Audit Module.
Plug this into the dashboard via: render_compliance_tab()
"""

import streamlit as st
import pandas as pd
import os
import glob

from compliance.compliance_report import (
    generate_compliance_report,
    save_report_txt,
    save_report_json,
    ALL_THREAT_TYPES,
    REPORTS_DIR,
)

DATA_DIR = 'data'


def render_compliance_tab():
    """Render the full Compliance Audit tab inside a Streamlit app."""

    st.header("⚖️ DPDP & IT Act Compliance Audit")
    st.markdown(
        "Generate legal compliance audit reports that map insider threat detections "
        "to **IT Act 2000**, **DPDP Act 2023**, and **GDPR** provisions."
    )

    # Load anomaly scores
    scores_path = os.path.join(DATA_DIR, 'anomaly_scores.csv')
    if not os.path.exists(scores_path):
        st.error("Anomaly scores not found. Please run the model training pipeline first.")
        return

    scores = pd.read_csv(scores_path)

    # --- Report Generator ---
    st.subheader("Generate Compliance Report")

    col1, col2 = st.columns(2)
    with col1:
        selected_user = st.selectbox(
            "Select Flagged User",
            scores['user'].tolist(),
            key='compliance_user',
        )
        threat_type = st.selectbox(
            "Threat Type",
            ALL_THREAT_TYPES,
            format_func=lambda x: x.replace('_', ' ').title(),
            key='compliance_threat',
        )

    with col2:
        department = st.selectbox(
            "Department",
            ["Finance", "Engineering", "HR", "IT", "Legal", "Operations", "Executive", "Other"],
            key='compliance_dept',
        )
        # Show the user's max anomaly score
        user_row = scores[scores['user'] == selected_user].iloc[0]
        max_score = max(
            user_row['isolation_forest'],
            user_row['oneclass_svm'],
            user_row['autoencoder'],
        )
        is_red_team = user_row['is_red_team'] == 1
        st.metric("Max Anomaly Score", f"{max_score:.4f}")
        if is_red_team:
            st.warning("🚩 This user is flagged as a Red Team member.")

    # Generate button
    if st.button("🔍 Generate Compliance Report", key='gen_compliance', type='primary'):
        report = generate_compliance_report(
            user_id=selected_user,
            threat_type=threat_type,
            anomaly_score=max_score,
            department=department,
            additional_context={},
        )
        st.session_state['latest_compliance_report'] = report
        st.success(f"Report generated: **{report['report_id']}**")

    # Display the report if generated
    if 'latest_compliance_report' in st.session_state:
        report = st.session_state['latest_compliance_report']
        _display_report(report)

    # --- Previous Reports ---
    st.divider()
    st.subheader("📁 Previous Reports")
    _display_previous_reports()


def _display_report(report):
    """Render a compliance report in expandable sections."""

    # Overall status
    if report['overall_compliant']:
        st.success("✅ Detection process is **COMPLIANT** with applicable regulations.")
    else:
        st.error("⚠️ Detection process has **COMPLIANCE ISSUES** that need attention.")

    st.markdown(f"**Report ID:** `{report['report_id']}`")
    st.markdown(f"**Timestamp:** {report['timestamp']}")

    # Legal Mapping
    with st.expander("📜 Legal Mapping", expanded=True):
        for law, sections in report['legal_mapping'].items():
            st.markdown(f"**{law}**")
            for sec, desc in sections.items():
                st.markdown(f"- **{sec}:** {desc}")

    # Compliance Evaluation
    with st.expander("🔎 Compliance Evaluation", expanded=True):
        eval_data = report['compliance_evaluation']

        st.markdown("##### Data Minimisation")
        dm = eval_data['data_minimisation']
        st.markdown(f"- **Compliant:** {'✅ Yes' if dm['compliant'] else '❌ No'}")
        st.markdown(f"- **Required Fields:** {', '.join(dm['required_fields']) if dm['required_fields'] else 'N/A'}")
        if dm['extra_fields_collected']:
            st.markdown(f"- **Extra Fields:** {', '.join(dm['extra_fields_collected'])}")
        st.info(dm['recommendation'])

        st.markdown("##### Automated Decision-Making")
        ad = eval_data['automated_decision_making']
        confidence_color = {"HIGH": "🟢", "MEDIUM": "🟡", "LOW": "🔴"}
        st.markdown(f"- **Confidence Level:** {confidence_color.get(ad['confidence_level'], '')} {ad['confidence_level']}")
        st.markdown(f"- **Human Review Required:** {'Yes' if ad['human_review_required'] else 'No'}")
        st.info(ad['recommendation'])

        st.markdown("##### Lawful Basis")
        lb = eval_data['lawful_basis']
        st.markdown(f"- **Basis:** {lb['lawful_basis']}")
        st.markdown(f"- **Department:** {lb['department_monitored']}")
        st.info(lb['recommendation'])

    # Recommended Actions
    with st.expander("📋 Recommended Actions", expanded=True):
        for i, action in enumerate(report['recommended_actions'], 1):
            st.markdown(f"{i}. {action}")

    # Export buttons
    st.divider()
    col1, col2 = st.columns(2)
    with col1:
        if st.button("💾 Export as .txt", key='export_txt'):
            path = save_report_txt(report)
            st.success(f"Saved to `{path}`")
    with col2:
        if st.button("💾 Export as .json", key='export_json'):
            path = save_report_json(report)
            st.success(f"Saved to `{path}`")


def _display_previous_reports():
    """List previously generated reports from the reports directory."""
    if not os.path.isdir(REPORTS_DIR):
        st.info("No reports generated yet.")
        return

    txt_files = sorted(glob.glob(os.path.join(REPORTS_DIR, '*.txt')), reverse=True)
    json_files = sorted(glob.glob(os.path.join(REPORTS_DIR, '*.json')), reverse=True)

    all_files = txt_files + json_files
    if not all_files:
        st.info("No reports generated yet.")
        return

    st.markdown(f"**{len(txt_files)}** text reports, **{len(json_files)}** JSON reports found.")

    for filepath in txt_files[:10]:  # Show latest 10
        filename = os.path.basename(filepath)
        with st.expander(f"📄 {filename}"):
            with open(filepath, 'r') as f:
                st.code(f.read(), language='text')
