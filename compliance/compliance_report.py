"""
DPDP & IT Act Compliance Audit Report Generator
Maps insider threat detections to Indian IT Act 2000, DPDP Act 2023, and GDPR provisions.
Evaluates detection compliance and generates actionable audit reports.
"""

import os
import json
from datetime import datetime

REPORTS_DIR = os.path.join(os.path.dirname(__file__), 'reports')

# ---------------------------------------------------------------------------
# Legal Mappings
# ---------------------------------------------------------------------------

IT_ACT_SECTIONS = {
    "Section 43": "Penalty and compensation for damage to computer, computer system, etc.",
    "Section 66": "Computer related offences (hacking with criminal intent).",
    "Section 66C": "Punishment for identity theft.",
    "Section 66E": "Punishment for violation of privacy.",
    "Section 72": "Breach of confidentiality and privacy by persons given access.",
}

DPDP_ACT_SECTIONS = {
    "Section 4": "Obligations of Data Fiduciary — process personal data lawfully.",
    "Section 5": "Consent — valid, informed, specific consent required for processing.",
    "Section 6": "Certain legitimate uses — processing without consent for specific purposes.",
    "Section 8": "Rights of Data Principals — access, correction, erasure, grievance redressal.",
    "Section 10": "Obligations of Significant Data Fiduciaries — DPO, audits, DPIA.",
}

GDPR_ARTICLES = {
    "Article 5": "Principles: lawfulness, fairness, transparency, purpose limitation, data minimisation.",
    "Article 13": "Information to be provided where personal data are collected from the data subject.",
    "Article 14": "Information to be provided where personal data have not been obtained from the data subject.",
    "Article 22": "Automated individual decision-making, including profiling.",
}

# Mapping of threat type → relevant legal sections
THREAT_LEGAL_MAP = {
    "mass_download": {
        "IT Act 2000": ["Section 43", "Section 66"],
        "DPDP Act 2023": ["Section 4", "Section 6", "Section 10"],
        "GDPR": ["Article 5", "Article 22"],
    },
    "after_hours_access": {
        "IT Act 2000": ["Section 43", "Section 66"],
        "DPDP Act 2023": ["Section 4", "Section 5"],
        "GDPR": ["Article 5", "Article 14"],
    },
    "unauthorized_usb": {
        "IT Act 2000": ["Section 43", "Section 66", "Section 72"],
        "DPDP Act 2023": ["Section 4", "Section 6", "Section 8"],
        "GDPR": ["Article 5", "Article 13"],
    },
    "data_exfiltration": {
        "IT Act 2000": ["Section 43", "Section 66", "Section 66E", "Section 72"],
        "DPDP Act 2023": ["Section 4", "Section 5", "Section 10"],
        "GDPR": ["Article 5", "Article 13", "Article 22"],
    },
    "credential_misuse": {
        "IT Act 2000": ["Section 66", "Section 66C"],
        "DPDP Act 2023": ["Section 4", "Section 8"],
        "GDPR": ["Article 5", "Article 14", "Article 22"],
    },
    "suspicious_email": {
        "IT Act 2000": ["Section 66", "Section 66E"],
        "DPDP Act 2023": ["Section 4", "Section 5", "Section 8"],
        "GDPR": ["Article 5", "Article 13", "Article 14"],
    },
}

ALL_THREAT_TYPES = list(THREAT_LEGAL_MAP.keys())

# ---------------------------------------------------------------------------
# Compliance Evaluation
# ---------------------------------------------------------------------------

def _evaluate_data_minimisation(threat_type, additional_context):
    """Check whether only necessary data was collected for the detection."""
    necessary_fields = {
        "mass_download": ["files_accessed", "download_volume"],
        "after_hours_access": ["login_time", "logout_time"],
        "unauthorized_usb": ["device_id", "plug_time"],
        "data_exfiltration": ["files_accessed", "transfer_method"],
        "credential_misuse": ["login_attempts", "source_ip"],
        "suspicious_email": ["email_count", "keyword_flags"],
    }
    required = necessary_fields.get(threat_type, [])
    extra_fields = [k for k in (additional_context or {}) if k not in required]
    compliant = len(extra_fields) == 0
    return {
        "compliant": compliant,
        "required_fields": required,
        "extra_fields_collected": extra_fields,
        "recommendation": (
            "Data collection is minimal and appropriate."
            if compliant
            else f"Extra fields collected beyond necessity: {extra_fields}. "
                 "Review whether these are required for the detection."
        ),
    }


def _evaluate_automated_decision(anomaly_score):
    """Assess whether the confidence score warrants human review."""
    if anomaly_score >= 0.85:
        level = "HIGH"
        human_review = "Optional — confidence is high, but human review is still recommended for legal defensibility."
    elif anomaly_score >= 0.50:
        level = "MEDIUM"
        human_review = "REQUIRED — confidence is moderate; automated action alone is not legally defensible."
    else:
        level = "LOW"
        human_review = "MANDATORY — confidence is insufficient for any automated action. Human investigation required."
    return {
        "anomaly_score": anomaly_score,
        "confidence_level": level,
        "human_review_required": level != "HIGH",
        "recommendation": human_review,
    }


def _evaluate_lawful_basis(threat_type, department):
    """Determine if there is a valid lawful ground for processing behavioral data."""
    # Legitimate interest grounds per threat type
    grounds = {
        "mass_download": "Legitimate interest — prevention of data loss and protection of organisational assets.",
        "after_hours_access": "Legitimate interest — monitoring for unauthorised access outside business hours.",
        "unauthorized_usb": "Legitimate interest — preventing data exfiltration via removable media.",
        "data_exfiltration": "Legitimate interest and legal obligation — protection of sensitive organisational data.",
        "credential_misuse": "Legitimate interest — preventing identity fraud and unauthorised system access.",
        "suspicious_email": "Legitimate interest — monitoring communications for insider threat indicators.",
    }
    basis = grounds.get(threat_type, "Legitimate interest — security monitoring.")
    return {
        "lawful_basis": basis,
        "department_monitored": department,
        "compliant": True,
        "recommendation": (
            f"Processing of behavioural data for '{threat_type}' in department '{department}' "
            "is supported by a legitimate interest ground. Ensure employees have been notified "
            "of monitoring policies per DPDP Act Section 5 and GDPR Article 13/14."
        ),
    }


# ---------------------------------------------------------------------------
# Report Generation
# ---------------------------------------------------------------------------

def generate_compliance_report(user_id, threat_type, anomaly_score,
                                department="Unknown",
                                additional_context=None):
    """
    Generate a full compliance audit report for a flagged insider threat detection event.

    Parameters
    ----------
    user_id : str
        Identifier of the flagged user.
    threat_type : str
        One of: mass_download, after_hours_access, unauthorized_usb,
                data_exfiltration, credential_misuse, suspicious_email.
    anomaly_score : float
        The anomaly / confidence score (0–2+ range depending on model).
    department : str
        Department the user belongs to.
    additional_context : dict, optional
        Extra data fields collected during detection.

    Returns
    -------
    dict
        Structured compliance audit report.
    """
    if threat_type not in THREAT_LEGAL_MAP:
        threat_type = "mass_download"  # fallback

    timestamp = datetime.now().isoformat()
    additional_context = additional_context or {}

    # Legal mapping
    legal_map = {}
    tt_map = THREAT_LEGAL_MAP[threat_type]
    for law, sections in tt_map.items():
        if law == "IT Act 2000":
            legal_map[law] = {s: IT_ACT_SECTIONS[s] for s in sections}
        elif law == "DPDP Act 2023":
            legal_map[law] = {s: DPDP_ACT_SECTIONS[s] for s in sections}
        elif law == "GDPR":
            legal_map[law] = {s: GDPR_ARTICLES[s] for s in sections}

    # Compliance evaluation
    data_min = _evaluate_data_minimisation(threat_type, additional_context)
    auto_dec = _evaluate_automated_decision(anomaly_score)
    lawful = _evaluate_lawful_basis(threat_type, department)

    # Recommended actions
    actions = _build_recommended_actions(threat_type, auto_dec, data_min, lawful)

    report = {
        "report_id": f"COMPLIANCE-{user_id}-{datetime.now().strftime('%Y%m%d%H%M%S')}",
        "timestamp": timestamp,
        "user_id": user_id,
        "threat_type": threat_type,
        "anomaly_score": anomaly_score,
        "department": department,
        "additional_context": additional_context,
        "legal_mapping": legal_map,
        "compliance_evaluation": {
            "data_minimisation": data_min,
            "automated_decision_making": auto_dec,
            "lawful_basis": lawful,
        },
        "recommended_actions": actions,
        "overall_compliant": data_min["compliant"] and lawful["compliant"],
    }
    return report


def _build_recommended_actions(threat_type, auto_dec, data_min, lawful):
    """Build a list of recommended actions for the security / legal team."""
    actions = []

    # Always recommend based on confidence level
    if auto_dec["confidence_level"] == "HIGH":
        actions.append("Review flagged activity and confirm automated assessment before proceeding with disciplinary action.")
    elif auto_dec["confidence_level"] == "MEDIUM":
        actions.append("Escalate to a human analyst for investigation before taking any action.")
        actions.append("Document the human review decision for audit trail.")
    else:
        actions.append("Do NOT take any automated action — anomaly score is too low.")
        actions.append("Refer to security team for further manual investigation if warranted.")

    # Data minimisation
    if not data_min["compliant"]:
        actions.append(f"Review extra data collected: {data_min['extra_fields_collected']}. "
                       "Remove or justify any unnecessary fields per DPDP Act Section 4.")

    # Notification obligation
    actions.append("Ensure the user's monitoring notification is on record per DPDP Act Section 5 / GDPR Article 13.")

    # Threat-specific
    threat_actions = {
        "mass_download": "Restrict download access and audit file sensitivity classification.",
        "after_hours_access": "Review access control policies for after-hours system use.",
        "unauthorized_usb": "Enforce USB device whitelisting and review DLP policies.",
        "data_exfiltration": "Immediately isolate the user's network access and preserve forensic evidence.",
        "credential_misuse": "Force password reset, enable MFA, and review access logs.",
        "suspicious_email": "Quarantine flagged emails and review email DLP rules.",
    }
    if threat_type in threat_actions:
        actions.append(threat_actions[threat_type])

    # DPIA recommendation for significant processing
    actions.append("Consider conducting a Data Protection Impact Assessment (DPIA) per DPDP Act Section 10 / GDPR Article 35.")

    return actions


# ---------------------------------------------------------------------------
# Report Export
# ---------------------------------------------------------------------------

def _ensure_reports_dir():
    os.makedirs(REPORTS_DIR, exist_ok=True)


def save_report_txt(report):
    """Save the compliance report as a human-readable .txt file."""
    _ensure_reports_dir()
    filename = f"{report['report_id']}.txt"
    filepath = os.path.join(REPORTS_DIR, filename)

    lines = []
    lines.append("=" * 70)
    lines.append("COMPLIANCE AUDIT REPORT")
    lines.append("=" * 70)
    lines.append(f"Report ID   : {report['report_id']}")
    lines.append(f"Timestamp   : {report['timestamp']}")
    lines.append(f"User ID     : {report['user_id']}")
    lines.append(f"Threat Type : {report['threat_type']}")
    lines.append(f"Anomaly Score: {report['anomaly_score']:.4f}")
    lines.append(f"Department  : {report['department']}")
    lines.append(f"Overall Compliant: {'YES' if report['overall_compliant'] else 'NO'}")
    lines.append("")

    lines.append("-" * 70)
    lines.append("LEGAL MAPPING")
    lines.append("-" * 70)
    for law, sections in report["legal_mapping"].items():
        lines.append(f"\n  {law}:")
        for sec, desc in sections.items():
            lines.append(f"    {sec}: {desc}")

    lines.append("")
    lines.append("-" * 70)
    lines.append("COMPLIANCE EVALUATION")
    lines.append("-" * 70)

    dm = report["compliance_evaluation"]["data_minimisation"]
    lines.append(f"\n  Data Minimisation:")
    lines.append(f"    Compliant: {'YES' if dm['compliant'] else 'NO'}")
    lines.append(f"    Required Fields: {dm['required_fields']}")
    lines.append(f"    Extra Fields: {dm['extra_fields_collected']}")
    lines.append(f"    Recommendation: {dm['recommendation']}")

    ad = report["compliance_evaluation"]["automated_decision_making"]
    lines.append(f"\n  Automated Decision-Making:")
    lines.append(f"    Anomaly Score: {ad['anomaly_score']:.4f}")
    lines.append(f"    Confidence Level: {ad['confidence_level']}")
    lines.append(f"    Human Review Required: {'YES' if ad['human_review_required'] else 'NO'}")
    lines.append(f"    Recommendation: {ad['recommendation']}")

    lb = report["compliance_evaluation"]["lawful_basis"]
    lines.append(f"\n  Lawful Basis:")
    lines.append(f"    Basis: {lb['lawful_basis']}")
    lines.append(f"    Department: {lb['department_monitored']}")
    lines.append(f"    Compliant: {'YES' if lb['compliant'] else 'NO'}")
    lines.append(f"    Recommendation: {lb['recommendation']}")

    lines.append("")
    lines.append("-" * 70)
    lines.append("RECOMMENDED ACTIONS")
    lines.append("-" * 70)
    for i, action in enumerate(report["recommended_actions"], 1):
        lines.append(f"  {i}. {action}")

    lines.append("")
    lines.append("=" * 70)
    lines.append("END OF REPORT")
    lines.append("=" * 70)

    with open(filepath, 'w') as f:
        f.write('\n'.join(lines))

    return filepath


def save_report_json(report):
    """Save the compliance report as a structured .json file."""
    _ensure_reports_dir()
    filename = f"{report['report_id']}.json"
    filepath = os.path.join(REPORTS_DIR, filename)

    with open(filepath, 'w') as f:
        json.dump(report, f, indent=2, default=str)

    return filepath
