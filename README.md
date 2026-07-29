# Cloud Threat Detection and Automated Response with Microsoft Sentinel
<img src="https://img.shields.io/badge/-Azure-0089D6?style=for-the-badge&logo=microsoftazure&logoColor=white" /> <img src="https://img.shields.io/badge/-Sentinel-0078D4?style=for-the-badge&logo=microsoftazure&logoColor=white" /> <img src="https://img.shields.io/badge/-KQL-282C34?style=for-the-badge&logo=windowsterminal&logoColor=white" />

<img src="assets/Screenshot 2026-06-18 214711.png" alt="Cover Image" width="100%">

This repository contains the architecture, implementation details, and documentation for establishing a proactive cloud security operations capability using Microsoft Azure. This project was a two-week proof of concept (PoC) for CloudScale Logistics, a mid-market freight and supply chain client, to resolve an ISO 27001 audit finding regarding their cloud detection and response processes[<a href="https://drive.google.com/file/d/1YQePyB5OAFX_dhXKXgkdyy4xodhtibex/view?usp=drive_link" target="_blank">Detailed Project Rationale</a>].

For a detailed breakdown of the engagement and original documentation, please reference the project file: <a href="https://drive.google.com/file/d/1Fnv_GgqXHQJqW_Nh8fuUUOC8OEJrlDip/view?usp=drive_link" target="_blank">Full Step by Step Documentation</a>.

---

## 📖 Project Context

CloudScale Logistics widened its attack surface by migrating core platforms to Azure over an eighteen-month period. Because the internal team primarily possessed on-premises expertise, this migration led to several security operations challenges:
*   **No Unified Visibility:** Telemetry and alerts were scattered across disconnected portals, allowing potential attackers to move laterally without raising timely alerts.
*   **Manual Response:** Alert triage was entirely manual, with a real incident previously taking over four hours to reach a containment decision.
*   **Compliance Gap:** The lack of a documented detection and response process resulted in an ISO 27001 non-conformance finding from auditors.

---

## 🏗️ Solution Architecture

The deployment strategy aligns with the NIST Cybersecurity Framework (Detect, Respond, Recover). Data flows unidirectionally through three foundational pillars, making the system easy to audit and manage:

1.  **Data Ingestion:** Centralized collection of security telemetry from Azure Activity logs and Microsoft Defender for Cloud into a Log Analytics Workspace named `LAW-Sentinel-CloudScale`.
2.  **Analytics & Detection:** Microsoft Sentinel functions as the SIEM/SOAR layer, running analytics rules written in Kusto Query Language (KQL) against the incoming telemetry to identify threats.
3.  **Automation & Orchestration:** An automated Azure Logic App playbook (`Playbook-IncidentNotification-Email`) is triggered upon incident creation to rapidly notify the security team via email.

---

## 🚀 Implementation Steps

### 1. Foundation and Data Ingestion
*   Deployed a central resource group (`RG-Sentinel-PoC`) in the East US region to house all project resources for simplified tracking and clean-up.
*   Provisioned a Log Analytics Workspace with a 90-day retention policy to satisfy the client's immediate compliance obligations.
*   Enabled the Azure Activity connector to ingest subscription-level control-plane operations.
*   Enabled the free foundational tier of Microsoft Defender for Cloud to stream pre-analyzed workload alerts mapped to MITRE ATT&CK.

### 2. Detection Engineering
Several analytics rules were enabled and mapped to MITRE ATT&CK tactics, such as mass cloud resource deletions, rare subscription-level operations, and suspicious resource deployment. 

Additionally, a custom KQL rule was engineered specifically for this client to detect unauthorized privilege escalation—specifically, an insider or compromised account granting high privileges outside of standard business hours.

**Custom KQL Rule:**
```kusto
AzureActivity
| where OperationNameValue == "MICROSOFT.AUTHORIZATION/ROLEASSIGNMENTS/WRITE"
| where ActivityStatusValue == "Success"
| extend Role = tostring(parse_json(Authorization).evidence)
| where Role contains "Owner" or Role contains "Contributor"
| extend Hour = hourofday(TimeGenerated)
| extend DayOfWeek = dayofweek(TimeGenerated)
| where Hour < 8 or Hour > 18 or DayOfWeek == 0d or DayOfWeek == 6d
| project TimeGenerated, Caller, Role, ResourceGroup, SubscriptionId
```
*Note: During initial testing, it was discovered that AzureActivity stores the role under the "Authorization" JSON field, not "Properties". The query was hardened to reflect this structure to prevent silent detection failures.*

### 3. Automated Incident Response
*   **Incident Grouping:** Configured Sentinel to group related alerts sharing the same account or IP address within a 24-hour window into a single incident.
*   **Logic App Playbook:** Built a low-code automated response playbook triggered by incident creation. It parses incident details (Title, Severity, Time, Entities, and a direct URL) and immediately delivers a structured email alert to the security analysts.

---

## 🧪 Testing and Outcomes

To validate the system end-to-end, a controlled test was executed to simulate the exact threat the custom rule was built to catch.

*   **Action:** A high-privilege role (Contributor) was assigned to a test account outside of standard business hours.
*   **Detection:** The custom rule successfully matched the event and Sentinel raised a grouped incident.
*   **Automation:** The Logic App playbook executed without error.
*   **Result:** A formatted alert email was delivered to the security team. 

The full chain completed in under five minutes (between 3:50 AM and 3:55 AM), drastically improving upon the pre-engagement baseline of four+ hours. This successfully provided the documented, demonstrable detection process needed to close the ISO 27001 audit gap.

---

## 💡 Lessons Learned

*   **The Friendly-Name Trap:** Never assume a field contains the human-readable value expected. Always validate detections against a real sample event (e.g., verifying the JSON path for role authorizations).
*   **Verify Ingestion First:** Running simple queries (like `take 10`) before building complex analytics saves time. An analytics rule built on an empty table will silently fail.
*   **Test the Whole Chain:** A rule firing and a playbook running in isolation do not guarantee they work together. End-to-end testing is critical.
*   **Naming Conventions:** Placing all assets in a single, properly named resource group made the project highly trackable.


🔎🧾For a detailed breakdown of the engagement and original documentation, please reference the project file: <a href="https://drive.google.com/file/d/1Fnv_GgqXHQJqW_Nh8fuUUOC8OEJrlDip/view?usp=drive_link" target="_blank">Full Step by Step Documentation</a>.
