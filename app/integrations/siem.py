"""
Detection-engineering templates for the Threat Hunting Jira task.

These are *defensive* hunting queries keyed off public CVE metadata
(vendor, product, CWE, attack vector). They do not include exploit payloads.
"""

from __future__ import annotations

from app.models.vulnerability import Vulnerability


def generate_detections(vuln: Vulnerability) -> dict[str, str]:
    product = (vuln.product or "unknown_product").replace(" ", "_").lower()
    vendor = (vuln.vendor or "unknown_vendor").replace(" ", "_").lower()
    cve = vuln.cve_id
    cwe = ", ".join(vuln.cwe_ids or []) or "n/a"
    vector = (vuln.attack_vector or "NETWORK").upper()

    sigma = f"""title: Hunting — {cve} ({vuln.product or 'unknown product'})
id: evulntasker-{cve.lower()}
status: experimental
description: >
  Detect potential exploitation attempts related to {cve}
  affecting {vuln.vendor or 'unknown'} {vuln.product or 'unknown'}.
  CWE: {cwe}. Attack vector: {vector}.
author: EVulnTasker
date: {vuln.created_at.date().isoformat() if vuln.created_at else '1970-01-01'}
references:
  - https://nvd.nist.gov/vuln/detail/{cve}
logsource:
  product: {product}
  service: application
detection:
  keywords:
    - '{cve}'
    - '{vuln.product or product}'
  condition: keywords
falsepositives:
  - Vulnerability scanners
  - Patch-management tooling
level: {'high' if (vuln.cvss_score or 0) >= 7 else 'medium'}
tags:
  - attack.initial_access
  - {cve.lower()}
"""

    kql = f"""// Microsoft Sentinel / Defender — {cve}
DeviceProcessEvents
| where Timestamp > ago(7d)
| where ProcessCommandLine has_any ("{cve}", "{vuln.product or product}")
   or InitiatingProcessFileName has "{product}"
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName
| take 1000

union
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where RemoteUrl has "{product}" or RemoteUrl has "{vendor}"
| project Timestamp, DeviceName, ActionType, RemoteIP, RemoteUrl
"""

    xql = f"""// Cortex XSIAM / XQL — {cve}
dataset = xdr_data
| filter event_type in ("PROCESS", "NETWORK")
| filter
    action_process_image_command_line contains "{cve}"
    or action_process_image_name contains "{product}"
    or dst_action_external_hostname contains "{vendor}"
| fields _time, agent_hostname, actor_effective_username,
         action_process_image_name, action_process_image_command_line, action_remote_ip
| sort desc _time
| limit 1000
"""

    aqk = f"""// Azure Resource Graph / AQK-style hunt — {cve}
resources
| where type =~ "microsoft.compute/virtualmachines"
   or type =~ "microsoft.web/sites"
| extend productHint = "{product}", vendorHint = "{vendor}", cve = "{cve}"
| project id, name, type, location, resourceGroup, productHint, vendorHint, cve
| order by name asc
"""

    ekql = f"""// Elastic Kibana Query Language — {cve}
(event.kind: alert or event.category: (process or network or web))
and (
  process.command_line: "*{cve}*"
  or process.name: "*{product}*"
  or url.original: "*{product}*"
  or vulnerability.id: "{cve}"
)
"""

    return {
        "sigma_rule": sigma.strip() + "\n",
        "kql": kql.strip() + "\n",
        "xql": xql.strip() + "\n",
        "aqk": aqk.strip() + "\n",
        "ekql": ekql.strip() + "\n",
    }
