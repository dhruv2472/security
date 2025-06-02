# security

{
  "_index": ".internal.alerts-security.alerts-default-000001",
  "_id": "10da92e0b4351ac7b6a3460814f87d13204b7dad67818290dadffdbfff7482b1",
  "_score": 1,
  "_source": {
    "kibana.alert.rule.execution.timestamp": "2025-06-02T07:08:53.125Z",
    "kibana.alert.start": "2025-06-02T07:08:53.125Z",
    "kibana.alert.last_detected": "2025-06-02T07:08:53.125Z",
    "kibana.version": "9.0.1",
    "kibana.alert.rule.parameters": {
      "description": "Identifies multiple consecutive logon failures from the same source address and within a short time interval. Adversaries will often brute force login attempts across multiple users with a common or known password, in an attempt to gain access to accounts.",
      "risk_score": 47,
      "severity": "medium",
      "note": "## Triage and analysis\n\n### Investigating Multiple Logon Failure from the same Source Address\n\nAdversaries with no prior knowledge of legitimate credentials within the system or environment may guess passwords to attempt access to accounts. Without knowledge of the password for an account, an adversary may opt to guess the password using a repetitive or iterative mechanism systematically. More details can be found [here](https://attack.mitre.org/techniques/T1110/001/).\n\nThis rule identifies potential password guessing/brute force activity from a single address.\n\n> **Note**:\n> This investigation guide uses the [Osquery Markdown Plugin](https://www.elastic.co/guide/en/security/current/invest-guide-run-osquery.html) introduced in Elastic Stack version 8.5.0. Older Elastic Stack versions will display unrendered Markdown in this guide.\n\n#### Possible investigation steps\n\n- Investigate the logon failure reason code and the targeted user names.\n  - Prioritize the investigation if the account is critical or has administrative privileges over the domain.\n- Investigate the source IP address of the failed Network Logon attempts.\n  - Identify whether these attempts are coming from the internet or are internal.\n- Investigate other alerts associated with the involved users and source host during the past 48 hours.\n- Identify the source and the target computer and their roles in the IT environment.\n- Check whether the involved credentials are used in automation or scheduled tasks.\n- If this activity is suspicious, contact the account owner and confirm whether they are aware of it.\n- Examine the source host for derived artifacts that indicate compromise:\n  - Observe and collect information about the following activities in the alert source host:\n    - Attempts to contact external domains and addresses.\n      - Examine the DNS cache for suspicious or anomalous entries.\n        - !{osquery{\"label\":\"Osquery - Retrieve DNS Cache\",\"query\":\"SELECT * FROM dns_cache\"}}\n    - Examine the host services for suspicious or anomalous entries.\n      - !{osquery{\"label\":\"Osquery - Retrieve All Services\",\"query\":\"SELECT description, display_name, name, path, pid, service_type, start_type, status, user_account FROM services\"}}\n      - !{osquery{\"label\":\"Osquery - Retrieve Services Running on User Accounts\",\"query\":\"SELECT description, display_name, name, path, pid, service_type, start_type, status, user_account FROM services WHERE\\nNOT (user_account LIKE '%LocalSystem' OR user_account LIKE '%LocalService' OR user_account LIKE '%NetworkService' OR\\nuser_account == null)\\n\"}}\n      - !{osquery{\"label\":\"Osquery - Retrieve Service Unsigned Executables with Virustotal Link\",\"query\":\"SELECT concat('https://www.virustotal.com/gui/file/', sha1) AS VtLink, name, description, start_type, status, pid,\\nservices.path FROM services JOIN authenticode ON services.path = authenticode.path OR services.module_path =\\nauthenticode.path JOIN hash ON services.path = hash.path WHERE authenticode.result != 'trusted'\\n\"}}\n- Investigate potentially compromised accounts. Analysts can do this by searching for login events (for example, 4624) to the host which is the source of this activity\n\n### False positive analysis\n\n- Understand the context of the authentications by contacting the asset owners. This activity can be related to a new or existing automation or business process that is in a failing state.\n- Authentication misconfiguration or obsolete credentials.\n- Service account password expired.\n- Domain trust relationship issues.\n- Infrastructure or availability issues.\n\n### Related rules\n\n- Multiple Logon Failure Followed by Logon Success - 4e85dc8a-3e41-40d8-bc28-91af7ac6cf60\n\n### Response and remediation\n\n- Initiate the incident response process based on the outcome of the triage.\n- Isolate the source host to prevent further post-compromise behavior.\n- If the asset is exposed to the internet with RDP or other remote services available, take the necessary measures to restrict access to the asset. If not possible, limit the access via the firewall to only the needed IP addresses. Also, ensure the system uses robust authentication mechanisms and is patched regularly.\n- Investigate credential exposure on systems compromised or used by the attacker to ensure all compromised accounts are identified. Reset passwords for these accounts and other potentially compromised credentials, such as email, business systems, and web services.\n- Run a full antimalware scan. This may reveal additional artifacts left in the system, persistence mechanisms, and malware components.\n- Determine the initial vector abused by the attacker and take action to prevent reinfection through the same vector.\n- Using the incident response data, update logging and audit policies to improve the mean time to detect (MTTD) and the mean time to respond (MTTR).\n",
      "license": "Elastic License v2",
      "author": [
        "Elastic"
      ],
      "false_positives": [],
      "from": "now-9m",
      "rule_id": "48b6edfc-079d-4907-b43c-baffa243270d",
      "max_signals": 100,
      "risk_score_mapping": [],
      "severity_mapping": [],
      "threat": [
        {
          "framework": "MITRE ATT&CK",
          "tactic": {
            "id": "TA0006",
            "name": "Credential Access",
            "reference": "https://attack.mitre.org/tactics/TA0006/"
          },
          "technique": [
            {
              "id": "T1110",
              "name": "Brute Force",
              "reference": "https://attack.mitre.org/techniques/T1110/",
              "subtechnique": [
                {
                  "id": "T1110.001",
                  "name": "Password Guessing",
                  "reference": "https://attack.mitre.org/techniques/T1110/001/"
                },
                {
                  "id": "T1110.003",
                  "name": "Password Spraying",
                  "reference": "https://attack.mitre.org/techniques/T1110/003/"
                }
              ]
            }
          ]
        }
      ],
      "to": "now",
      "references": [
        "https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4625",
        "https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=4624",
        "https://social.technet.microsoft.com/Forums/ie/en-US/c82ac4f3-a235-472c-9fd3-53aa646cfcfd/network-information-missing-in-event-id-4624?forum=winserversecurity",
        "https://serverfault.com/questions/379092/remote-desktop-failed-logon-event-4625-not-logging-ip-address-on-2008-terminal-s/403638#403638"
      ],
      "version": 114,
      "exceptions_list": [],
      "immutable": true,
      "rule_source": {
        "type": "external",
        "is_customized": false
      },
      "related_integrations": [
        {
          "package": "system",
          "version": "^1.64.0"
        },
        {
          "package": "windows",
          "version": "^2.5.0"
        }
      ],
      "required_fields": [
        {
          "name": "event.action",
          "type": "keyword",
          "ecs": true
        },
        {
          "name": "source.ip",
          "type": "ip",
          "ecs": true
        },
        {
          "name": "user.domain",
          "type": "keyword",
          "ecs": true
        },
        {
          "name": "user.name",
          "type": "keyword",
          "ecs": true
        },
        {
          "name": "winlog.computer_name",
          "type": "keyword",
          "ecs": false
        },
        {
          "name": "winlog.event_data.Status",
          "type": "keyword",
          "ecs": false
        },
        {
          "name": "winlog.logon.type",
          "type": "unknown",
          "ecs": false
        }
      ],
      "setup": "## Setup\n\n- In some cases the source network address in Windows events 4625/4624 is not populated due to Microsoft logging limitations (examples in the references links). This edge case will break the rule condition and it won't trigger an alert.\n",
      "type": "eql",
      "language": "eql",
      "index": [
        "logs-system.security*",
        "logs-windows.forwarded*",
        "winlogbeat-*"
      ],
      "query": "sequence by winlog.computer_name, source.ip with maxspan=10s\n  [authentication where event.action == \"logon-failed\" and\n    /* event 4625 need to be logged */\n    winlog.logon.type : \"Network\" and\n    source.ip != null and source.ip != \"127.0.0.1\" and source.ip != \"::1\" and\n    not user.name : (\"ANONYMOUS LOGON\", \"-\", \"*$\") and not user.domain == \"NT AUTHORITY\" and\n\n    /*\n    noisy failure status codes often associated to authentication misconfiguration :\n     0xC000015B - The user has not been granted the requested logon type (also called the logon right) at this machine.\n     0XC000005E\t- There are currently no logon servers available to service the logon request.\n     0XC0000133\t- Clocks between DC and other computer too far out of sync.\n     0XC0000192\tAn attempt was made to logon, but the Netlogon service was not started.\n    */\n    not winlog.event_data.Status : (\"0xC000015B\", \"0XC000005E\", \"0XC0000133\", \"0XC0000192\")] with runs=10\n"
    },
    "kibana.alert.rule.category": "Event Correlation Rule",
    "kibana.alert.rule.consumer": "siem",
    "kibana.alert.rule.execution.uuid": "3646a55a-b15c-4d84-8522-1d3381a7a9f7",
    "kibana.alert.rule.name": "Multiple Logon Failure from the same Source Address",
    "kibana.alert.rule.producer": "siem",
    "kibana.alert.rule.revision": 0,
    "kibana.alert.rule.rule_type_id": "siem.eqlRule",
    "kibana.alert.rule.uuid": "0945c418-c530-45ea-b998-02350c260c5b",
    "kibana.space_ids": [
      "default"
    ],
    "kibana.alert.rule.tags": [
      "Domain: Endpoint",
      "OS: Windows",
      "Use Case: Threat Detection",
      "Tactic: Credential Access",
      "Resources: Investigation Guide",
      "Data Source: Windows Security Event Logs"
    ],
    "@timestamp": "2025-06-02T07:08:52.979Z",
    "agent": {
      "name": "DESKTOP-NIU0UCP",
      "id": "b35b5962-0c75-4cc5-9f51-8304680f6e92",
      "type": "filebeat",
      "ephemeral_id": "f3d80e5d-dda2-4756-b71f-60bf9ff19fca",
      "version": "9.0.1"
    },
    "process": {
      "pid": 0
    },
    "winlog": {
      "computer_name": "DESKTOP-NIU0UCP",
      "process": {
        "pid": 652
      },
      "keywords": [
        "Audit Failure"
      ],
      "logon": {
        "failure": {
          "reason": "Unknown user name or bad password.",
          "sub_status": "User logon with misspelled or bad user account",
          "status": "This is either due to a bad username or authentication information"
        },
        "id": "0x0",
        "type": "Network"
      },
      "channel": "Security",
      "event_data": {
        "Status": "0xc000006d",
        "LogonType": "3",
        "SubjectLogonId": "0x0",
        "KeyLength": "0",
        "FailureReason": "Unknown user name or bad password.",
        "TargetUserName": "denny",
        "SubStatus": "0xc0000064",
        "TargetDomainName": ".",
        "LogonProcessName": "NtLmSsp ",
        "SubjectUserSid": "S-1-0-0",
        "AuthenticationPackageName": "NTLM",
        "TargetUserSid": "S-1-0-0"
      },
      "opcode": "Info",
      "event_id": "4625",
      "task": "Logon",
      "provider_guid": "{54849625-5478-4994-A5BA-3E3B0328C30D}",
      "activity_id": "{20257C1D-D386-0000-247D-252086D3DB01}",
      "provider_name": "Microsoft-Windows-Security-Auditing"
    },
    "log": {
      "level": "information"
    },
    "elastic_agent": {
      "id": "b35b5962-0c75-4cc5-9f51-8304680f6e92",
      "version": "9.0.1",
      "snapshot": false
    },
    "source": {
      "ip": "192.168.4.101",
      "domain": "WORKSTATION"
    },
    "input": {
      "type": "winlog"
    },
    "ecs": {
      "version": "8.11.0"
    },
    "related": {
      "ip": [
        "192.168.4.101"
      ],
      "user": [
        "denny"
      ]
    },
    "data_stream": {
      "namespace": "default",
      "type": "logs",
      "dataset": "system.security"
    },
    "host": {
      "hostname": "DESKTOP-NIU0UCP",
      "os": {
        "build": "19045.5854",
        "kernel": "10.0.19041.5848 (WinBuild.160101.0800)",
        "name": "Windows 10 Pro",
        "type": "windows",
        "family": "windows",
        "version": "10.0",
        "platform": "windows"
      },
      "ip": [
        "fe80::1afa:fd11:68c3:3ffa",
        "192.168.4.100"
      ],
      "name": "desktop-niu0ucp",
      "id": "1a43f10e-f342-4e14-a82c-84245a382736",
      "mac": [
        "08-00-27-E1-2A-68"
      ],
      "architecture": "x86_64"
    },
    "event": {
      "agent_id_status": "verified",
      "ingested": "2025-06-02T07:05:14Z",
      "code": "4625",
      "provider": "Microsoft-Windows-Security-Auditing",
      "action": "logon-failed",
      "category": [
        "authentication"
      ],
      "type": [
        "start"
      ],
      "dataset": "system.security",
      "outcome": "failure",
      "module": "system"
    },
    "user": {
      "domain": ".",
      "name": "denny",
      "id": "S-1-0-0"
    },
    "kibana.alert.original_event.agent_id_status": "verified",
    "kibana.alert.original_event.ingested": "2025-06-02T07:05:14Z",
    "kibana.alert.original_event.code": "4625",
    "kibana.alert.original_event.provider": "Microsoft-Windows-Security-Auditing",
    "kibana.alert.original_event.kind": "event",
    "kibana.alert.original_event.action": "logon-failed",
    "kibana.alert.original_event.category": [
      "authentication"
    ],
    "kibana.alert.original_event.type": [
      "start"
    ],
    "kibana.alert.original_event.dataset": "system.security",
    "kibana.alert.original_event.outcome": "failure",
    "kibana.alert.original_event.module": "system",
    "event.kind": "signal",
    "kibana.alert.ancestors": [
      {
        "id": "AZcvdRS9iYAeD95vW3WL",
        "type": "event",
        "index": ".ds-logs-system.security-default-2025.05.30-000002",
        "depth": 0
      },
      {
        "id": "5a630b9d49ee43c356b485e947ee4b431513d3a284354b6fcae9cc5e57d0d61f",
        "type": "signal",
        "index": "",
        "depth": 1,
        "rule": "0945c418-c530-45ea-b998-02350c260c5b"
      },
      {
        "id": "AZcvdRS9iYAeD95vW3WM",
        "type": "event",
        "index": ".ds-logs-system.security-default-2025.05.30-000002",
        "depth": 0
      },
      {
        "id": "8af33ff57cb1050c6334494cc334917700d78681743a1083334fcf35bd987b11",
        "type": "signal",
        "index": "",
        "depth": 1,
        "rule": "0945c418-c530-45ea-b998-02350c260c5b"
      },
      {
        "id": "AZcvdRS9iYAeD95vW3WN",
        "type": "event",
        "index": ".ds-logs-system.security-default-2025.05.30-000002",
        "depth": 0
      },
      {
        "id": "4a0832eb41f37735211036abfcba23e412959084fe482a53bd217dec835afe9c",
        "type": "signal",
        "index": "",
        "depth": 1,
        "rule": "0945c418-c530-45ea-b998-02350c260c5b"
      },
      {
        "id": "AZcvdRS9iYAeD95vW3WO",
        "type": "event",
        "index": ".ds-logs-system.security-default-2025.05.30-000002",
        "depth": 0
      },
      {
        "id": "d7d897fd15b95a780c60d503550b279f5c3c634e73c604786df15fcdbab41aef",
        "type": "signal",
        "index": "",
        "depth": 1,
        "rule": "0945c418-c530-45ea-b998-02350c260c5b"
      },
      {
        "id": "AZcvdRS9iYAeD95vW3WP",
        "type": "event",
        "index": ".ds-logs-system.security-default-2025.05.30-000002",
        "depth": 0
      },
      {
        "id": "fe9349f6282ded70b9f2be636db22ed005d55c2c3b894ffcf967d681e24b7186",
        "type": "signal",
        "index": "",
        "depth": 1,
        "rule": "0945c418-c530-45ea-b998-02350c260c5b"
      },
      {
        "id": "AZcvdRS9iYAeD95vW3WQ",
        "type": "event",
        "index": ".ds-logs-system.security-default-2025.05.30-000002",
        "depth": 0
      },
      {
        "id": "c76ff77fbc9e8faae91eb171c68ff7f2c1b175075d9e22d83a0d6fc194297254",
        "type": "signal",
        "index": "",
        "depth": 1,
        "rule": "0945c418-c530-45ea-b998-02350c260c5b"
      },
      {
        "id": "AZcvdRS9iYAeD95vW3WR",
        "type": "event",
        "index": ".ds-logs-system.security-default-2025.05.30-000002",
        "depth": 0
      },
      {
        "id": "a7a1dfe87281a52f01dd46fbfcc99efe81fb38cbfbc491ff8f1d8fc6f810dfc8",
        "type": "signal",
        "index": "",
        "depth": 1,
        "rule": "0945c418-c530-45ea-b998-02350c260c5b"
      },
      {
        "id": "AZcvdRS9iYAeD95vW3WS",
        "type": "event",
        "index": ".ds-logs-system.security-default-2025.05.30-000002",
        "depth": 0
      },
      {
        "id": "f4cea659202a5c5057748bb2a3e8a543d8bc660e606f80eca2b1d36eae2aee8a",
        "type": "signal",
        "index": "",
        "depth": 1,
        "rule": "0945c418-c530-45ea-b998-02350c260c5b"
      },
      {
        "id": "AZcvdRS9iYAeD95vW3WT",
        "type": "event",
        "index": ".ds-logs-system.security-default-2025.05.30-000002",
        "depth": 0
      },
      {
        "id": "398b9778f9a79cfdae8365a4db3484053e53ce281889d99377b90dd342fcf22c",
        "type": "signal",
        "index": "",
        "depth": 1,
        "rule": "0945c418-c530-45ea-b998-02350c260c5b"
      },
      {
        "id": "AZcvdRS9iYAeD95vW3WU",
        "type": "event",
        "index": ".ds-logs-system.security-default-2025.05.30-000002",
        "depth": 0
      },
      {
        "id": "22b271ad8d48aa30470c60d38fffea9007072d8a19d068abd9e71d1dd2b3707c",
        "type": "signal",
        "index": "",
        "depth": 1,
        "rule": "0945c418-c530-45ea-b998-02350c260c5b"
      }
    ],
    "kibana.alert.status": "active",
    "kibana.alert.workflow_status": "open",
    "kibana.alert.depth": 2,
    "kibana.alert.severity": "medium",
    "kibana.alert.risk_score": 47,
    "kibana.alert.rule.actions": [],
    "kibana.alert.rule.author": [
      "Elastic"
    ],
    "kibana.alert.rule.created_at": "2025-05-28T11:34:52.053Z",
    "kibana.alert.rule.created_by": "elastic",
    "kibana.alert.rule.description": "Identifies multiple consecutive logon failures from the same source address and within a short time interval. Adversaries will often brute force login attempts across multiple users with a common or known password, in an attempt to gain access to accounts.",
    "kibana.alert.rule.enabled": true,
    "kibana.alert.rule.exceptions_list": [],
    "kibana.alert.rule.false_positives": [],
    "kibana.alert.rule.from": "now-9m",
    "kibana.alert.rule.immutable": true,
    "kibana.alert.rule.interval": "5m",
    "kibana.alert.rule.indices": [
      "logs-system.security*",
      "logs-windows.forwarded*",
      "winlogbeat-*"
    ],
    "kibana.alert.rule.license": "Elastic License v2",
    "kibana.alert.rule.max_signals": 100,
    "kibana.alert.rule.note": "## Triage and analysis\n\n### Investigating Multiple Logon Failure from the same Source Address\n\nAdversaries with no prior knowledge of legitimate credentials within the system or environment may guess passwords to attempt access to accounts. Without knowledge of the password for an account, an adversary may opt to guess the password using a repetitive or iterative mechanism systematically. More details can be found [here](https://attack.mitre.org/techniques/T1110/001/).\n\nThis rule identifies potential password guessing/brute force activity from a single address.\n\n> **Note**:\n> This investigation guide uses the [Osquery Markdown Plugin](https://www.elastic.co/guide/en/security/current/invest-guide-run-osquery.html) introduced in Elastic Stack version 8.5.0. Older Elastic Stack versions will display unrendered Markdown in this guide.\n\n#### Possible investigation steps\n\n- Investigate the logon failure reason code and the targeted user names.\n  - Prioritize the investigation if the account is critical or has administrative privileges over the domain.\n- Investigate the source IP address of the failed Network Logon attempts.\n  - Identify whether these attempts are coming from the internet or are internal.\n- Investigate other alerts associated with the involved users and source host during the past 48 hours.\n- Identify the source and the target computer and their roles in the IT environment.\n- Check whether the involved credentials are used in automation or scheduled tasks.\n- If this activity is suspicious, contact the account owner and confirm whether they are aware of it.\n- Examine the source host for derived artifacts that indicate compromise:\n  - Observe and collect information about the following activities in the alert source host:\n    - Attempts to contact external domains and addresses.\n      - Examine the DNS cache for suspicious or anomalous entries.\n        - !{osquery{\"label\":\"Osquery - Retrieve DNS Cache\",\"query\":\"SELECT * FROM dns_cache\"}}\n    - Examine the host services for suspicious or anomalous entries.\n      - !{osquery{\"label\":\"Osquery - Retrieve All Services\",\"query\":\"SELECT description, display_name, name, path, pid, service_type, start_type, status, user_account FROM services\"}}\n      - !{osquery{\"label\":\"Osquery - Retrieve Services Running on User Accounts\",\"query\":\"SELECT description, display_name, name, path, pid, service_type, start_type, status, user_account FROM services WHERE\\nNOT (user_account LIKE '%LocalSystem' OR user_account LIKE '%LocalService' OR user_account LIKE '%NetworkService' OR\\nuser_account == null)\\n\"}}\n      - !{osquery{\"label\":\"Osquery - Retrieve Service Unsigned Executables with Virustotal Link\",\"query\":\"SELECT concat('https://www.virustotal.com/gui/file/', sha1) AS VtLink, name, description, start_type, status, pid,\\nservices.path FROM services JOIN authenticode ON services.path = authenticode.path OR services.module_path =\\nauthenticode.path JOIN hash ON services.path = hash.path WHERE authenticode.result != 'trusted'\\n\"}}\n- Investigate potentially compromised accounts. Analysts can do this by searching for login events (for example, 4624) to the host which is the source of this activity\n\n### False positive analysis\n\n- Understand the context of the authentications by contacting the asset owners. This activity can be related to a new or existing automation or business process that is in a failing state.\n- Authentication misconfiguration or obsolete credentials.\n- Service account password expired.\n- Domain trust relationship issues.\n- Infrastructure or availability issues.\n\n### Related rules\n\n- Multiple Logon Failure Followed by Logon Success - 4e85dc8a-3e41-40d8-bc28-91af7ac6cf60\n\n### Response and remediation\n\n- Initiate the incident response process based on the outcome of the triage.\n- Isolate the source host to prevent further post-compromise behavior.\n- If the asset is exposed to the internet with RDP or other remote services available, take the necessary measures to restrict access to the asset. If not possible, limit the access via the firewall to only the needed IP addresses. Also, ensure the system uses robust authentication mechanisms and is patched regularly.\n- Investigate credential exposure on systems compromised or used by the attacker to ensure all compromised accounts are identified. Reset passwords for these accounts and other potentially compromised credentials, such as email, business systems, and web services.\n- Run a full antimalware scan. This may reveal additional artifacts left in the system, persistence mechanisms, and malware components.\n- Determine the initial vector abused by the attacker and take action to prevent reinfection through the same vector.\n- Using the incident response data, update logging and audit policies to improve the mean time to detect (MTTD) and the mean time to respond (MTTR).\n",
    "kibana.alert.rule.references": [
      "https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4625",
      "https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=4624",
      "https://social.technet.microsoft.com/Forums/ie/en-US/c82ac4f3-a235-472c-9fd3-53aa646cfcfd/network-information-missing-in-event-id-4624?forum=winserversecurity",
      "https://serverfault.com/questions/379092/remote-desktop-failed-logon-event-4625-not-logging-ip-address-on-2008-terminal-s/403638#403638"
    ],
    "kibana.alert.rule.risk_score_mapping": [],
    "kibana.alert.rule.rule_id": "48b6edfc-079d-4907-b43c-baffa243270d",
    "kibana.alert.rule.severity_mapping": [],
    "kibana.alert.rule.threat": [
      {
        "framework": "MITRE ATT&CK",
        "tactic": {
          "id": "TA0006",
          "name": "Credential Access",
          "reference": "https://attack.mitre.org/tactics/TA0006/"
        },
        "technique": [
          {
            "id": "T1110",
            "name": "Brute Force",
            "reference": "https://attack.mitre.org/techniques/T1110/",
            "subtechnique": [
              {
                "id": "T1110.001",
                "name": "Password Guessing",
                "reference": "https://attack.mitre.org/techniques/T1110/001/"
              },
              {
                "id": "T1110.003",
                "name": "Password Spraying",
                "reference": "https://attack.mitre.org/techniques/T1110/003/"
              }
            ]
          }
        ]
      }
    ],
    "kibana.alert.rule.to": "now",
    "kibana.alert.rule.type": "eql",
    "kibana.alert.rule.updated_at": "2025-05-28T11:40:33.891Z",
    "kibana.alert.rule.updated_by": "elastic",
    "kibana.alert.rule.version": 114,
    "kibana.alert.workflow_tags": [],
    "kibana.alert.workflow_assignee_ids": [],
    "kibana.alert.rule.risk_score": 47,
    "kibana.alert.rule.severity": "medium",
    "kibana.alert.rule.execution.type": "scheduled",
    "kibana.alert.original_time": "2025-06-02T07:08:52.956Z",
    "kibana.alert.reason": "authentication event with source 192.168.4.101 by denny on desktop-niu0ucp created medium alert Multiple Logon Failure from the same Source Address.",
    "kibana.alert.uuid": "10da92e0b4351ac7b6a3460814f87d13204b7dad67818290dadffdbfff7482b1",
    "kibana.alert.intended_timestamp": "2025-06-02T07:08:52.979Z",
    "kibana.alert.group.id": "10da92e0b4351ac7b6a3460814f87d13204b7dad67818290dadffdbfff7482b1"
  },
  "fields": {
    "winlog.event_data.AuthenticationPackageName": [
      "NTLM"
    ],
    "kibana.alert.rule.references": [
      "https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4625",
      "https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=4624",
      "https://social.technet.microsoft.com/Forums/ie/en-US/c82ac4f3-a235-472c-9fd3-53aa646cfcfd/network-information-missing-in-event-id-4624?forum=winserversecurity",
      "https://serverfault.com/questions/379092/remote-desktop-failed-logon-event-4625-not-logging-ip-address-on-2008-terminal-s/403638#403638"
    ],
    "kibana.alert.rule.updated_by": [
      "elastic"
    ],
    "elastic_agent.version": [
      "9.0.1"
    ],
    "host.os.name.text": [
      "Windows 10 Pro"
    ],
    "host.hostname": [
      "DESKTOP-NIU0UCP"
    ],
    "host.mac": [
      "08-00-27-E1-2A-68"
    ],
    "signal.rule.threat.technique.subtechnique.id": [
      "T1110.001",
      "T1110.003"
    ],
    "winlog.process.pid": [
      652
    ],
    "kibana.alert.rule.threat.technique.id": [
      "T1110"
    ],
    "signal.rule.enabled": [
      "true"
    ],
    "host.os.version": [
      "10.0"
    ],
    "signal.rule.max_signals": [
      100
    ],
    "kibana.alert.risk_score": [
      47
    ],
    "signal.rule.updated_at": [
      "2025-05-28T11:40:33.891Z"
    ],
    "winlog.logon.id": [
      "0x0"
    ],
    "kibana.alert.rule.threat.technique.subtechnique.reference": [
      "https://attack.mitre.org/techniques/T1110/001/",
      "https://attack.mitre.org/techniques/T1110/003/"
    ],
    "winlog.logon.failure.reason": [
      "Unknown user name or bad password."
    ],
    "winlog.logon.failure.sub_status": [
      "User logon with misspelled or bad user account"
    ],
    "host.os.type": [
      "windows"
    ],
    "signal.original_event.code": [
      "4625"
    ],
    "winlog.event_data.TargetUserSid": [
      "S-1-0-0"
    ],
    "kibana.alert.original_event.module": [
      "system"
    ],
    "signal.rule.references": [
      "https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4625",
      "https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=4624",
      "https://social.technet.microsoft.com/Forums/ie/en-US/c82ac4f3-a235-472c-9fd3-53aa646cfcfd/network-information-missing-in-event-id-4624?forum=winserversecurity",
      "https://serverfault.com/questions/379092/remote-desktop-failed-logon-event-4625-not-logging-ip-address-on-2008-terminal-s/403638#403638"
    ],
    "kibana.alert.rule.interval": [
      "5m"
    ],
    "kibana.alert.rule.type": [
      "eql"
    ],
    "event.provider": [
      "Microsoft-Windows-Security-Auditing"
    ],
    "kibana.alert.rule.immutable": [
      "true"
    ],
    "kibana.alert.rule.version": [
      "114"
    ],
    "signal.original_event.outcome": [
      "failure"
    ],
    "host.ip": [
      "fe80::1afa:fd11:68c3:3ffa",
      "192.168.4.100"
    ],
    "agent.type": [
      "filebeat"
    ],
    "signal.original_event.category": [
      "authentication"
    ],
    "winlog.event_data.SubjectLogonId": [
      "0x0"
    ],
    "related.ip": [
      "192.168.4.101"
    ],
    "signal.rule.threat.framework": [
      "MITRE ATT&CK"
    ],
    "host.id": [
      "1a43f10e-f342-4e14-a82c-84245a382736"
    ],
    "elastic_agent.id": [
      "b35b5962-0c75-4cc5-9f51-8304680f6e92"
    ],
    "winlog.event_data.LogonProcessName": [
      "NtLmSsp "
    ],
    "kibana.alert.rule.indices": [
      "logs-system.security*",
      "logs-windows.forwarded*",
      "winlogbeat-*"
    ],
    "signal.rule.threat.technique.subtechnique.reference": [
      "https://attack.mitre.org/techniques/T1110/001/",
      "https://attack.mitre.org/techniques/T1110/003/"
    ],
    "signal.rule.updated_by": [
      "elastic"
    ],
    "winlog.channel": [
      "Security"
    ],
    "winlog.event_data.LogonType": [
      "3"
    ],
    "host.os.platform": [
      "windows"
    ],
    "kibana.alert.intended_timestamp": [
      "2025-06-02T07:08:52.979Z"
    ],
    "kibana.alert.rule.severity": [
      "medium"
    ],
    "winlog.event_data.TargetDomainName": [
      "."
    ],
    "winlog.opcode": [
      "Info"
    ],
    "kibana.alert.rule.execution.timestamp": [
      "2025-06-02T07:08:53.125Z"
    ],
    "signal.rule.threat.technique.reference": [
      "https://attack.mitre.org/techniques/T1110/"
    ],
    "kibana.version": [
      "9.0.1"
    ],
    "signal.ancestors.type": [
      "event",
      "signal",
      "event",
      "signal",
      "event",
      "signal",
      "event",
      "signal",
      "event",
      "signal",
      "event",
      "signal",
      "event",
      "signal",
      "event",
      "signal",
      "event",
      "signal",
      "event",
      "signal"
    ],
    "user.name.text": [
      "denny"
    ],
    "kibana.alert.ancestors.id": [
      "AZcvdRS9iYAeD95vW3WL",
      "5a630b9d49ee43c356b485e947ee4b431513d3a284354b6fcae9cc5e57d0d61f",
      "AZcvdRS9iYAeD95vW3WM",
      "8af33ff57cb1050c6334494cc334917700d78681743a1083334fcf35bd987b11",
      "AZcvdRS9iYAeD95vW3WN",
      "4a0832eb41f37735211036abfcba23e412959084fe482a53bd217dec835afe9c",
      "AZcvdRS9iYAeD95vW3WO",
      "d7d897fd15b95a780c60d503550b279f5c3c634e73c604786df15fcdbab41aef",
      "AZcvdRS9iYAeD95vW3WP",
      "fe9349f6282ded70b9f2be636db22ed005d55c2c3b894ffcf967d681e24b7186",
      "AZcvdRS9iYAeD95vW3WQ",
      "c76ff77fbc9e8faae91eb171c68ff7f2c1b175075d9e22d83a0d6fc194297254",
      "AZcvdRS9iYAeD95vW3WR",
      "a7a1dfe87281a52f01dd46fbfcc99efe81fb38cbfbc491ff8f1d8fc6f810dfc8",
      "AZcvdRS9iYAeD95vW3WS",
      "f4cea659202a5c5057748bb2a3e8a543d8bc660e606f80eca2b1d36eae2aee8a",
      "AZcvdRS9iYAeD95vW3WT",
      "398b9778f9a79cfdae8365a4db3484053e53ce281889d99377b90dd342fcf22c",
      "AZcvdRS9iYAeD95vW3WU",
      "22b271ad8d48aa30470c60d38fffea9007072d8a19d068abd9e71d1dd2b3707c"
    ],
    "kibana.alert.original_event.code": [
      "4625"
    ],
    "kibana.alert.rule.description": [
      "Identifies multiple consecutive logon failures from the same source address and within a short time interval. Adversaries will often brute force login attempts across multiple users with a common or known password, in an attempt to gain access to accounts."
    ],
    "winlog.computer_name": [
      "DESKTOP-NIU0UCP"
    ],
    "kibana.alert.rule.producer": [
      "siem"
    ],
    "kibana.alert.rule.to": [
      "now"
    ],
    "kibana.alert.original_event.ingested": [
      "2025-06-02T07:05:14.000Z"
    ],
    "signal.rule.id": [
      "0945c418-c530-45ea-b998-02350c260c5b"
    ],
    "winlog.keywords": [
      "Audit Failure"
    ],
    "signal.reason": [
      "authentication event with source 192.168.4.101 by denny on desktop-niu0ucp created medium alert Multiple Logon Failure from the same Source Address."
    ],
    "signal.rule.risk_score": [
      47
    ],
    "host.os.name": [
      "Windows 10 Pro"
    ],
    "log.level": [
      "information"
    ],
    "signal.status": [
      "open"
    ],
    "winlog.activity_id": [
      "{20257C1D-D386-0000-247D-252086D3DB01}"
    ],
    "signal.rule.tags": [
      "Domain: Endpoint",
      "OS: Windows",
      "Use Case: Threat Detection",
      "Tactic: Credential Access",
      "Resources: Investigation Guide",
      "Data Source: Windows Security Event Logs"
    ],
    "winlog.event_data.TargetUserName": [
      "denny"
    ],
    "kibana.alert.rule.threat.tactic.name": [
      "Credential Access"
    ],
    "kibana.alert.rule.uuid": [
      "0945c418-c530-45ea-b998-02350c260c5b"
    ],
    "kibana.alert.original_event.category": [
      "authentication"
    ],
    "signal.original_event.provider": [
      "Microsoft-Windows-Security-Auditing"
    ],
    "winlog.event_data.FailureReason": [
      "Unknown user name or bad password."
    ],
    "kibana.alert.ancestors.index": [
      ".ds-logs-system.security-default-2025.05.30-000002",
      "",
      ".ds-logs-system.security-default-2025.05.30-000002",
      "",
      ".ds-logs-system.security-default-2025.05.30-000002",
      "",
      ".ds-logs-system.security-default-2025.05.30-000002",
      "",
      ".ds-logs-system.security-default-2025.05.30-000002",
      "",
      ".ds-logs-system.security-default-2025.05.30-000002",
      "",
      ".ds-logs-system.security-default-2025.05.30-000002",
      "",
      ".ds-logs-system.security-default-2025.05.30-000002",
      "",
      ".ds-logs-system.security-default-2025.05.30-000002",
      "",
      ".ds-logs-system.security-default-2025.05.30-000002",
      ""
    ],
    "agent.version": [
      "9.0.1"
    ],
    "host.os.family": [
      "windows"
    ],
    "kibana.alert.rule.from": [
      "now-9m"
    ],
    "kibana.alert.rule.parameters": [
      {
        "severity": "medium",
        "max_signals": 100,
        "rule_source": {
          "type": "external",
          "is_customized": false
        },
        "references": [
          "https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4625",
          "https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=4624",
          "https://social.technet.microsoft.com/Forums/ie/en-US/c82ac4f3-a235-472c-9fd3-53aa646cfcfd/network-information-missing-in-event-id-4624?forum=winserversecurity",
          "https://serverfault.com/questions/379092/remote-desktop-failed-logon-event-4625-not-logging-ip-address-on-2008-terminal-s/403638#403638"
        ],
        "risk_score": 47,
        "author": "Elastic",
        "query": "sequence by winlog.computer_name, source.ip with maxspan=10s\n  [authentication where event.action == \"logon-failed\" and\n    /* event 4625 need to be logged */\n    winlog.logon.type : \"Network\" and\n    source.ip != null and source.ip != \"127.0.0.1\" and source.ip != \"::1\" and\n    not user.name : (\"ANONYMOUS LOGON\", \"-\", \"*$\") and not user.domain == \"NT AUTHORITY\" and\n\n    /*\n    noisy failure status codes often associated to authentication misconfiguration :\n     0xC000015B - The user has not been granted the requested logon type (also called the logon right) at this machine.\n     0XC000005E\t- There are currently no logon servers available to service the logon request.\n     0XC0000133\t- Clocks between DC and other computer too far out of sync.\n     0XC0000192\tAn attempt was made to logon, but the Netlogon service was not started.\n    */\n    not winlog.event_data.Status : (\"0xC000015B\", \"0XC000005E\", \"0XC0000133\", \"0XC0000192\")] with runs=10\n",
        "description": "Identifies multiple consecutive logon failures from the same source address and within a short time interval. Adversaries will often brute force login attempts across multiple users with a common or known password, in an attempt to gain access to accounts.",
        "index": [
          "logs-system.security*",
          "logs-windows.forwarded*",
          "winlogbeat-*"
        ],
        "language": "eql",
        "type": "eql",
        "version": 114,
        "rule_id": "48b6edfc-079d-4907-b43c-baffa243270d",
        "license": "Elastic License v2",
        "required_fields": [
          {
            "name": "event.action",
            "type": "keyword",
            "ecs": true
          },
          {
            "name": "source.ip",
            "type": "ip",
            "ecs": true
          },
          {
            "name": "user.domain",
            "type": "keyword",
            "ecs": true
          },
          {
            "name": "user.name",
            "type": "keyword",
            "ecs": true
          },
          {
            "name": "winlog.computer_name",
            "type": "keyword",
            "ecs": false
          },
          {
            "name": "winlog.event_data.Status",
            "type": "keyword",
            "ecs": false
          },
          {
            "name": "winlog.logon.type",
            "type": "unknown",
            "ecs": false
          }
        ],
        "immutable": true,
        "related_integrations": [
          {
            "package": "system",
            "version": "^1.64.0"
          },
          {
            "package": "windows",
            "version": "^2.5.0"
          }
        ],
        "setup": "## Setup\n\n- In some cases the source network address in Windows events 4625/4624 is not populated due to Microsoft logging limitations (examples in the references links). This edge case will break the rule condition and it won't trigger an alert.\n",
        "from": "now-9m",
        "threat": {
          "framework": "MITRE ATT&CK",
          "tactic": {
            "id": "TA0006",
            "name": "Credential Access",
            "reference": "https://attack.mitre.org/tactics/TA0006/"
          },
          "technique": [
            {
              "id": "T1110",
              "name": "Brute Force",
              "reference": "https://attack.mitre.org/techniques/T1110/",
              "subtechnique": [
                {
                  "id": "T1110.001",
                  "name": "Password Guessing",
                  "reference": "https://attack.mitre.org/techniques/T1110/001/"
                },
                {
                  "id": "T1110.003",
                  "name": "Password Spraying",
                  "reference": "https://attack.mitre.org/techniques/T1110/003/"
                }
              ]
            }
          ]
        },
        "to": "now"
      }
    ],
    "kibana.alert.rule.threat.tactic.id": [
      "TA0006"
    ],
    "signal.original_event.kind": [
      "event"
    ],
    "kibana.alert.rule.threat.technique.name": [
      "Brute Force"
    ],
    "signal.depth": [
      2
    ],
    "signal.rule.immutable": [
      "true"
    ],
    "host.os.build": [
      "19045.5854"
    ],
    "signal.rule.name": [
      "Multiple Logon Failure from the same Source Address"
    ],
    "event.module": [
      "system"
    ],
    "host.os.kernel": [
      "10.0.19041.5848 (WinBuild.160101.0800)"
    ],
    "kibana.alert.rule.license": [
      "Elastic License v2"
    ],
    "kibana.alert.rule.threat.technique.subtechnique.id": [
      "T1110.001",
      "T1110.003"
    ],
    "kibana.alert.original_event.kind": [
      "event"
    ],
    "winlog.task": [
      "Logon"
    ],
    "signal.rule.description": [
      "Identifies multiple consecutive logon failures from the same source address and within a short time interval. Adversaries will often brute force login attempts across multiple users with a common or known password, in an attempt to gain access to accounts."
    ],
    "kibana.alert.original_event.outcome": [
      "failure"
    ],
    "kibana.space_ids": [
      "default"
    ],
    "kibana.alert.severity": [
      "medium"
    ],
    "signal.ancestors.depth": [
      0,
      1,
      0,
      1,
      0,
      1,
      0,
      1,
      0,
      1,
      0,
      1,
      0,
      1,
      0,
      1,
      0,
      1,
      0,
      1
    ],
    "event.category": [
      "authentication"
    ],
    "kibana.alert.rule.tags": [
      "Domain: Endpoint",
      "OS: Windows",
      "Use Case: Threat Detection",
      "Tactic: Credential Access",
      "Resources: Investigation Guide",
      "Data Source: Windows Security Event Logs"
    ],
    "kibana.alert.reason.text": [
      "authentication event with source 192.168.4.101 by denny on desktop-niu0ucp created medium alert Multiple Logon Failure from the same Source Address."
    ],
    "winlog.event_data.KeyLength": [
      "0"
    ],
    "kibana.alert.ancestors.depth": [
      0,
      1,
      0,
      1,
      0,
      1,
      0,
      1,
      0,
      1,
      0,
      1,
      0,
      1,
      0,
      1,
      0,
      1,
      0,
      1
    ],
    "kibana.alert.rule.threat.technique.subtechnique.name": [
      "Password Guessing",
      "Password Spraying"
    ],
    "source.ip": [
      "192.168.4.101"
    ],
    "agent.name": [
      "DESKTOP-NIU0UCP"
    ],
    "event.agent_id_status": [
      "verified"
    ],
    "event.outcome": [
      "failure"
    ],
    "kibana.alert.group.id": [
      "10da92e0b4351ac7b6a3460814f87d13204b7dad67818290dadffdbfff7482b1"
    ],
    "user.id": [
      "S-1-0-0"
    ],
    "input.type": [
      "winlog"
    ],
    "signal.rule.threat.technique.subtechnique.name": [
      "Password Guessing",
      "Password Spraying"
    ],
    "related.user": [
      "denny"
    ],
    "host.architecture": [
      "x86_64"
    ],
    "kibana.alert.start": [
      "2025-06-02T07:08:53.125Z"
    ],
    "event.code": [
      "4625"
    ],
    "kibana.alert.original_event.type": [
      "start"
    ],
    "agent.id": [
      "b35b5962-0c75-4cc5-9f51-8304680f6e92"
    ],
    "signal.original_event.module": [
      "system"
    ],
    "signal.rule.from": [
      "now-9m"
    ],
    "kibana.alert.rule.enabled": [
      "true"
    ],
    "kibana.alert.ancestors.type": [
      "event",
      "signal",
      "event",
      "signal",
      "event",
      "signal",
      "event",
      "signal",
      "event",
      "signal",
      "event",
      "signal",
      "event",
      "signal",
      "event",
      "signal",
      "event",
      "signal",
      "event",
      "signal"
    ],
    "winlog.event_data.SubjectUserSid": [
      "S-1-0-0"
    ],
    "signal.ancestors.index": [
      ".ds-logs-system.security-default-2025.05.30-000002",
      "",
      ".ds-logs-system.security-default-2025.05.30-000002",
      "",
      ".ds-logs-system.security-default-2025.05.30-000002",
      "",
      ".ds-logs-system.security-default-2025.05.30-000002",
      "",
      ".ds-logs-system.security-default-2025.05.30-000002",
      "",
      ".ds-logs-system.security-default-2025.05.30-000002",
      "",
      ".ds-logs-system.security-default-2025.05.30-000002",
      "",
      ".ds-logs-system.security-default-2025.05.30-000002",
      "",
      ".ds-logs-system.security-default-2025.05.30-000002",
      "",
      ".ds-logs-system.security-default-2025.05.30-000002",
      ""
    ],
    "user.name": [
      "denny"
    ],
    "source.domain": [
      "WORKSTATION"
    ],
    "winlog.logon.failure.status": [
      "This is either due to a bad username or authentication information"
    ],
    "winlog.event_data.Status": [
      "0xc000006d"
    ],
    "elastic_agent.snapshot": [
      false
    ],
    "user.domain": [
      "."
    ],
    "signal.original_event.type": [
      "start"
    ],
    "kibana.alert.rule.note": [
      "## Triage and analysis\n\n### Investigating Multiple Logon Failure from the same Source Address\n\nAdversaries with no prior knowledge of legitimate credentials within the system or environment may guess passwords to attempt access to accounts. Without knowledge of the password for an account, an adversary may opt to guess the password using a repetitive or iterative mechanism systematically. More details can be found [here](https://attack.mitre.org/techniques/T1110/001/).\n\nThis rule identifies potential password guessing/brute force activity from a single address.\n\n> **Note**:\n> This investigation guide uses the [Osquery Markdown Plugin](https://www.elastic.co/guide/en/security/current/invest-guide-run-osquery.html) introduced in Elastic Stack version 8.5.0. Older Elastic Stack versions will display unrendered Markdown in this guide.\n\n#### Possible investigation steps\n\n- Investigate the logon failure reason code and the targeted user names.\n  - Prioritize the investigation if the account is critical or has administrative privileges over the domain.\n- Investigate the source IP address of the failed Network Logon attempts.\n  - Identify whether these attempts are coming from the internet or are internal.\n- Investigate other alerts associated with the involved users and source host during the past 48 hours.\n- Identify the source and the target computer and their roles in the IT environment.\n- Check whether the involved credentials are used in automation or scheduled tasks.\n- If this activity is suspicious, contact the account owner and confirm whether they are aware of it.\n- Examine the source host for derived artifacts that indicate compromise:\n  - Observe and collect information about the following activities in the alert source host:\n    - Attempts to contact external domains and addresses.\n      - Examine the DNS cache for suspicious or anomalous entries.\n        - !{osquery{\"label\":\"Osquery - Retrieve DNS Cache\",\"query\":\"SELECT * FROM dns_cache\"}}\n    - Examine the host services for suspicious or anomalous entries.\n      - !{osquery{\"label\":\"Osquery - Retrieve All Services\",\"query\":\"SELECT description, display_name, name, path, pid, service_type, start_type, status, user_account FROM services\"}}\n      - !{osquery{\"label\":\"Osquery - Retrieve Services Running on User Accounts\",\"query\":\"SELECT description, display_name, name, path, pid, service_type, start_type, status, user_account FROM services WHERE\\nNOT (user_account LIKE '%LocalSystem' OR user_account LIKE '%LocalService' OR user_account LIKE '%NetworkService' OR\\nuser_account == null)\\n\"}}\n      - !{osquery{\"label\":\"Osquery - Retrieve Service Unsigned Executables with Virustotal Link\",\"query\":\"SELECT concat('https://www.virustotal.com/gui/file/', sha1) AS VtLink, name, description, start_type, status, pid,\\nservices.path FROM services JOIN authenticode ON services.path = authenticode.path OR services.module_path =\\nauthenticode.path JOIN hash ON services.path = hash.path WHERE authenticode.result != 'trusted'\\n\"}}\n- Investigate potentially compromised accounts. Analysts can do this by searching for login events (for example, 4624) to the host which is the source of this activity\n\n### False positive analysis\n\n- Understand the context of the authentications by contacting the asset owners. This activity can be related to a new or existing automation or business process that is in a failing state.\n- Authentication misconfiguration or obsolete credentials.\n- Service account password expired.\n- Domain trust relationship issues.\n- Infrastructure or availability issues.\n\n### Related rules\n\n- Multiple Logon Failure Followed by Logon Success - 4e85dc8a-3e41-40d8-bc28-91af7ac6cf60\n\n### Response and remediation\n\n- Initiate the incident response process based on the outcome of the triage.\n- Isolate the source host to prevent further post-compromise behavior.\n- If the asset is exposed to the internet with RDP or other remote services available, take the necessary measures to restrict access to the asset. If not possible, limit the access via the firewall to only the needed IP addresses. Also, ensure the system uses robust authentication mechanisms and is patched regularly.\n- Investigate credential exposure on systems compromised or used by the attacker to ensure all compromised accounts are identified. Reset passwords for these accounts and other potentially compromised credentials, such as email, business systems, and web services.\n- Run a full antimalware scan. This may reveal additional artifacts left in the system, persistence mechanisms, and malware components.\n- Determine the initial vector abused by the attacker and take action to prevent reinfection through the same vector.\n- Using the incident response data, update logging and audit policies to improve the mean time to detect (MTTD) and the mean time to respond (MTTR).\n"
    ],
    "kibana.alert.rule.max_signals": [
      100
    ],
    "signal.rule.author": [
      "Elastic"
    ],
    "winlog.logon.type": [
      "Network"
    ],
    "kibana.alert.rule.risk_score": [
      47
    ],
    "signal.original_event.dataset": [
      "system.security"
    ],
    "signal.rule.threat.technique.id": [
      "T1110"
    ],
    "kibana.alert.rule.consumer": [
      "siem"
    ],
    "kibana.alert.rule.category": [
      "Event Correlation Rule"
    ],
    "event.action": [
      "logon-failed"
    ],
    "event.ingested": [
      "2025-06-02T07:05:14.000Z"
    ],
    "@timestamp": [
      "2025-06-02T07:08:52.979Z"
    ],
    "kibana.alert.original_event.action": [
      "logon-failed"
    ],
    "kibana.alert.original_event.agent_id_status": [
      "verified"
    ],
    "data_stream.dataset": [
      "system.security"
    ],
    "agent.ephemeral_id": [
      "f3d80e5d-dda2-4756-b71f-60bf9ff19fca"
    ],
    "kibana.alert.rule.execution.uuid": [
      "3646a55a-b15c-4d84-8522-1d3381a7a9f7"
    ],
    "kibana.alert.uuid": [
      "10da92e0b4351ac7b6a3460814f87d13204b7dad67818290dadffdbfff7482b1"
    ],
    "signal.rule.note": [
      "## Triage and analysis\n\n### Investigating Multiple Logon Failure from the same Source Address\n\nAdversaries with no prior knowledge of legitimate credentials within the system or environment may guess passwords to attempt access to accounts. Without knowledge of the password for an account, an adversary may opt to guess the password using a repetitive or iterative mechanism systematically. More details can be found [here](https://attack.mitre.org/techniques/T1110/001/).\n\nThis rule identifies potential password guessing/brute force activity from a single address.\n\n> **Note**:\n> This investigation guide uses the [Osquery Markdown Plugin](https://www.elastic.co/guide/en/security/current/invest-guide-run-osquery.html) introduced in Elastic Stack version 8.5.0. Older Elastic Stack versions will display unrendered Markdown in this guide.\n\n#### Possible investigation steps\n\n- Investigate the logon failure reason code and the targeted user names.\n  - Prioritize the investigation if the account is critical or has administrative privileges over the domain.\n- Investigate the source IP address of the failed Network Logon attempts.\n  - Identify whether these attempts are coming from the internet or are internal.\n- Investigate other alerts associated with the involved users and source host during the past 48 hours.\n- Identify the source and the target computer and their roles in the IT environment.\n- Check whether the involved credentials are used in automation or scheduled tasks.\n- If this activity is suspicious, contact the account owner and confirm whether they are aware of it.\n- Examine the source host for derived artifacts that indicate compromise:\n  - Observe and collect information about the following activities in the alert source host:\n    - Attempts to contact external domains and addresses.\n      - Examine the DNS cache for suspicious or anomalous entries.\n        - !{osquery{\"label\":\"Osquery - Retrieve DNS Cache\",\"query\":\"SELECT * FROM dns_cache\"}}\n    - Examine the host services for suspicious or anomalous entries.\n      - !{osquery{\"label\":\"Osquery - Retrieve All Services\",\"query\":\"SELECT description, display_name, name, path, pid, service_type, start_type, status, user_account FROM services\"}}\n      - !{osquery{\"label\":\"Osquery - Retrieve Services Running on User Accounts\",\"query\":\"SELECT description, display_name, name, path, pid, service_type, start_type, status, user_account FROM services WHERE\\nNOT (user_account LIKE '%LocalSystem' OR user_account LIKE '%LocalService' OR user_account LIKE '%NetworkService' OR\\nuser_account == null)\\n\"}}\n      - !{osquery{\"label\":\"Osquery - Retrieve Service Unsigned Executables with Virustotal Link\",\"query\":\"SELECT concat('https://www.virustotal.com/gui/file/', sha1) AS VtLink, name, description, start_type, status, pid,\\nservices.path FROM services JOIN authenticode ON services.path = authenticode.path OR services.module_path =\\nauthenticode.path JOIN hash ON services.path = hash.path WHERE authenticode.result != 'trusted'\\n\"}}\n- Investigate potentially compromised accounts. Analysts can do this by searching for login events (for example, 4624) to the host which is the source of this activity\n\n### False positive analysis\n\n- Understand the context of the authentications by contacting the asset owners. This activity can be related to a new or existing automation or business process that is in a failing state.\n- Authentication misconfiguration or obsolete credentials.\n- Service account password expired.\n- Domain trust relationship issues.\n- Infrastructure or availability issues.\n\n### Related rules\n\n- Multiple Logon Failure Followed by Logon Success - 4e85dc8a-3e41-40d8-bc28-91af7ac6cf60\n\n### Response and remediation\n\n- Initiate the incident response process based on the outcome of the triage.\n- Isolate the source host to prevent further post-compromise behavior.\n- If the asset is exposed to the internet with RDP or other remote services available, take the necessary measures to restrict access to the asset. If not possible, limit the access via the firewall to only the needed IP addresses. Also, ensure the system uses robust authentication mechanisms and is patched regularly.\n- Investigate credential exposure on systems compromised or used by the attacker to ensure all compromised accounts are identified. Reset passwords for these accounts and other potentially compromised credentials, such as email, business systems, and web services.\n- Run a full antimalware scan. This may reveal additional artifacts left in the system, persistence mechanisms, and malware components.\n- Determine the initial vector abused by the attacker and take action to prevent reinfection through the same vector.\n- Using the incident response data, update logging and audit policies to improve the mean time to detect (MTTD) and the mean time to respond (MTTR).\n"
    ],
    "signal.rule.threat.technique.name": [
      "Brute Force"
    ],
    "signal.rule.license": [
      "Elastic License v2"
    ],
    "kibana.alert.ancestors.rule": [
      "0945c418-c530-45ea-b998-02350c260c5b",
      "0945c418-c530-45ea-b998-02350c260c5b",
      "0945c418-c530-45ea-b998-02350c260c5b",
      "0945c418-c530-45ea-b998-02350c260c5b",
      "0945c418-c530-45ea-b998-02350c260c5b",
      "0945c418-c530-45ea-b998-02350c260c5b",
      "0945c418-c530-45ea-b998-02350c260c5b",
      "0945c418-c530-45ea-b998-02350c260c5b",
      "0945c418-c530-45ea-b998-02350c260c5b",
      "0945c418-c530-45ea-b998-02350c260c5b"
    ],
    "kibana.alert.rule.rule_id": [
      "48b6edfc-079d-4907-b43c-baffa243270d"
    ],
    "signal.rule.type": [
      "eql"
    ],
    "winlog.provider_guid": [
      "{54849625-5478-4994-A5BA-3E3B0328C30D}"
    ],
    "winlog.provider_name": [
      "Microsoft-Windows-Security-Auditing"
    ],
    "process.pid": [
      0
    ],
    "signal.rule.created_by": [
      "elastic"
    ],
    "signal.rule.interval": [
      "5m"
    ],
    "kibana.alert.rule.created_by": [
      "elastic"
    ],
    "kibana.alert.rule.name": [
      "Multiple Logon Failure from the same Source Address"
    ],
    "host.name": [
      "desktop-niu0ucp"
    ],
    "kibana.alert.rule.threat.technique.reference": [
      "https://attack.mitre.org/techniques/T1110/"
    ],
    "event.kind": [
      "signal"
    ],
    "signal.rule.created_at": [
      "2025-05-28T11:34:52.053Z"
    ],
    "kibana.alert.workflow_status": [
      "open"
    ],
    "kibana.alert.reason": [
      "authentication event with source 192.168.4.101 by denny on desktop-niu0ucp created medium alert Multiple Logon Failure from the same Source Address."
    ],
    "signal.rule.threat.tactic.id": [
      "TA0006"
    ],
    "data_stream.type": [
      "logs"
    ],
    "signal.ancestors.id": [
      "AZcvdRS9iYAeD95vW3WL",
      "5a630b9d49ee43c356b485e947ee4b431513d3a284354b6fcae9cc5e57d0d61f",
      "AZcvdRS9iYAeD95vW3WM",
      "8af33ff57cb1050c6334494cc334917700d78681743a1083334fcf35bd987b11",
      "AZcvdRS9iYAeD95vW3WN",
      "4a0832eb41f37735211036abfcba23e412959084fe482a53bd217dec835afe9c",
      "AZcvdRS9iYAeD95vW3WO",
      "d7d897fd15b95a780c60d503550b279f5c3c634e73c604786df15fcdbab41aef",
      "AZcvdRS9iYAeD95vW3WP",
      "fe9349f6282ded70b9f2be636db22ed005d55c2c3b894ffcf967d681e24b7186",
      "AZcvdRS9iYAeD95vW3WQ",
      "c76ff77fbc9e8faae91eb171c68ff7f2c1b175075d9e22d83a0d6fc194297254",
      "AZcvdRS9iYAeD95vW3WR",
      "a7a1dfe87281a52f01dd46fbfcc99efe81fb38cbfbc491ff8f1d8fc6f810dfc8",
      "AZcvdRS9iYAeD95vW3WS",
      "f4cea659202a5c5057748bb2a3e8a543d8bc660e606f80eca2b1d36eae2aee8a",
      "AZcvdRS9iYAeD95vW3WT",
      "398b9778f9a79cfdae8365a4db3484053e53ce281889d99377b90dd342fcf22c",
      "AZcvdRS9iYAeD95vW3WU",
      "22b271ad8d48aa30470c60d38fffea9007072d8a19d068abd9e71d1dd2b3707c"
    ],
    "signal.original_time": [
      "2025-06-02T07:08:52.956Z"
    ],
    "ecs.version": [
      "8.11.0"
    ],
    "signal.rule.severity": [
      "medium"
    ],
    "kibana.alert.depth": [
      2
    ],
    "kibana.alert.rule.revision": [
      0
    ],
    "signal.rule.version": [
      "114"
    ],
    "signal.group.id": [
      "10da92e0b4351ac7b6a3460814f87d13204b7dad67818290dadffdbfff7482b1"
    ],
    "kibana.alert.status": [
      "active"
    ],
    "kibana.alert.last_detected": [
      "2025-06-02T07:08:53.125Z"
    ],
    "kibana.alert.original_event.dataset": [
      "system.security"
    ],
    "kibana.alert.rule.rule_type_id": [
      "siem.eqlRule"
    ],
    "kibana.alert.original_event.provider": [
      "Microsoft-Windows-Security-Auditing"
    ],
    "signal.rule.rule_id": [
      "48b6edfc-079d-4907-b43c-baffa243270d"
    ],
    "signal.rule.threat.tactic.reference": [
      "https://attack.mitre.org/tactics/TA0006/"
    ],
    "signal.rule.threat.tactic.name": [
      "Credential Access"
    ],
    "kibana.alert.rule.threat.framework": [
      "MITRE ATT&CK"
    ],
    "kibana.alert.rule.updated_at": [
      "2025-05-28T11:40:33.891Z"
    ],
    "data_stream.namespace": [
      "default"
    ],
    "kibana.alert.rule.author": [
      "Elastic"
    ],
    "winlog.event_id": [
      "4625"
    ],
    "kibana.alert.rule.threat.tactic.reference": [
      "https://attack.mitre.org/tactics/TA0006/"
    ],
    "signal.original_event.action": [
      "logon-failed"
    ],
    "kibana.alert.rule.created_at": [
      "2025-05-28T11:34:52.053Z"
    ],
    "signal.rule.to": [
      "now"
    ],
    "winlog.event_data.SubStatus": [
      "0xc0000064"
    ],
    "event.type": [
      "start"
    ],
    "kibana.alert.rule.execution.type": [
      "scheduled"
    ],
    "event.dataset": [
      "system.security"
    ],
    "kibana.alert.original_time": [
      "2025-06-02T07:08:52.956Z"
    ]
  }
}
