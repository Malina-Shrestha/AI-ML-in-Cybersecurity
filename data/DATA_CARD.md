# Data Card - TriageMate Alert Dataset

## Summary
53 real security alerts extracted from the two data sources listed in the course
resources. Every alert is a genuine event recorded during a published attack
simulation, reshaped into the TriageMate schema. No synthetic or random data is
used. For defensive research and coursework only.

## Sources (both from the course resource list)
1. OTRF Security-Datasets - https://github.com/OTRF/Security-Datasets
2. Splunk Attack Data - https://github.com/splunk/attack_data
3. MITRE ATT&CK (technique references) - https://attack.mitre.org/resources/attack-data-and-tools/

## Files
- `all_alerts.jsonl` - 53 alerts, one JSON object per line (no answer labels inside).
- `all_labels.csv` - answer key: alert_id, label_category, label_priority.

## Schema (per alert)
`alert_id`, `timestamp`, `rule_name`, `vendor_severity`, `log_source`, `host.name`,
`user.name`, `source.ip`, `destination.ip`, `raw_log`, `mitre_hint`, `data_source`.
The `data_source` field holds the full reference to the originating dataset.

## Categories
| Category | Count |
| --- | --- |
| credential_attack | 16 |
| lateral_movement | 11 |
| ransomware | 2 |
| benign | 12 |
| false_positive | 12 |
| **Total** | **53** |

## How alerts were extracted
Each source recording holds thousands of mixed events. For every dataset we
selected the event that reveals the technique (for example, the process that
accesses LSASS memory, or the command that deletes shadow copies). Benign alerts
are real routine background events (signed system processes) drawn from the same
recordings. False-positive alerts are real benign events that could plausibly
trigger a detection (admin PowerShell, scheduled tasks, WMI host activity); the
`fp_rationale` field records why each looks suspicious but is not an attack.

## Labelling and provenance
- Source (data_source): a verifiable fact, cited to the exact dataset.
- Attack labels: taken from the known technique of each source dataset.
- Benign and false-positive labels: assigned by the team on real background
  events, since the sources do not pre-label these. Documented openly here.

## Full reference list (alert IDs to source dataset)
| Alerts | Source dataset |
| --- | --- |
| OTRF-009 | datasets/atomic/windows/credential_access/host/cmd_dumping_ntds_dit_file_ntdsutil.zip |
| OTRF-BEN-011, OTRF-BEN-012 | datasets/atomic/windows/credential_access/host/cmd_dumping_ntds_dit_file_ntdsutil.zip (benign background event) |
| OTRF-004 | datasets/atomic/windows/credential_access/host/cmd_lsass_memory_dumpert_syscalls.zip |
| OTRF-008 | datasets/atomic/windows/credential_access/host/cmd_psexec_lsa_secrets_dump.zip |
| OTRF-007 | datasets/atomic/windows/credential_access/host/cmd_sam_copy_esentutl.zip |
| OTRF-012 | datasets/atomic/windows/credential_access/host/covenant_dcsync_dcerpc_drsuapi_DsGetNCChanges.zip |
| OTRF-011 | datasets/atomic/windows/credential_access/host/empire_dcsync_dcerpc_drsuapi_DsGetNCChanges.zip |
| OTRF-002 | datasets/atomic/windows/credential_access/host/empire_mimikatz_logonpasswords.zip |
| OTRF-BEN-001, OTRF-BEN-002 | datasets/atomic/windows/credential_access/host/empire_mimikatz_logonpasswords.zip (benign background event) |
| OTRF-003 | datasets/atomic/windows/credential_access/host/empire_mimikatz_lsadump_patch.zip |
| OTRF-005 | datasets/atomic/windows/credential_access/host/empire_mimikatz_sam_access.zip |
| OTRF-010 | datasets/atomic/windows/credential_access/host/empire_ninjacopy_dumping_ntds_dit_file.zip |
| OTRF-006 | datasets/atomic/windows/credential_access/host/empire_shell_reg_dump_sam.zip |
| OTRF-013 | datasets/atomic/windows/credential_access/host/empire_shell_rubeus_asktgt_ptt.zip |
| OTRF-014 | datasets/atomic/windows/credential_access/host/psh_input_capture_promptforcreds.zip |
| OTRF-001 | datasets/atomic/windows/credential_access/host/psh_lsass_memory_dump_comsvcs.zip |
| OTRF-015 | datasets/atomic/windows/credential_access/host/psh_windows_vault_web_credentials.zip |
| OTRF-025 | datasets/atomic/windows/lateral_movement/host/covenant_copy_smb_CreateRequest.zip |
| OTRF-FP-010, OTRF-FP-011, OTRF-FP-012 | datasets/atomic/windows/lateral_movement/host/covenant_copy_smb_CreateRequest.zip (benign background event, team-labelled false positive) |
| OTRF-023 | datasets/atomic/windows/lateral_movement/host/covenant_dcom_executeexcel4macro_allowed.zip |
| OTRF-021 | datasets/atomic/windows/lateral_movement/host/covenant_psremoting_command.zip |
| OTRF-BEN-009, OTRF-BEN-010 | datasets/atomic/windows/lateral_movement/host/covenant_psremoting_command.zip (benign background event) |
| OTRF-019 | datasets/atomic/windows/lateral_movement/host/covenant_sharpwmi_create_dcerpc_wmi.zip |
| OTRF-022 | datasets/atomic/windows/lateral_movement/host/empire_dcom_shellwindows_stager.zip |
| OTRF-016 | datasets/atomic/windows/lateral_movement/host/empire_psexec_dcerpc_tcp_svcctl.zip |
| OTRF-BEN-003, OTRF-BEN-004 | datasets/atomic/windows/lateral_movement/host/empire_psexec_dcerpc_tcp_svcctl.zip (benign background event) |
| OTRF-020 | datasets/atomic/windows/lateral_movement/host/empire_psremoting_stager.zip |
| OTRF-FP-004, OTRF-FP-005, OTRF-FP-006 | datasets/atomic/windows/lateral_movement/host/empire_psremoting_stager.zip (benign background event, team-labelled false positive) |
| OTRF-017 | datasets/atomic/windows/lateral_movement/host/empire_smbexec_dcerpc_smb_svcctl.zip |
| OTRF-018 | datasets/atomic/windows/lateral_movement/host/empire_wmi_dcerpc_wmi_IWbemServices_ExecMethod.zip |
| OTRF-BEN-007, OTRF-BEN-008 | datasets/atomic/windows/lateral_movement/host/empire_wmi_dcerpc_wmi_IWbemServices_ExecMethod.zip (benign background event) |
| OTRF-FP-007, OTRF-FP-008, OTRF-FP-009 | datasets/atomic/windows/lateral_movement/host/empire_wmi_dcerpc_wmi_IWbemServices_ExecMethod.zip (benign background event, team-labelled false positive) |
| OTRF-026 | datasets/atomic/windows/lateral_movement/host/mimikatz_CVE-2020-1472_Unauthenticated_NetrServerAuthenticate2.zip |
| OTRF-024 | datasets/atomic/windows/lateral_movement/host/schtask_create.zip |
| OTRF-BEN-005, OTRF-BEN-006 | datasets/atomic/windows/lateral_movement/host/schtask_create.zip (benign background event) |
| OTRF-FP-001, OTRF-FP-002, OTRF-FP-003 | datasets/atomic/windows/lateral_movement/host/schtask_create.zip (benign background event, team-labelled false positive) |
| SPLK-003 | datasets/attack_techniques/T1486/.../snapattack.log |
| SPLK-001, SPLK-002 | datasets/attack_techniques/T1490/atomic_red_team/4688_xml_windows_security_delete_shadow.log |

## Limitations
- Ransomware is lightly covered (2 alerts), because clean ransomware events are
  rare in these sources; shadow-copy deletion is the strongest available signal.
- False-positive labels are team judgment on real events, not source labels.
- 53 alerts is enough for a grounded demo and evaluation; metrics on small
  per-category counts should be read with that in mind. More alerts can be added
  from the same sources using the extraction scripts.