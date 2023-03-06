""" Copyright start
  Copyright (C) 2008 - 2023 Fortinet Inc.
  All rights reserved.
  FORTINET CONFIDENTIAL & FORTINET PROPRIETARY SOURCE CODE
  Copyright end """

Detection = "https://detections.icebrg.io/v1/"
Sensors = "https://sensor.icebrg.io/v1/"
Entity = "https://entity.icebrg.io/v1/entity/"
Entity_Tracking = "https://entity.icebrg.io/v2/entity/"

SORT_BY = {
    'IP Address': 'ip_address',
    'Internal': 'internal',
    'External': 'external',
    'First Seen': 'first_seen',
    'Status': 'status',
    'Device IP': 'device_ip',
    'Detection Count': 'detection_count',
    'Threat Score': 'threat_score',
    'Indicator Count': 'indicator_count',
    'Created': 'created',
    'Updated': 'updated',
    'Detections': 'detections',
    'Severity': 'severity',
    'Confidence': 'confidence',
    'Category': 'category',
    'Last Seen': 'last_seen',
    'Detection Muted': 'detections_muted'
}

SORT_ORDER = {
    'Ascending': 'asc',
    'Descending': 'desc'
}

EVENT_TYPE = {
    "DHCP": "dhcp",
    "DNS": "dns",
    "Flow": "flow",
    "FTP": "ftp",
    "HTTP": "http",
    "X509": "x509",
    "DCE RPC": "dce_rpc",
    "Kerberos": "kerberos",
    "Notice": "notice",
    "NTLM": "ntlm",
    "Observation": "observation",
    "PE": "pe",
    "RDP": "rdp",
    "SMB Files": "smb_files",
    "SMB Mapping": "smb_mapping",
    "SMTP": "smtp",
    "Software": "software",
    "SSH": "ssh",
    "SSL": "ssl",
    "Suricata": "suricata",
    "Tunnel": "tunnel"
}

GROUP_BY = {
    'Sensor ID': 'sensor_id',
    'Event Type': 'event_type'
}

Interval = {
    'Day': 'day',
    'Month to Day': 'month_to_day'
}

Resolution = {
    "True Positive Mitigated": "true_positive_mitigated",
    "True Positive No Action": "true_positive_no_action",
    "False Positive": "false_positive",
    "Unknown": "unknown"
}
