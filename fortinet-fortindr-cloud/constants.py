"""
Copyright start
MIT License
Copyright (c) 2026 Fortinet Inc
Copyright end
"""

US_Detection = "https://detections.icebrg.io/v1/"
US_Sensors = "https://sensor.icebrg.io/v1/"
US_Entity = "https://entity.icebrg.io/v1/entity/"
US_Entity_Tracking = "https://entity.icebrg.io/v2/entity/"
US_Annotation = "https://entity.icebrg.io/v2/annotation/"
US_Annotation_Bulk = "https://entity.icebrg.io/v2/annotation_bulk/"

EU_Detection = "https://detections.eu.fortindr.forticloud.com/v1/"
EU_Sensors = "https://sensor.eu.fortindr.forticloud.com/v1/"
EU_Entity = "https://entity.eu.fortindr.forticloud.com/v1/entity/"
EU_Entity_Tracking = "https://entity.eu.fortindr.forticloud.com/v2/entity/"
EU_Annotation = "https://entity.eu.fortindr.forticloud.com/v2/annotation/"
EU_Annotation_Bulk = "https://entity.eu.fortindr.forticloud.com/v2/annotation_bulk/"

SORT_BY = {
    'IP Address': 'ip_address',
    'Internal': 'internal',
    'External': 'external',
    'First Seen': 'first_seen',
    'Status': 'status',
    'Device IP': 'device_ip',
    'IP': 'ip',
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
