import urllib.request
import json
import base64
import sys

GRAFANA_URL = "http://localhost:3000"
GRAFANA_USER = "admin"
GRAFANA_PASS = "admin"

def make_request(path, method="GET", data=None):
    url = f"{GRAFANA_URL}{path}"
    req = urllib.request.Request(url, method=method)
    auth_header = base64.b64encode(f"{GRAFANA_USER}:{GRAFANA_PASS}".encode()).decode()
    req.add_header("Authorization", f"Basic {auth_header}")
    req.add_header("Content-Type", "application/json")
    
    body = json.dumps(data).encode("utf-8") if data else None
    with urllib.request.urlopen(req, data=body) as resp:
        return json.loads(resp.read().decode())

def deploy_dashboard():
    print("=" * 75)
    print(" Configuring Grafana & Deploying World-Class SOC Dashboard...")
    print("=" * 75)
    
    datasources = make_request("/api/datasources")
    prom_ds = next((ds for ds in datasources if ds.get("type") == "prometheus"), None)
    
    if not prom_ds:
        print("[+] Creating Prometheus Data Source...")
        ds_payload = {
            "name": "Prometheus",
            "type": "prometheus",
            "access": "proxy",
            "url": "http://localhost:9090",
            "isDefault": True,
            "jsonData": {"httpMethod": "GET"}
        }
        res = make_request("/api/datasources", method="POST", data=ds_payload)
        ds_uid = res.get("datasource", {}).get("uid", "prometheus")
        print(f"[OK] Prometheus Data Source created with UID: {ds_uid}")
    else:
        ds_uid = prom_ds["uid"]
        print(f"[OK] Utilizing Prometheus Data Source (UID: {ds_uid})")

    dashboard = {
        "dashboard": {
            "id": None,
            "uid": "institute-soc-overview",
            "title": "Institute Cyber Security SOC & Network Monitor",
            "tags": ["soc", "security", "network", "windows-endpoints", "mitre-attack", "threat-intel"],
            "timezone": "browser",
            "schemaVersion": 39,
            "refresh": "5s",
            "time": {"from": "now-1h", "to": "now"},
            "panels": [
                # ----------------- 1. ACTIVE COMPUTERS -----------------
                {
                    "id": 1,
                    "title": "Active Computers",
                    "type": "stat",
                    "gridPos": {"h": 4, "w": 4, "x": 0, "y": 0},
                    "datasource": {"type": "prometheus", "uid": ds_uid},
                    "targets": [{"expr": "count(max by (target_ip) (endpoint_status)) or vector(0)", "refId": "A"}],
                    "options": {
                        "colorMode": "background",
                        "graphMode": "area",
                        "justifyMode": "center",
                        "textMode": "value_and_name",
                        "reduceOptions": {"calcs": ["lastNotNull"], "values": False}
                    },
                    "fieldConfig": {
                        "defaults": {
                            "unit": "short",
                            "color": {"mode": "fixed", "fixedColor": "dark-green"},
                            "thresholds": {"mode": "absolute", "steps": [{"color": "dark-green", "value": None}]}
                        },
                        "overrides": []
                    }
                },
                # ----------------- 2. ROGUE DEVICES -----------------
                {
                    "id": 2,
                    "title": "Rogue / Unauthorized PCs",
                    "type": "stat",
                    "gridPos": {"h": 4, "w": 4, "x": 4, "y": 0},
                    "datasource": {"type": "prometheus", "uid": ds_uid},
                    "targets": [{"expr": "total_rogue_devices or vector(0)", "refId": "A"}],
                    "options": {
                        "colorMode": "background",
                        "graphMode": "none",
                        "justifyMode": "center",
                        "textMode": "value_and_name"
                    },
                    "fieldConfig": {
                        "defaults": {
                            "unit": "short",
                            "color": {"mode": "thresholds"},
                            "thresholds": {
                                "mode": "absolute",
                                "steps": [
                                    {"color": "#10B981", "value": None},
                                    {"color": "#EF4444", "value": 1}
                                ]
                            }
                        },
                        "overrides": []
                    }
                },
                # ----------------- 3. VULNERABILITIES DETECTED -----------------
                {
                    "id": 3,
                    "title": "Vulnerability Risks",
                    "type": "stat",
                    "gridPos": {"h": 4, "w": 4, "x": 8, "y": 0},
                    "datasource": {"type": "prometheus", "uid": ds_uid},
                    "targets": [{"expr": "total_vulnerabilities_detected or vector(0)", "refId": "A"}],
                    "options": {"colorMode": "background", "graphMode": "none", "justifyMode": "center", "textMode": "value_and_name"},
                    "fieldConfig": {
                        "defaults": {
                            "unit": "short",
                            "color": {"mode": "thresholds"},
                            "thresholds": {
                                "mode": "absolute",
                                "steps": [
                                    {"color": "#10B981", "value": None},
                                    {"color": "#F59E0B", "value": 1},
                                    {"color": "#EF4444", "value": 5}
                                ]
                            }
                        },
                        "overrides": []
                    }
                },
                # ----------------- 4. HEALTH RATING -----------------
                {
                    "id": 4,
                    "title": "Security Health Posture",
                    "type": "stat",
                    "gridPos": {"h": 4, "w": 4, "x": 12, "y": 0},
                    "datasource": {"type": "prometheus", "uid": ds_uid},
                    "targets": [{"expr": "network_health_index or vector(100)", "refId": "A"}],
                    "options": {"colorMode": "value", "graphMode": "none", "justifyMode": "center", "textMode": "value_and_name"},
                    "fieldConfig": {
                        "defaults": {
                            "unit": "percent",
                            "min": 0,
                            "max": 100,
                            "decimals": 0,
                            "color": {"mode": "thresholds"},
                            "thresholds": {
                                "mode": "absolute",
                                "steps": [
                                    {"color": "#EF4444", "value": None},
                                    {"color": "#F59E0B", "value": 70},
                                    {"color": "#10B981", "value": 90}
                                ]
                            }
                        },
                        "overrides": []
                    }
                },
                # ----------------- 5. LATENCY -----------------
                {
                    "id": 5,
                    "title": "Average Network Latency",
                    "type": "stat",
                    "gridPos": {"h": 4, "w": 4, "x": 16, "y": 0},
                    "datasource": {"type": "prometheus", "uid": ds_uid},
                    "targets": [{"expr": "avg(endpoint_latency_ms) or vector(0)", "refId": "A"}],
                    "options": {"colorMode": "value", "graphMode": "area", "justifyMode": "center", "textMode": "value_and_name"},
                    "fieldConfig": {
                        "defaults": {
                            "unit": "ms",
                            "decimals": 1,
                            "color": {"mode": "thresholds"},
                            "thresholds": {
                                "mode": "absolute",
                                "steps": [
                                    {"color": "#10B981", "value": None},
                                    {"color": "#F59E0B", "value": 30},
                                    {"color": "#EF4444", "value": 80}
                                ]
                            }
                        },
                        "overrides": []
                    }
                },
                # ----------------- 6. LOGON ANOMALIES -----------------
                {
                    "id": 6,
                    "title": "Logon Failures (5m)",
                    "type": "stat",
                    "gridPos": {"h": 4, "w": 4, "x": 20, "y": 0},
                    "datasource": {"type": "prometheus", "uid": ds_uid},
                    "targets": [{"expr": "sum(increase(brute_force_attempts_total[5m])) or vector(0)", "refId": "A"}],
                    "options": {"colorMode": "background", "graphMode": "area", "justifyMode": "center", "textMode": "value_and_name"},
                    "fieldConfig": {
                        "defaults": {
                            "unit": "short",
                            "decimals": 0,
                            "color": {"mode": "thresholds"},
                            "thresholds": {
                                "mode": "absolute",
                                "steps": [
                                    {"color": "rgba(16, 185, 129, 0.2)", "value": None},
                                    {"color": "#F59E0B", "value": 1},
                                    {"color": "#EF4444", "value": 5}
                                ]
                            }
                        },
                        "overrides": []
                    }
                },

                # ----------------- 7. MASTER ENDPOINT INVENTORY TABLE -----------------
                {
                    "id": 7,
                    "title": "Master Endpoint Inventory Matrix (Hardware & IEEE Vendor Recognition)",
                    "type": "table",
                    "gridPos": {"h": 10, "w": 24, "x": 0, "y": 4},
                    "datasource": {"type": "prometheus", "uid": ds_uid},
                    "targets": [
                        {
                            "expr": "max by (target_ip, hostname, subnet, mac, vendor) (endpoint_status)",
                            "instant": True,
                            "format": "table",
                            "refId": "A"
                        }
                    ],
                    "transformations": [
                        {
                            "id": "merge",
                            "options": {}
                        },
                        {
                            "id": "organize",
                            "options": {
                                "excludeByName": {
                                    "Time": True,
                                    "__name__": True
                                },
                                "renameByName": {
                                    "target_ip": "IP Address",
                                    "hostname": "Computer Name",
                                    "subnet": "Subnet / Lab Segment",
                                    "mac": "Hardware MAC Address",
                                    "vendor": "Hardware Vendor (OUI)",
                                    "Value": "Status"
                                }
                            }
                        }
                    ],
                    "options": {
                        "cellOptions": {"type": "auto"},
                        "footer": {"show": True, "countRows": True, "enablePagination": True},
                        "showHeader": True
                    },
                    "fieldConfig": {
                        "defaults": {
                            "custom": {
                                "align": "left",
                                "filterable": True
                            },
                            "mappings": [
                                {
                                    "type": "value",
                                    "options": {
                                        "1": {
                                            "text": "ONLINE",
                                            "color": "dark-green"
                                        }
                                    }
                                }
                            ],
                            "thresholds": {
                                "mode": "absolute",
                                "steps": [
                                    {"color": "dark-green", "value": None}
                                ]
                            }
                        },
                        "overrides": []
                    }
                },

                # ----------------- 8. MITRE ATT&CK FRAMEWORK TABLE -----------------
                {
                    "id": 8,
                    "title": "MITRE ATT&CK Threat Framework Alignment Matrix",
                    "type": "table",
                    "gridPos": {"h": 8, "w": 14, "x": 0, "y": 14},
                    "datasource": {"type": "prometheus", "uid": ds_uid},
                    "targets": [
                        {
                            "expr": "max by (target_ip, technique_id, technique_name, tactic, severity) (mitre_attack_technique == 1)",
                            "instant": True,
                            "format": "table",
                            "refId": "A"
                        }
                    ],
                    "transformations": [
                        {
                            "id": "merge",
                            "options": {}
                        },
                        {
                            "id": "organize",
                            "options": {
                                "excludeByName": {"Time": True, "__name__": True, "Value": True},
                                "renameByName": {
                                    "target_ip": "Target IP",
                                    "technique_id": "MITRE ID",
                                    "technique_name": "Technique Name",
                                    "tactic": "ATT&CK Tactic",
                                    "severity": "Severity"
                                }
                            }
                        }
                    ],
                    "options": {
                        "cellOptions": {"type": "auto"},
                        "footer": {"show": True, "countRows": True},
                        "showHeader": True
                    },
                    "fieldConfig": {
                        "defaults": {"custom": {"align": "left", "filterable": True}},
                        "overrides": [
                            {
                                "matcher": {"id": "byName", "options": "Severity"},
                                "properties": [
                                    {
                                        "id": "mappings",
                                        "value": [
                                            {"type": "value", "options": {"CRITICAL": {"text": "CRITICAL", "color": "dark-red"}}},
                                            {"type": "value", "options": {"HIGH": {"text": "HIGH", "color": "red"}}},
                                            {"type": "value", "options": {"MEDIUM": {"text": "MEDIUM", "color": "dark-orange"}}},
                                            {"type": "value", "options": {"LOW": {"text": "LOW", "color": "dark-blue"}}}
                                        ]
                                    }
                                ]
                            }
                        ]
                    }
                },

                # ----------------- 9. ROGUE DEVICE TABLE -----------------
                {
                    "id": 9,
                    "title": "Unauthorized / Rogue Device Alarms",
                    "type": "table",
                    "gridPos": {"h": 8, "w": 10, "x": 14, "y": 14},
                    "datasource": {"type": "prometheus", "uid": ds_uid},
                    "targets": [
                        {
                            "expr": "max by (target_ip, mac, hostname, lab_name) (rogue_device_detected == 1)",
                            "instant": True,
                            "format": "table",
                            "refId": "A"
                        }
                    ],
                    "transformations": [
                        {
                            "id": "merge",
                            "options": {}
                        },
                        {
                            "id": "organize",
                            "options": {
                                "excludeByName": {"Time": True, "__name__": True, "Value": True},
                                "renameByName": {
                                    "target_ip": "Rogue IP",
                                    "mac": "MAC Address",
                                    "hostname": "Hostname",
                                    "lab_name": "Lab Location"
                                }
                            }
                        }
                    ],
                    "options": {
                        "cellOptions": {"type": "auto"},
                        "footer": {"show": True, "countRows": True},
                        "showHeader": True
                    },
                    "fieldConfig": {"defaults": {"custom": {"align": "left", "filterable": True}}, "overrides": []}
                },

                # ----------------- 10. CVSS RISK GAUGE -----------------
                {
                    "id": 10,
                    "title": "Endpoint CVSS v3.1 Quantitative Risk Scores",
                    "type": "bargauge",
                    "gridPos": {"h": 8, "w": 12, "x": 0, "y": 22},
                    "datasource": {"type": "prometheus", "uid": ds_uid},
                    "targets": [{"expr": "max by (target_ip) (endpoint_risk_score)", "legendFormat": "{{target_ip}}", "refId": "A"}],
                    "options": {
                        "displayMode": "gradient",
                        "orientation": "horizontal",
                        "showUnfilled": True,
                        "reduceOptions": {"calcs": ["lastNotNull"], "values": False}
                    },
                    "fieldConfig": {
                        "defaults": {
                            "unit": "short",
                            "min": 0,
                            "max": 100,
                            "decimals": 0,
                            "color": {"mode": "thresholds"},
                            "thresholds": {
                                "mode": "absolute",
                                "steps": [
                                    {"color": "#10B981", "value": None},
                                    {"color": "#F59E0B", "value": 30},
                                    {"color": "#EF4444", "value": 60}
                                ]
                            }
                        },
                        "overrides": []
                    }
                },

                # ----------------- 11. LATENCY BREAKDOWN -----------------
                {
                    "id": 11,
                    "title": "Endpoint Network Latency Breakdown (ms)",
                    "type": "bargauge",
                    "gridPos": {"h": 8, "w": 12, "x": 12, "y": 22},
                    "datasource": {"type": "prometheus", "uid": ds_uid},
                    "targets": [{"expr": "max by (target_ip) (endpoint_latency_ms)", "legendFormat": "{{target_ip}}", "refId": "A"}],
                    "options": {
                        "displayMode": "gradient",
                        "orientation": "horizontal",
                        "showUnfilled": True,
                        "reduceOptions": {"calcs": ["lastNotNull"], "values": False}
                    },
                    "fieldConfig": {
                        "defaults": {
                            "unit": "ms",
                            "decimals": 1,
                            "min": 0,
                            "max": 100,
                            "color": {"mode": "thresholds"},
                            "thresholds": {
                                "mode": "absolute",
                                "steps": [
                                    {"color": "#10B981", "value": None},
                                    {"color": "#F59E0B", "value": 30},
                                    {"color": "#EF4444", "value": 70}
                                ]
                            }
                        },
                        "overrides": []
                    }
                },

                # ----------------- 12. PRESENCE TIMELINE -----------------
                {
                    "id": 12,
                    "title": "Subnet Computer Presence Timeline (Historical Activity)",
                    "type": "timeseries",
                    "gridPos": {"h": 8, "w": 24, "x": 0, "y": 30},
                    "datasource": {"type": "prometheus", "uid": ds_uid},
                    "targets": [{"expr": "count by (subnet) (endpoint_status)", "legendFormat": "Subnet: {{subnet}}", "refId": "A"}],
                    "options": {
                        "legend": {"calcs": ["lastNotNull", "max", "min"], "displayMode": "table", "placement": "bottom"},
                        "tooltip": {"mode": "multi", "sort": "desc"}
                    },
                    "fieldConfig": {
                        "defaults": {
                            "unit": "short",
                            "custom": {
                                "drawStyle": "line",
                                "lineInterpolation": "smooth",
                                "lineWidth": 3,
                                "fillOpacity": 20,
                                "gradientMode": "opacity",
                                "spanNulls": True
                            },
                            "color": {"mode": "palette-classic"}
                        },
                        "overrides": []
                    }
                }
            ]
        },
        "overwrite": True
    }

    dash_res = make_request("/api/dashboards/db", method="POST", data=dashboard)
    dash_url = f"{GRAFANA_URL}{dash_res.get('url', '/d/institute-soc-overview')}"
    
    try:
        make_request("/api/org/preferences", method="PUT", data={"homeDashboardUID": "institute-soc-overview"})
    except Exception:
        pass

    print(f"[SUCCESS] Dashboard Deployed Successfully!")
    print(f"[ACCESS URL] {dash_url}")
    print("=" * 75)

if __name__ == "__main__":
    try:
        deploy_dashboard()
    except Exception as e:
        print(f"[ERROR] Deployment failed: {e}")
        sys.exit(1)
