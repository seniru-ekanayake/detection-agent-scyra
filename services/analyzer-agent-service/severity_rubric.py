from typing import List, Dict, Any

def determine_base_severity(properties: List[Dict[str, Any]], cves: List[Dict[str, Any]], org_context: Dict[str, Any]) -> str:
    ports = []
    has_admin = False
    has_expired_tls = False
    has_takeover = False
    has_outdated = False
    has_unusual_port = False

    for prop in properties:
        key = prop.get("property_key", "").lower()
        val = str(prop.get("property_value", "")).lower()
        
        if key == "port":
            try:
                ports.append(int(val))
            except:
                pass
        elif "admin" in key or "admin" in val:
            has_admin = True
        elif "expired" in val and ("tls" in key or "cert" in key):
            has_expired_tls = True
        elif "takeover" in key or "takeover" in val:
            has_takeover = True
        elif "outdated" in val:
            has_outdated = True

    # 1. Database port internet-facing
    db_ports = {5432, 3306, 6379, 27017, 1521, 5984, 9200}
    for port in ports:
        if port in db_ports:
            return "critical"

    # 2. Internet-exposed service + public exploit for version
    has_public_exploit = any(cve.get("exploit_available", False) for cve in cves)
    if ports and has_public_exploit:
        return "critical"

    # 3. CVE CVSS >= 9.0 + confirmed internet exposure
    max_cvss = max([cve.get("cvss_score", 0.0) for cve in cves]) if cves else 0.0
    if max_cvss >= 9.0:
        return "critical"

    # 4. Any finding on PII or restricted asset + exposure
    data_class = org_context.get("data_classification", "").lower()
    if data_class in ["pii", "restricted"] and (ports or cves or has_admin or has_expired_tls):
        return "critical"

    # HIGH
    # - CVE CVSS 7.0-8.9 + internet exposure
    if max_cvss >= 7.0:
         return "high"
    # - Expired TLS on customer-facing asset
    business_crit = org_context.get("business_criticality", "").lower()
    if has_expired_tls and business_crit in ["high", "critical"]:
        return "high"
    # - Subdomain takeover risk
    if has_takeover:
        return "high"
    # - Admin interface, no CVE confirmed
    if has_admin:
        return "high"

    # MEDIUM
    # - CVE CVSS 4.0-6.9
    if max_cvss >= 4.0:
        return "medium"
    # - Expired certificate on internal asset
    if has_expired_tls:
        return "medium"
    # - Outdated software, no known CVE
    if has_outdated:
        return "medium"
    # - Unusual open port, no identified service
    # Say, anything other than 80, 443, 22
    unusual = [p for p in ports if p not in [80, 443, 22]]
    if unusual:
        return "medium"

    # LOW
    # - Single-source finding, unverified
    # - Informational exposure, no exploit path
    if ports or cves:
        return "low"

    # INFORMATIONAL
    return "informational"

def modify_severity(base_severity: str, org_context: Dict[str, Any]) -> str:
    severity_order = ["informational", "low", "medium", "high", "critical"]
    try:
        idx = severity_order.index(base_severity.lower())
    except ValueError:
        return base_severity

    data_class = org_context.get("data_classification", "").lower()
    is_third_party = org_context.get("known_third_party", False)

    # Escalation
    if data_class in ["pii", "restricted"]:
        idx = min(len(severity_order) - 1, idx + 1)

    # De-escalation
    if is_third_party:
        idx = max(0, idx - 1)

    return severity_order[idx]
