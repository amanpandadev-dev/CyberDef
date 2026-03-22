"""
MITRE ATT&CK Tactics and Techniques

Reference data for MITRE ATT&CK framework.
"""

from __future__ import annotations

from typing import Any


# MITRE ATT&CK Tactics
MITRE_TACTICS = {
    "TA0043": {"name": "Reconnaissance", "description": "Gathering information for planning future operations"},
    "TA0042": {"name": "Resource Development", "description": "Establishing resources to support operations"},
    "TA0001": {"name": "Initial Access", "description": "Gaining initial foothold in the target environment"},
    "TA0002": {"name": "Execution", "description": "Running adversary-controlled code"},
    "TA0003": {"name": "Persistence", "description": "Maintaining presence in the environment"},
    "TA0004": {"name": "Privilege Escalation", "description": "Gaining higher-level permissions"},
    "TA0005": {"name": "Defense Evasion", "description": "Avoiding detection"},
    "TA0006": {"name": "Credential Access", "description": "Stealing credentials"},
    "TA0007": {"name": "Discovery", "description": "Exploring the environment"},
    "TA0008": {"name": "Lateral Movement", "description": "Moving through the environment"},
    "TA0009": {"name": "Collection", "description": "Gathering data of interest"},
    "TA0011": {"name": "Command and Control", "description": "Communicating with compromised systems"},
    "TA0010": {"name": "Exfiltration", "description": "Stealing data from the environment"},
    "TA0040": {"name": "Impact", "description": "Manipulate, interrupt, or destroy systems and data"},
}

# Subset of commonly relevant MITRE ATT&CK techniques
MITRE_TECHNIQUES = {
    # Reconnaissance
    "T1595": {"name": "Active Scanning", "tactic": "Reconnaissance", "description": "Scanning victim IP blocks"},
    "T1595.001": {"name": "Scanning IP Blocks", "tactic": "Reconnaissance", "parent": "T1595"},
    "T1595.002": {"name": "Vulnerability Scanning", "tactic": "Reconnaissance", "parent": "T1595"},
    
    # Initial Access
    "T1133": {"name": "External Remote Services", "tactic": "Initial Access", "description": "Leveraging remote services for access"},
    "T1190": {"name": "Exploit Public-Facing Application", "tactic": "Initial Access", "description": "Exploiting vulnerabilities in internet-facing applications"},
    "T1078": {"name": "Valid Accounts", "tactic": "Initial Access", "description": "Using legitimate credentials"},
    "T1078.001": {"name": "Default Accounts", "tactic": "Initial Access", "parent": "T1078"},
    "T1078.002": {"name": "Domain Accounts", "tactic": "Initial Access", "parent": "T1078"},
    "T1078.003": {"name": "Local Accounts", "tactic": "Initial Access", "parent": "T1078"},
    
    # Credential Access
    "T1110": {"name": "Brute Force", "tactic": "Credential Access", "description": "Attempting to access accounts by trying many passwords"},
    "T1110.001": {"name": "Password Guessing", "tactic": "Credential Access", "parent": "T1110"},
    "T1110.002": {"name": "Password Cracking", "tactic": "Credential Access", "parent": "T1110"},
    "T1110.003": {"name": "Password Spraying", "tactic": "Credential Access", "parent": "T1110"},
    "T1110.004": {"name": "Credential Stuffing", "tactic": "Credential Access", "parent": "T1110"},
    "T1555": {"name": "Credentials from Password Stores", "tactic": "Credential Access", "description": "Searching for credentials in common locations"},
    "T1552": {"name": "Unsecured Credentials", "tactic": "Credential Access", "description": "Searching for insecurely stored credentials"},
    
    # Discovery
    "T1046": {"name": "Network Service Discovery", "tactic": "Discovery", "description": "Discovering services on remote systems"},
    "T1018": {"name": "Remote System Discovery", "tactic": "Discovery", "description": "Discovering remote systems in the network"},
    "T1087": {"name": "Account Discovery", "tactic": "Discovery", "description": "Discovering accounts on the system or domain"},
    "T1087.001": {"name": "Local Account Discovery", "tactic": "Discovery", "parent": "T1087"},
    "T1087.002": {"name": "Domain Account Discovery", "tactic": "Discovery", "parent": "T1087"},
    "T1135": {"name": "Network Share Discovery", "tactic": "Discovery", "description": "Discovering network shares"},
    "T1040": {"name": "Network Sniffing", "tactic": "Discovery", "description": "Capturing network traffic"},
    "T1082": {"name": "System Information Discovery", "tactic": "Discovery", "description": "Gathering system information"},
    "T1083": {"name": "File and Directory Discovery", "tactic": "Discovery", "description": "Enumerating files and directories"},
    
    # Lateral Movement
    "T1021": {"name": "Remote Services", "tactic": "Lateral Movement", "description": "Using remote services to move laterally"},
    "T1021.001": {"name": "Remote Desktop Protocol", "tactic": "Lateral Movement", "parent": "T1021"},
    "T1021.002": {"name": "SMB/Windows Admin Shares", "tactic": "Lateral Movement", "parent": "T1021"},
    "T1021.004": {"name": "SSH", "tactic": "Lateral Movement", "parent": "T1021"},
    "T1021.005": {"name": "VNC", "tactic": "Lateral Movement", "parent": "T1021"},
    "T1210": {"name": "Exploitation of Remote Services", "tactic": "Lateral Movement", "description": "Exploiting vulnerabilities in remote services"},
    "T1570": {"name": "Lateral Tool Transfer", "tactic": "Lateral Movement", "description": "Transferring tools between systems"},
    
    # Command and Control
    "T1071": {"name": "Application Layer Protocol", "tactic": "Command and Control", "description": "Using application protocols for C2"},
    "T1071.001": {"name": "Web Protocols", "tactic": "Command and Control", "parent": "T1071"},
    "T1071.004": {"name": "DNS", "tactic": "Command and Control", "parent": "T1071"},
    "T1095": {"name": "Non-Application Layer Protocol", "tactic": "Command and Control", "description": "Using non-standard protocols for C2"},
    "T1572": {"name": "Protocol Tunneling", "tactic": "Command and Control", "description": "Tunneling traffic through other protocols"},
    "T1090": {"name": "Proxy", "tactic": "Command and Control", "description": "Using proxies to hide C2"},
    
    # Exfiltration
    "T1048": {"name": "Exfiltration Over Alternative Protocol", "tactic": "Exfiltration", "description": "Exfiltrating over non-standard protocols"},
    "T1048.001": {"name": "Exfiltration Over Symmetric Encrypted Non-C2 Protocol", "tactic": "Exfiltration", "parent": "T1048"},
    "T1041": {"name": "Exfiltration Over C2 Channel", "tactic": "Exfiltration", "description": "Exfiltrating data over C2 channel"},
    "T1567": {"name": "Exfiltration Over Web Service", "tactic": "Exfiltration", "description": "Exfiltrating to cloud services"},
    
    # Impact
    "T1498": {"name": "Network Denial of Service", "tactic": "Impact", "description": "Disrupting network availability"},
    "T1498.001": {"name": "Direct Network Flood", "tactic": "Impact", "parent": "T1498"},
    "T1499": {"name": "Endpoint Denial of Service", "tactic": "Impact", "description": "Disrupting endpoint availability"},
}


def get_technique(technique_id: str) -> dict[str, Any] | None:
    """
    Get technique details by ID.
    
    Args:
        technique_id: MITRE technique ID (e.g., T1110, T1110.001)
        
    Returns:
        Technique details or None if not found
    """
    technique = MITRE_TECHNIQUES.get(technique_id)
    if technique:
        return {
            "id": technique_id,
            **technique,
        }
    return None


def get_tactic(tactic_id: str) -> dict[str, Any] | None:
    """
    Get tactic details by ID.
    
    Args:
        tactic_id: MITRE tactic ID (e.g., TA0006)
        
    Returns:
        Tactic details or None if not found
    """
    tactic = MITRE_TACTICS.get(tactic_id)
    if tactic:
        return {
            "id": tactic_id,
            **tactic,
        }
    return None


def get_tactic_by_name(name: str) -> dict[str, Any] | None:
    """
    Get tactic details by name.
    
    Args:
        name: Tactic name (e.g., "Credential Access")
        
    Returns:
        Tactic details or None if not found
    """
    for tactic_id, tactic in MITRE_TACTICS.items():
        if tactic["name"].lower() == name.lower():
            return {
                "id": tactic_id,
                **tactic,
            }
    return None


def get_techniques_by_tactic(tactic_name: str) -> list[dict[str, Any]]:
    """
    Get all techniques for a given tactic.
    
    Args:
        tactic_name: Tactic name
        
    Returns:
        List of techniques for the tactic
    """
    techniques = []
    for tech_id, tech in MITRE_TECHNIQUES.items():
        if tech.get("tactic", "").lower() == tactic_name.lower():
            techniques.append({
                "id": tech_id,
                **tech,
            })
    return techniques
