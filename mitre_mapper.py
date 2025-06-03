def map_anomaly_to_mitre(anomaly_row):
    """
    Maps suspicious network behavior to known MITRE ATT&CK techniques (offline version)
    """
    matched_tactics = []

    # Simple behavioral rules
    if anomaly_row['byte_count'] > 1_000_000:
        matched_tactics.append("Exfiltration")
    if anomaly_row['duration'] > 300:
        matched_tactics.append("Command and Control")
    if anomaly_row['packet_count'] > 100:
        matched_tactics.append("Lateral Movement")

    if not matched_tactics:
        return []

    # Fallback MITRE ATT&CK technique mappings
    mitre_tags = {
        "Exfiltration": [
            {"id": "T1048", "name": "Exfiltration Over Alternative Protocol", "tactic": "Exfiltration"},
            {"id": "T1029", "name": "Scheduled Transfer", "tactic": "Exfiltration"},
        ],
        "Command and Control": [
            {"id": "T1071", "name": "Application Layer Protocol", "tactic": "Command and Control"},
            {"id": "T1105", "name": "Remote File Copy", "tactic": "Command and Control"},
        ],
        "Lateral Movement": [
            {"id": "T1021", "name": "Remote Services", "tactic": "Lateral Movement"},
            {"id": "T1570", "name": "Serverless Execution", "tactic": "Lateral Movement"},
        ]
    }

    results = []
    for tactic in set(matched_tactics):
        results.extend(mitre_tags.get(tactic, []))

    print(f"[+] Matched {len(results)} MITRE ATT&CK techniques (offline)")
    return results[:5]  # Return up to 5 matches