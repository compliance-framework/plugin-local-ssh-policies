package compliance_framework.deny_password_based_root_ssh

import future.keywords.in

risk_templates := [{
  "name": "SSH root login with password enabled",
  "title": "Direct Privileged Remote Access via Root Password Authentication",
  "statement": "Allowing root SSH login with password enables attackers to directly target the most privileged account using brute force or credential stuffing. Successful compromise provides immediate full system control without requiring privilege escalation, enabling persistence, data access, and lateral movement.",
  "likelihood_hint": "high",
  "impact_hint": "critical",
  "violation_ids": ["ssh_root_password_auth"],
  "threat_refs": [
    {
      "system": "https://cwe.mitre.org",
      "external_id": "CWE-522",
      "title": "Insufficiently Protected Credentials",
      "url": "https://cwe.mitre.org/data/definitions/522.html"
    },
  ],
  "remediation": {
    "title": "Eliminate direct root password SSH access",
    "description": "Disable root password login over SSH and require named user accounts with key-based authentication and controlled privilege elevation.",
    "tasks": [
      { "title": "Set PermitRootLogin no (or prohibit-password/without-password where policy allows)" },
      { "title": "Set PasswordAuthentication no for SSH" },
      { "title": "Require named admin accounts and use sudo for privileged actions" },
      { "title": "Restrict SSH access to approved management networks" },
      { "title": "Enforce lockout/throttling and MFA as compensating controls if temporary exceptions exist" },
      { "title": "Reload/restart sshd and validate administrative access paths" }
    ]
  }
}]

violation[{"id": "ssh_root_password_auth"}] if {
	not "without-password" in input.permitrootlogin
}

title := "Root account should not use password authentication"
description := "Root accounts using password is a severe security flaw, by which a brute force attack could gain elevated access to a host machine."
labels := {
    "severity": "high"
}
