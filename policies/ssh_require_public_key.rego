package compliance_framework.require_key_based_ssh

import future.keywords.in

risk_templates := [{
  "name": "SSH public key authentication not enforced",
  "title": "Insufficient SSH Authentication Strength",
  "statement": "When SSH public key authentication is not enabled, remote access may rely on weaker authentication methods, increasing exposure to credential theft, brute-force, and unauthorized administrative access.",
  "likelihood_hint": "medium",
  "impact_hint": "high",
  "violation_ids": ["ssh_require_public_key"],
  "threat_refs": [
    {
      "system": "https://cwe.mitre.org",
      "external_id": "CWE-308",
      "title": "Use of Single-factor Authentication",
      "url": "https://cwe.mitre.org/data/definitions/308.html"
    },
    {
      "system": "https://cwe.mitre.org",
      "external_id": "CWE-522",
      "title": "Insufficiently Protected Credentials",
      "url": "https://cwe.mitre.org/data/definitions/522.html"
    }
  ],
  "remediation": {
    "title": "Enforce SSH key-based authentication",
    "description": "Enable public key authentication for SSH and remove weaker authentication paths where operationally feasible.",
    "tasks": [
      { "title": "Set PubkeyAuthentication yes in sshd configuration" },
      { "title": "Provision and validate authorized keys for approved users" },
      { "title": "Disable PasswordAuthentication and keyboard-interactive methods unless explicitly required" },
      { "title": "Restrict SSH exposure to approved management networks" },
      { "title": "Reload/restart sshd and validate administrative access flows" }
    ]
  }
}]

violation[{"id": "ssh_require_public_key"}] if {
	not "yes" in input.pubkeyauthentication
}

title := "SSH should use key based authentication"
description := "Key based SSH authentication is considered secure. Key-based authentication should be used to secure remote access to sensitive hosts"
labels := {
    "severity": "medium"
}
