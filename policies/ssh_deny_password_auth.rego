package compliance_framework.deny_password_based_ssh

import future.keywords.in

risk_templates := [{
  "name": "SSH password authentication enabled",
  "title": "Weak SSH Authentication Exposure",
  "statement": "SSH password authentication permits interactive password-based remote access, increasing exposure to brute-force, password spraying, and credential stuffing attacks, especially on administrative interfaces.",
  "likelihood_hint": "high",
  "impact_hint": "high",
  "violation_ids": ["ssh_password_auth"],
  "threat_refs": [
    {
      "system": "https://cwe.mitre.org",
      "external_id": "CWE-309",
      "title": "Use of Password System for Primary Authentication",
      "url": "https://cwe.mitre.org/data/definitions/309.html"
    },
    {
      "system": "https://cwe.mitre.org",
      "external_id": "CWE-308",
      "title": "Use of Single-factor Authentication",
      "url": "https://cwe.mitre.org/data/definitions/308.html"
    },
    {
      "system": "https://cwe.mitre.org",
      "external_id": "CWE-307",
      "title": "Improper Restriction of Excessive Authentication Attempts",
      "url": "https://cwe.mitre.org/data/definitions/307.html"
    }
  ],
  "remediation": {
    "title": "Harden SSH authentication",
    "description": "Disable password-based SSH authentication for administrative access and require approved key-based authentication, with compensating controls where password auth cannot yet be removed.",
    "tasks": [
      { "title": "Set PasswordAuthentication no in sshd configuration" },
      { "title": "Ensure PubkeyAuthentication yes is configured" },
      { "title": "Review keyboard-interactive/challenge-response settings and disable if not required" },
      { "title": "Validate key-based access for authorized administrative accounts before service restart" },
      { "title": "Restrict SSH access to approved management networks or access paths" },
      { "title": "If password authentication must remain temporarily, enforce MFA and failed-attempt throttling/lockout controls" },
      { "title": "Reload or restart SSH daemon and re-test remote access" }
    ]
  }
}]

violation[{"id": "ssh_password_auth"}] if {
	"yes" in input.passwordauthentication
}

title := "SSH should disable password based authentication"
description := "Password-based SSH auth is insecure. Use key-based authentication for sensitive hosts."
labels := {
    "severity": "high"
}
