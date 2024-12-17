# Ensure that SSH password are never used on host machines, as this is insecure to brute force attacks,
# unless paired with something like fail2ban.
#
# METADATA
# title: Verify password authentication is disabled
# description: Verifies that password authentication is not enabled for ssh on a machine. This helps prevent unauthorised brute force attacks.
package compliance_framework.local_ssh.deny_password_auth

import future.keywords.in

activities := [
    {
        "title": "Validate PasswordAuthentication Setting",
        "description": "Verify that the SSH configuration does not allow password-based authentication.",
        "type": "evaluation",
        "steps": [
            "Parse SSHD configuration file",
            "Check if the `PasswordAuthentication` key is present and set to 'yes'.",
            "Flag a violation if the condition is met."
        ],
        "tools": ["rego", "OPA"]
    },
]

risks := [
    {
        "title": "Unauthorized Access via Credential-Based Attacks",
        "description": "Password-based authentication increases susceptibility to brute-force, credential-stuffing, and dictionary attacks.",
        "statement": "Password authentication should be disabled to prevent unauthorized access to the system.",
        "links": [
            {
                "text": "Mitre Attack Reference",
                "href": "https://attack.mitre.org/techniques/T1110/"
            },
        ],
    },
    {
        "title": "Data Exfiltration through Compromised Credentials",
        "description": "An attacker gaining access via weak or reused passwords can exfiltrate sensitive or regulated data.",
        "statement": "Switch to key-based authentication to protect against unauthorized data access.",
        "links": [
            {
                "text": "Mitre Attack Reference",
                "href": "https://attack.mitre.org/techniques/T1003/"
            },
        ],
    },
    {
        "title": "Regulatory Non-Compliance",
        "description": "Use of insecure authentication methods violates standards like NIST SP 800-53 IA-2, IA-5, and AC-17.",
        "statement": "Ensure SSH configurations align with regulatory requirements to pass audits.",
        "links": [],
    },
    {
        "title": "Audit Failures and Penalties",
        "description": "Weak SSH configurations can lead to audit findings, resulting in penalties, fines, or reputational harm.",
        "statement": "Disable password authentication to satisfy audit requirements.",
        "links": [],
    },
    {
        "title": "Operational Disruption Due to Compromise",
        "description": "Compromised SSH systems can lead to ransomware attacks, service interruptions, or unauthorized changes.",
        "statement": "Adopt robust SSH security practices to maintain system integrity and availability.",
        "links": [
            {
                "text": "Mitre Attack Reference",
                "href": "https://attack.mitre.org/techniques/T1078/"
            },
        ],
    }
]

violation[{
    "title": "Host SSH is using password authentication.",
    "description": "Host SSH should not use password, as this is insecure to brute force attacks from external sources.",
    "remarks": "Migrate to using SSH Public Keys, and switch off password authentication.",
    "control-implementations": [
        "AC-2",
        "AC-17",
        "IA-2",
        "IA-5",
        "SC-12",
        "CM-7",
        "SI-7",
    ]
}] {
	"yes" in input.passwordauthentication
}
