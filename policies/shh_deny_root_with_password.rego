# Ensure that the root account is not permitted to use password-based authentication, as this presents a severe security risk.
#
# METADATA
# title: Verify root login with password is disabled
# description: Verifies that the root account does not allow password-based authentication, ensuring stronger access control and reducing risks of brute-force attacks.
package compliance_framework.local_ssh.deny_root_with_password

import future.keywords.in

activities := [
    {
        "title": "Validate Root Login with Password Setting",
        "description": "Check that the SSH configuration does not allow the root account to log in using passwords.",
        "type": "evaluation",
        "steps": [
            "Parse SSHD configuration file",
            "Check if the `PermitRootLogin` key is present and set to 'without-password'.",
            "Flag a violation if the condition is not met."
        ],
        "tools": ["rego", "OPA"]
    },
]

risks := [
    {
        "title": "Privilege Escalation via Root Account",
        "description": "Allowing root to authenticate with a password exposes the system to brute-force attacks, enabling unauthorized privilege escalation.",
        "statement": "Restrict root authentication to key-based methods or certificates to prevent privilege escalation.",
        "links": [
            {
                "text": "Mitre Attack Reference",
                "href": "https://attack.mitre.org/techniques/T1078/"
            },
        ],
    },
    {
        "title": "Increased Likelihood of Host Compromise",
        "description": "Compromised root accounts can lead to full host control, potentially exposing sensitive data and disrupting operations.",
        "statement": "Disallow root login with passwords to minimize risk.",
        "links": [
            {
                "text": "Mitre Attack Reference",
                "href": "https://attack.mitre.org/techniques/T1110/"
            },
        ],
    },
    {
        "title": "Regulatory Non-Compliance",
        "description": "Permitting root login with passwords violates security best practices and regulatory requirements, such as NIST SP 800-53 AC-3, AC-6, and IA-5.",
        "statement": "Configure root authentication to comply with access control and identity management standards.",
        "links": [],
    },
    {
        "title": "Audit Findings and Security Penalties",
        "description": "Weak root authentication can lead to audit failures, reputational damage, and regulatory fines.",
        "statement": "Ensure compliance by disabling password-based root authentication.",
        "links": [],
    }
]

violation[{
    "title": "Root account should not be allowed to use password authentication",
    "description": "Root accounts using password is a severe security flaw, by which a brute force attack could gain elevated access to a host machine.",
    "remarks": "Remove password authentication from the root account, and use public keys or certificates as a stronger authentication method.",
    "control-implementations": [
        "AC-3",
        "AC-6",
        "IA-2",
        "IA-5",
        "SC-12",
        "CM-7",
        "SI-7",
    ]
}] {
    not "without-password" in input.permitrootlogin
}
