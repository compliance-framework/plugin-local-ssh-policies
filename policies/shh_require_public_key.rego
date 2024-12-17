# Ensure that SSH public key authentication is enabled on host machines, as this provides a secure method of authentication,
# reducing the risk of brute force and credential-based attacks.
#
# METADATA
# title: Verify public key authentication is enabled
# description: Verifies that public key authentication is enabled for SSH on a machine. This ensures secure and robust access control, mitigating risks of unauthorized access.
package compliance_framework.local_ssh.ensure_public_key_auth

import future.keywords.in

activities := [
    {
        "title": "Validate PubkeyAuthentication Setting",
        "description": "Verify that the SSH configuration allows public key-based authentication.",
        "type": "evaluation",
        "steps": [
            "Parse SSHD configuration file",
            "Check if the `PubkeyAuthentication` key is present and set to 'yes'.",
            "Flag a violation if the condition is not met."
        ],
        "tools": ["rego", "OPA"]
    },
]

risks := [
    {
        "title": "Unauthorized Access via Weak Authentication",
        "description": "Without public key authentication, the system is reliant on less secure methods such as password-based authentication.",
        "statement": "Enable public key authentication to prevent unauthorized access and strengthen security.",
        "links": [],
    },
    {
        "title": "Regulatory Non-Compliance",
        "description": "Failing to enable secure authentication methods like public key authentication can violate standards such as NIST SP 800-53 IA-2 and IA-5.",
        "statement": "Ensure public key authentication is configured to meet regulatory requirements.",
        "links": [],
    },
    {
        "title": "Increased Risk of Credential Compromise",
        "description": "Systems without public key authentication are more susceptible to credential theft or brute force attacks.",
        "statement": "Mitigate risks by enabling public key authentication as the primary method of SSH access.",
        "links": [
            {
                "text": "Mitre Attack Reference",
                "href": "https://attack.mitre.org/techniques/T1110/"
            }
        ],
    }
]

violation[{
    "title": "Host SSH is not using public key authentication.",
    "description": "Host SSH should enable public key authentication, as it provides a secure alternative to password-based authentication.",
    "remarks": "Ensure `PubkeyAuthentication` is set to 'yes' in the SSH configuration file.",
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
    not "yes" in input.pubkeyauthentication
}
