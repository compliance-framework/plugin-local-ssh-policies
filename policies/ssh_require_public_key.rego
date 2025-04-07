package compliance_framework.require_key_based_ssh

import future.keywords.in

violation[{}] if {
	not "yes" in input.pubkeyauthentication
}

title := "SSH should use key based authentication"
description := "Key based SSH authentication is considered secure. Key-based authentication should be used to secure remote access to sensitive hosts"
controls := [
    # SAMA Cyber Security Framework v1.0
    # https://rulebook.sama.gov.sa/en/cyber-security-framework-2
    # Class: SAMA_CSF_1.0
    #
    # 3.3: Cyber Security Operations and Technology
    # https://rulebook.sama.gov.sa/en/33-cyber-security-operations-and-technology-0
    {
        "class": "SAMA_CSF_1.0",
        "control-id": "3.3.5", # Identity and Access Management https://rulebook.sama.gov.sa/en/335-identity-and-access-management-0
        "statement-ids": [
            "2",
        ],
    },
    {
        "class": "SAMA_CSF_1.0",
        "control-id": "3.3.8", # Infrastructure Security https://rulebook.sama.gov.sa/en/338-infrastructure-security-0
        "statement-ids": [
            "2",
            "4",
            "5",
            "6.a",
            "6.d",
            "6.j",
        ],
    },
    {
        "class": "SAMA_CSF_1.0",
        "control-id": "3.3.9", # Cryptography https://rulebook.sama.gov.sa/en/339-cryptography-0
        "statement-ids": [
            "1",
            "2",
            "3",
            "4.a",
            "4.c",
        ],
    },
    # SAMA Information Technology Governance Framework v1.0
    # https://rulebook.sama.gov.sa/en/information-technology-governance-framework
    # Class: SAMA_ITGF_1.0
    #
    # 3.3: Operations Management
    # https://rulebook.sama.gov.sa/en/33-operations-management
    {
        "class": "SAMA_ITGF_1.0",
        "control-id": "3.3.6", # Network Architecture and Monitoring https://rulebook.sama.gov.sa/en/336-network-architecture-and-monitoring
        "statement-ids": [
            "2.p",
        ],
    },
    {
        "class": "SAMA_ITGF_1.0",
        "control-id": "3.3.11", # Virtualization https://rulebook.sama.gov.sa/en/3311-virtualization
        "statement-ids": [
            "2",
        ],
    },
    # SAMA Cyber Resilience Fundamental Requirements v1.0
    # https://rulebook.sama.gov.sa/en/32-cyber-security-operations-and-technology
    # Class: SAMA_CRFR_1.0
    #
    # 3.2: Cyber Security Operations and Technology
    {
        "class": "SAMA_CRFR_1.0",
        # 3.2.1:
        # Entities should establish identity and access management process to govern the logical accesses
        # to the information assets according to need-to-have and need-to-know principles.
        "control-id": "3.2.1",
    },
    {
        "class": "SAMA_CRFR_1.0", # SAMA Cyber Resilience Fundamental Requirements v1.0
        # 3.2.1:
        # Entities should adopt secure and robust cryptography algorithms and ensure that the application
        # and server communications are encrypted using secure protocols.
        "control-id": "3.2.4",
    },
    {
        "class": "SAMA_CRFR_1.0", # SAMA Cyber Resilience Fundamental Requirements v1.0
        # 3.2.1:
        # Entities should adopt secure and robust cryptography algorithms and ensure that the application
        # and server communications are encrypted using secure protocols.
        "control-id": "3.2.4",
    },
    {
        "class": "SAMA_CRFR_1.0", # SAMA Cyber Resilience Fundamental Requirements v1.0
        # 3.2.1:
        # Entities should implement session timeout configurations with reasonable timeframe; in-active
        # sessions should not exceed 5 minutes for applications and underlying infrastructure.
        "control-id": "3.2.15",
    },
]
