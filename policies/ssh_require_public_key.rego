package compliance_framework.require_key_based_ssh

import future.keywords.in

violation[{}] if {
	not "yes" in input.pubkeyauthentication
}

title := "SSH should use key based authentication"
description := "Key based SSH authentication is considered secure. Key-based authentication should be used to secure remote access to sensitive hosts"
labels := {
    "severity": "medium"
}
