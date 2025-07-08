package compliance_framework.deny_password_based_ssh

import future.keywords.in

violation[{}] if {
	"yes" in input.passwordauthentication
}

title := "SSH should disable password based authentication"
description := "Password based SSH authentication is considered insecure. Key-based authentication should be used to secure remote access to sensitive hosts"
labels := {
    "severity": "high"
}
