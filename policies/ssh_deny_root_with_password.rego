package compliance_framework.deny_password_based_root_ssh

import future.keywords.in

violation[{}] if {
	not "without-password" in input.permitrootlogin
}

title := "Root account should not use password authentication"
description := "Root accounts using password is a severe security flaw, by which a brute force attack could gain elevated access to a host machine."
labels := {
    "severity": "high"
}
