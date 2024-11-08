package compliance_framework.local_ssh.deny_root_with_password

import future.keywords.in

violation[{"msg": msg}] {
	not "without-password" in input.permitrootlogin
	msg := "Root can login with password"
}
