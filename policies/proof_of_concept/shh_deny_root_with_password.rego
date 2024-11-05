package compliance_framework.remote_ssh.deny_root_with_password

import future.keywords.in

violation[{"msg": msg}] {
	not "without-password" in input.permitrootlogin
	msg := "Host SSH should not allow the use of password authentication. Set `passwordauthentication` to `no`"
}
