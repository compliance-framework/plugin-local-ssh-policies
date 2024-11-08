# METADATA
# title: Verify password authentication is disabled
# description: Verifies that password authentication is not enabled for ssh on a machine. This helps prevent unauthorised brute force attacks.
package compliance_framework.local_ssh.deny_password_auth

import future.keywords.in

violation[{"msg": msg}] {
	"yes" in input.passwordauthentication
	msg := "Host SSH should not allow the use of password authentication. Set `passwordauthentication` to `no`"
}
