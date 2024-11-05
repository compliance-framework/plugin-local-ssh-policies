# METADATA
# cf_enabled: true
# title: Ensure SSH hosts have password authentication disabled
# description: SSH hosts should never use password authentication, as this is suseptable to brute force attacks. Public Keys, Certificates and Multi Factor Authentication should be preferred.
# controls:
# - IA-2
package ssh.deny_root_with_password

import future.keywords.in

violation[{"msg": msg}] {
	not "without-password" in input.permitrootlogin
	msg := "Host SSH should not allow the use of password authentication. Set `passwordauthentication` to `no`"
}
