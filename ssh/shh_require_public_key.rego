# METADATA
# cf_enabled: true
# title: Ensure SSH hosts have password authentication disabled
# description: SSH hosts should never use password authentication, as this is suseptable to brute force attacks. Public Keys, Certificates and Multi Factor Authentication should be preferred.
# controls:
# - IA-2
package ssh.require_public_key

import future.keywords.in

violation[{"msg": msg}] {
	not "yes" in input.pubkeyauthentication
	msg := "Host SSH should use public key authentication"
}
