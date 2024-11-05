package compliance_framework.remote_ssh.require_public_key

import future.keywords.in

violation[{"msg": msg}] {
	not "yes" in input.pubkeyauthentication
	msg := "Host SSH should use public key authentication"
}
