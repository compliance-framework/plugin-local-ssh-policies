# Ensure that SSH password are never used on host machines, as this is insecure to brute force attacks,
# unless paired with something like fail2ban.
#
# METADATA
# title: Verify password authentication is disabled
# description: Verifies that password authentication is not enabled for ssh on a machine. This helps prevent unauthorised brute force attacks.
# custom:
#   controls:
#     - AC-1
#   schedule: "* * * * * *"
package compliance_framework.local_ssh.deny_password_auth

import future.keywords.in

violation[{
    "title": "Host SSH is using password authentication.",
    "description": "Host SSH should not use password, as this is insecure to brute force attacks from external sources.",
    "remarks": "Migrate to using SSH Public Keys, and switch off password authentication."
}] if {
	"yes" in input.passwordauthentication
}
