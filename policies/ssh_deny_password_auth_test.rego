package compliance_framework.deny_password_based_ssh

test_deny_password_auth_off if {
    count(violation) == 0 with input as {
        "passwordauthentication": [
            "no"
        ]
    }
}

test_deny_password_auth_on if {
    count(violation) == 1 with input as {
        "passwordauthentication": [
            "yes"
        ]
    }
}
