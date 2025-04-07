package compliance_framework.require_key_based_ssh

test_ssh_password_off if {
    count(violation) == 0 with input as {
        "pubkeyauthentication": [
            "yes"
        ]
    }
}

test_ssh_password_on if {
    count(violation) == 1 with input as {
        "pubkeyauthentication": [
            "no"
        ]
    }
}
