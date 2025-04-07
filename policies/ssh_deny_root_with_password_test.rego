package compliance_framework.deny_password_based_root_ssh

test_ssh_password_off if {
    count(violation) == 0 with input as {
        "permitrootlogin": [
            "without-password"
        ]
    }
}

test_ssh_password_on if {
    count(violation) == 1 with input as {
        "permitrootlogin": []
    }
}
