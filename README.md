# SSH policies for use in Compliance Framework Local SSH Plugin

## Requirements

Install [opa](https://www.openpolicyagent.org/docs/latest/#running-opa) for testing & building the bundles.

## Testing

```shell
make test
```

## Bundling

Policies are built into bundle to make distribution easier. 

You can easily build the policies by running 
```shell
make build
```

## Running policies locally

```shell
opa eval -I -b policies -f pretty data.compliance_framework <<EOF 
{
  "passwordauthentication": [
    "yes"
  ],
  "permitrootlogin": [
    "with-password"
  ],
  "pubkeyauthentication": [
    "no"
  ]
}
EOF
```

## Writing policies.

Policies are written in the [Rego](https://www.openpolicyagent.org/docs/latest/policy-language/) language.

```rego
package compliance_framework.deny_password_auth

import future.keywords.in

violation[{}] {
	"yes" in input.passwordauthentication
}

title := "SSH should disable password based authentication"
description := "Password based SSH authentication is considered insecure. Key-based authentication should be used to secure remote access to sensitive hosts"
labels := {
    "severity": "high"
}
```
