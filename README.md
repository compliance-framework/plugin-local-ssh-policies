# SSH policies for use in Compliance Framework

## Validating Metadata for Compliance Framework

```shell
concom verify -p policies/
```

## Testing

```shell
opa test policies
```

### Writing policies.

Policies are written in the [Rego](https://www.openpolicyagent.org/docs/latest/policy-language/) language.

```rego
package ssh.deny_password_auth

import future.keywords.in

violation[{"msg": msg}] {
	"yes" in input.passwordauthentication
	msg := "Host SSH should not allow the use of password authentication. Set `passwordauthentication` to `no`"
}
```
