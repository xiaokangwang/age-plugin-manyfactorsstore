# Many Factor Store

This plugin is a fork of https://github.com/FiloSottile/typage/blob/main/fido2prf/cmd/age-plugin-fido2prf/main.go
with modifications to support additional use cases. Its file format is different from the original.

This plugin allows you to use multiple factors for encryption and decryption with age.
It supports the following factors:
- FIDO2 security keys (e.g., Yubikey, SoloKey)
- Password (per file)
- PIN (on the security key)

5 layers of security:

1. Security key
2. PIN on the security key
3. Security key identity handle
4. Password (per file)
5. Touch on the security key

## How to use

Generate a key:

```bash
age-plugin-manyfactorstore-t6uh9av7whdoa00qwl18w3ggab6pycd1h8v3 -generate "ManyFactor" -name "testkey" -options "touch,pin,password" > identity
```

encrypt a file:

```bash
echo "HelloWorld"|age -e -i identity -a > encrypted
```

decrypt a file:

```bash
cat encrypted|age -d -i  identity
``` 

## Options

The options are comma-separated and can include any of the following:
Not all options are supported, or omittable on all keys.

- `touch`: require a touch on the security key
- `pin`: require a pin on the security key
- `password`: require a password to encrypt/decrypt