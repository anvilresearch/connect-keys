# NOTICE

We’re archiving Anvil Connect and all related packages. This code is entirely MIT Licensed. You’re free to do with it what you want. That said, we are recommending _**against**_ using it, due to the potential for security issues arising from unmaintained software. For more information, see the announcement at [anvil.io](https://anvil.io).

# connect-keys
[![Build Status](https://travis-ci.org/anvilresearch/connect-keys.svg?branch=master)](https://travis-ci.org/anvilresearch/connect-keys)

Key pair utilities shared between the Anvil Connect server and its CLI

## Methods

### Static

#### AnvilConnectKeys.generateKeyPair(publicKeyPath, privateKeyPath)
Generates a 4096-bit RSA key pair, with the given public and private key paths.

#### AnvilConnectKeys.loadKeyPair(publicKeyPath, privateKeyPath, keyUse)
Loads an RSA key pair, with the given public and private key paths. Provides the
public and private keys both as raw PEM data, and the public key as a JWK. The
`keyUse` parameter corresponds to the `use` property on the JWK.

```json
{
  "pem": {
    "pub": "Public PEM key contents",
    "prv": "Private PEM key contents"
  },
  "jwk": {
    "pub": {
      "kty": "RSA",
      "use": "keyUse",
      "alg": "RS256",
      "n": "modulus",
      "e": "exponent"
    }
  }
}
```

#### AnvilConnectKeys.generateSetupToken(tokenPath)
Generates a random 256-byte hash and saves it to `tokenPath` using the UTF-8
encoding. Returns the generated token as a string.

#### AnvilConnectKeys.loadSetupToken(tokenPath)
Returns the contents of the file at `tokenPath` as a string, decoded using the
UTF-8 encoding.

### Instance

#### new AnvilConnectKeys()
Returns a new instance of AnvilConnectKeys scoped to a `keys` folder in the
current working directory.

#### new AnvilConnectKeys(path)
Returns a new instance of AnvilConnectKeys scoped to a `keys` folder in the
given path.

#### instance.generateKeyPairs()
Generates both signing and encryption key pairs in the scoped path.

File name | Key
--------- | ---
sig.rsa.pub.pem | Public signing key
sig.rsa.prv.pem | Private signing key
enc.rsa.pub.pem | Public encryption key
enc.rsa.prv.pem | Private encryption key

#### instance.loadKeyPairs()
Loads both signing and encryption key pairs from the scoped path.

```json
{
  "sig": {
    "pub": "Public signing PEM key contents",
    "prv": "Private signing PEM key contents"
  },
  "enc": {
    "pub": "Public encryption PEM key contents",
    "prv": "Private encryption PEM key contents"
  },
  "jwks": {
    "keys": [
      {
        "kty": "RSA",
        "use": "sig",
        "alg": "RS256",
        "n": "modulus",
        "e": "exponent"
      },
      {
        "kty": "RSA",
        "use": "enc",
        "alg": "RS256",
        "n": "modulus",
        "e": "exponent"
      }
    ]
  }
}
```

#### instance.generateSetupToken()
Generates a random 256-byte hash and saves it to the scoped path as
`setup.token` using the UTF-8 encoding. Returns the generated token as a string.

#### instance.loadSetupToken()
Returns the contents of the `setup.token` file in the scoped path as a string,
decoded using the UTF-8 encoding.
