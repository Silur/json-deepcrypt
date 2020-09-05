# json-deepcrypt ![](https://img.shields.io/npm/v/json-deepcrypt)

A tool to recursively encrypt and optionally MAC specified fields of JSON data based on `jq`-like schemas. The codebase was originally intended to ease pinning of JSON-based stuff on blockchain but found other use cases. It uses [OpenPGP.js](https://openpgpjs.org/) under the hood

## Install

```bash
npm install -S json-deepcrypt
```

## Usage

### With AES256
```javascript
  const cipherText = await jsonDeepcrypt.encrypt({
    data: JSON.stringify(plainText),
    privateFields: ['Account.Order.$.OrderID'], // $ to wildcard array elements
    password: `thats my kung fu`,
    salt: `somesalt`
  })
  console.log(JSON.stringify(cipherText)) // you get an object as result
  const decrypted = await jsonDeepcrypt.decrypt({
    data: cipherText, // you can pass object or string too here
    privateFields: ['Account.Order.$.OrderID'],
    password: `thats my kung fu`,
    salt: `somesalt`
  })
  console.log(decrypted)
```

### With PKI

```javascript
const publicKeyArmored = `-----BEGIN PGP PUBLIC KEY BLOCK-----
...
-----END PGP PUBLIC KEY BLOCK-----`;
    const privateKeyArmored = `-----BEGIN PGP PRIVATE KEY BLOCK-----
...
-----END PGP PRIVATE KEY BLOCK-----`; // encrypted private key

const cipherText = await jsonDeepcrypt.encrypt({
    data: plainText, // ... or object
    privateFields: ['Account.Order.$.OrderID'],
    pubKeys: [publicKeyArmored] // you can encrypt to multiple keys!
  })
  console.log(JSON.stringify(cipherText))

  const decrypted = await jsonDeepcrypt.decrypt({
    data: cipherText,
    password: password,
    privateFields: ['Account.Order.$.OrderID'],
    privKey: privateKeyArmored
  })
  console.log(decrypted)
```

### With MAC verification
```javascript
  const cipherText = await jsonDeepcrypt.encrypt({
    data: JSON.stringify(plainText),
    privateFields: ['Account.Order.$.OrderID'],
    password: password,
    salt: 'somesalt',
    hmacKey: 'another key for the hmac'
  })
  console.log(JSON.stringify(cipherText))

  const decrypted = await jsonDeepcrypt.decrypt({
    data: JSON.stringify(cipherText),
    privateFields: ['Account.Order.$.OrderID'],
    password: password,
    salt: 'somesalt',
    hmacKey: 'another key for the hmac'
  })
  console.log(decrypted)
  
  const shouldFail = await jsonDeepcrypt.decrypt({
    data: JSON.stringify(cipherText),
    privateFields: ['Account.Order.$.OrderID'],
    password: password,
    salt: 'somesalt',
    hmacKey: 'wrong hmac breaks hashes'
  })
  // should throw an error
```

### Trivia

The data format for encrypted fields is:

- `_data:gq9kule12j6wMA...ayl5CeTPw5E=` with no HMAC
- `_data:gq9kule12j6wMA...ayl5CeTPw5E=;_hmac:2d17f4...85420c` with HMAC
