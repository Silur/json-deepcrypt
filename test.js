const jsonEncrypt = require('./index.js')
const assert = require('assert')
const expect = require('chai').expect
const openpgp = require('openpgp')

const plainText = {
  'glossary': {
    'title': 'example glossary',
    'GlossDiv': {
      'title': 'S',
      'GlossList': {
        'GlossEntry': {
          'ID': 'SGML',
          'SortAs': 'SGML',
          'GlossTerm': 'Standard Generalized Markup Language',
          'Acronym': 'SGML',
          'Abbrev': 'ISO 8879:1986',
          'GlossDef': {
            'para': 'A meta-markup language, used to create markup languages such as DocBook.',
            'GlossSeeAlso': ['GML', 'XML']
          },
          'GlossSee': 'markup'
        }
      }
    }
  }
}

const encryptSchema = [
  'glossary'
]

const password = 'thats my kung fu'
const salt = ''

it('AES256 encrypt without salt', async function () {
  const cipherText = await jsonEncrypt.encrypt({
    data: JSON.stringify(plainText.glossary),
    password: password
  })
  const decrypted = await jsonEncrypt.decrypt({
    data: cipherText,
    password: password
  })
  expect(JSON.parse(decrypted)).to.deep.equal(plainText.glossary)
})

it('AES256 encrypt with salt', async function () {
  const cipherText = await jsonEncrypt.encrypt({
    data: JSON.stringify(plainText.glossary),
    password: password,
    salt: 'somesalt'
  })
  const decrypted = await jsonEncrypt.decrypt({
    data: cipherText,
    password: password,
    salt: 'somesalt'
  })
  expect(JSON.parse(decrypted)).to.deep.equal(plainText.glossary)
})

it('EC encrypt with single key', async function () {
  const { privateKeyArmored,
    publicKeyArmored } = await openpgp.generateKey({
    userIds: [{ name: 'Alice', email: 'alice@example.com' }],
    curve: 'ed25519',
    passphrase: password
  })
  const cipherText = await jsonEncrypt.encrypt({
    data: JSON.stringify(plainText.glossary),
    password: password,
    pubKeys: [publicKeyArmored]
  })
  const decrypted = await jsonEncrypt.decrypt({
    data: cipherText,
    password: password,
    privKey: privateKeyArmored
  })
  expect(JSON.parse(decrypted)).to.deep.equal(plainText.glossary)
})

it('EC encrypt with multiple keys', async function () {
  const key1 = await openpgp.generateKey({
    userIds: [{ name: 'Alice', email: 'alice@example.com' }],
    curve: 'ed25519',
    passphrase: password
  })
  const key2 = await openpgp.generateKey({
    userIds: [{ name: 'Bob', email: 'bob@example.com' }],
    curve: 'ed25519',
    passphrase: 'something else Alice doesn\'t know'
  })
  const cipherText = await jsonEncrypt.encrypt({
    data: JSON.stringify(plainText.glossary),
    password: password,
    pubKeys: [key1.publicKeyArmored, key2.publicKeyArmored]
  })
  const decrypted = await jsonEncrypt.decrypt({
    data: cipherText,
    password: password,
    privKey: key1.privateKeyArmored
  })
  expect(JSON.parse(decrypted)).to.deep.equal(plainText.glossary)
})

it('RSA encrypt with single key', async function () {
  const { privateKeyArmored,
    publicKeyArmored } = await openpgp.generateKey({
    userIds: [{ name: 'Alice', email: 'alice@example.com' }],
    rsaBits: 1024,
    passphrase: password
  })
  const cipherText = await jsonEncrypt.encrypt({
    data: JSON.stringify(plainText.glossary),
    password: password,
    pubKeys: [publicKeyArmored]
  })
  const decrypted = await jsonEncrypt.decrypt({
    data: cipherText,
    password: password,
    privKey: privateKeyArmored
  })
  expect(JSON.parse(decrypted)).to.deep.equal(plainText.glossary)
})

it('RSA encrypt with multiple keys', async function () {
  const key1 = await openpgp.generateKey({
    userIds: [{ name: 'Alice', email: 'alice@example.com' }],
    rsaBits: 1024,
    passphrase: password
  })
  const key2 = await openpgp.generateKey({
    userIds: [{ name: 'Bob', email: 'bob@example.com' }],
    curve: 'ed25519',
    passphrase: 'something else Alice doesn\'t know'
  })
  const cipherText = await jsonEncrypt.encrypt({
    data: JSON.stringify(plainText.glossary),
    password: password,
    pubKeys: [key1.publicKeyArmored, key2.publicKeyArmored]
  })
  const decrypted = await jsonEncrypt.decrypt({
    data: cipherText,
    password: password,
    privKey: key1.privateKeyArmored
  })
  expect(JSON.parse(decrypted)).to.deep.equal(plainText.glossary)
})
