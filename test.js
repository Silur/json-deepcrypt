const jsonEncrypt = require('./index.js')
const assert = require('assert')
const expect = require('chai').expect
const openpgp = require('openpgp')

const plainText = {
  "Account": {
    "Account Name": "Firefly",
    "Order": [
      {
        "OrderID": "order103",
        "Product": [
          {
            "Product Name": "Bowler Hat",
            "ProductID": 858383,
            "SKU": "0406654608",
            "Description": {
              "Colour": "Purple",
              "Width": 300,
              "Height": 200,
              "Depth": 210,
              "Weight": 0.75
            },
            "Price": 34.45,
            "Quantity": 2
          },
          {
            "Product Name": "Trilby hat",
            "ProductID": 858236,
            "SKU": "0406634348",
            "Description": {
              "Colour": "Orange",
              "Width": 300,
              "Height": 200,
              "Depth": 210,
              "Weight": 0.6
            },
            "Price": 21.67,
            "Quantity": 1
          }
        ]
      },
      {
        "OrderID": "order104",
        "Product": [
          {
            "Product Name": "Bowler Hat",
            "ProductID": 858383,
            "SKU": "040657863",
            "Description": {
              "Colour": "Purple",
              "Width": 300,
              "Height": 200,
              "Depth": 210,
              "Weight": 0.75
            },
            "Price": 34.45,
            "Quantity": 4
          },
          {
            "ProductID": 345664,
            "SKU": "0406654603",
            "Product Name": "Cloak",
            "Description": {
              "Colour": "Black",
              "Width": 30,
              "Height": 20,
              "Depth": 210,
              "Weight": 2
            },
            "Price": 107.99,
            "Quantity": 1
          }
        ]
      }
    ]
  }
}

const encryptSchema = ['Account.Order.$.OrderID']

const password = 'thats my kung fu'
const salt = ''

it('AES256 encrypt without salt', async function () {
  const cipherText = await jsonEncrypt.encrypt({
    data: JSON.stringify(plainText),
    password: password
  })
  const decrypted = await jsonEncrypt.decrypt({
    data: cipherText,
    password: password
  })
  expect(JSON.parse(decrypted)).to.deep.equal(plainText)
})

it('AES256 encrypt with salt', async function () {
  const cipherText = await jsonEncrypt.encrypt({
    data: JSON.stringify(plainText),
    password: password,
    salt: 'somesalt'
  })
  const decrypted = await jsonEncrypt.decrypt({
    data: cipherText,
    password: password,
    salt: 'somesalt'
  })
  expect(JSON.parse(decrypted)).to.deep.equal(plainText)
})

it('EC encrypt with single key', async function () {
  const { privateKeyArmored,
    publicKeyArmored } = await openpgp.generateKey({
      userIds: [{ name: 'Alice', email: 'alice@example.com' }],
      curve: 'ed25519',
      passphrase: password
    })
  const cipherText = await jsonEncrypt.encrypt({
    data: JSON.stringify(plainText),
    password: password,
    pubKeys: [publicKeyArmored]
  })
  const decrypted = await jsonEncrypt.decrypt({
    data: cipherText,
    password: password,
    privKey: privateKeyArmored
  })
  expect(JSON.parse(decrypted)).to.deep.equal(plainText)
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
    data: JSON.stringify(plainText),
    password: password,
    pubKeys: [key1.publicKeyArmored, key2.publicKeyArmored]
  })
  const decrypted = await jsonEncrypt.decrypt({
    data: cipherText,
    password: password,
    privKey: key1.privateKeyArmored
  })
  expect(JSON.parse(decrypted)).to.deep.equal(plainText)
})

it('RSA encrypt with single key', async function () {
  const { privateKeyArmored,
    publicKeyArmored } = await openpgp.generateKey({
      userIds: [{ name: 'Alice', email: 'alice@example.com' }],
      rsaBits: 1024,
      passphrase: password
    })
  const cipherText = await jsonEncrypt.encrypt({
    data: JSON.stringify(plainText),
    password: password,
    pubKeys: [publicKeyArmored]
  })
  const decrypted = await jsonEncrypt.decrypt({
    data: cipherText,
    password: password,
    privKey: privateKeyArmored
  })
  expect(JSON.parse(decrypted)).to.deep.equal(plainText)
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
    data: JSON.stringify(plainText),
    password: password,
    pubKeys: [key1.publicKeyArmored, key2.publicKeyArmored]
  })
  const decrypted = await jsonEncrypt.decrypt({
    data: cipherText,
    password: password,
    privKey: key1.privateKeyArmored
  })
  expect(JSON.parse(decrypted)).to.deep.equal(plainText)
})

function mapOperation(obj, index, element) {
  return element
}

it('Walk JSON', function () {
  jsonEncrypt.walk(plainText, encryptSchema, mapOperation)
})
