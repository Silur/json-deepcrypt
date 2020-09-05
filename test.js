const jsonEncrypt = require('./index.js')
const expect = require('chai').expect
const openpgp = require('openpgp')

const plainText = {
  'Account': {
    'Account Name': 'Firefly',
    'Order': [
      {
        'OrderID': 'order103',
        'Product': [
          {
            'Product Name': 'Bowler Hat',
            'ProductID': 858383,
            'SKU': '0406654608',
            'Description': {
              'Colour': 'Purple',
              'Width': 300,
              'Height': 200,
              'Depth': 210,
              'Weight': 0.75
            },
            'Price': 34.45,
            'Quantity': 2
          },
          {
            'Product Name': 'Trilby hat',
            'ProductID': 858236,
            'SKU': '0406634348',
            'Description': {
              'Colour': 'Orange',
              'Width': 300,
              'Height': 200,
              'Depth': 210,
              'Weight': 0.6
            },
            'Price': 21.67,
            'Quantity': 1
          }
        ]
      },
      {
        'OrderID': 'order104',
        'Product': [
          {
            'Product Name': 'Bowler Hat',
            'ProductID': 858383,
            'SKU': '040657863',
            'Description': {
              'Colour': 'Purple',
              'Width': 300,
              'Height': 200,
              'Depth': 210,
              'Weight': 0.75
            },
            'Price': 34.45,
            'Quantity': 4
          },
          {
            'ProductID': 345664,
            'SKU': '0406654603',
            'Product Name': 'Cloak',
            'Description': {
              'Colour': 'Black',
              'Width': 30,
              'Height': 20,
              'Depth': 210,
              'Weight': 2
            },
            'Price': 107.99,
            'Quantity': 1
          }
        ]
      }
    ]
  }
}

const password = 'thats my kung fu'

it('AES256 encrypt with salt', async function () {
  const cipherText = await jsonEncrypt.encrypt({
    data: JSON.stringify(plainText),
    password: password,
    privateFields: ['Account.Order.$.OrderID'],
    salt: 'somesalt'
  })
  const decrypted = await jsonEncrypt.decrypt({
    data: cipherText,
    password: password,
    privateFields: ['Account.Order.$.OrderID'],
    salt: 'somesalt'
  })
  expect(decrypted).to.deep.equal(plainText)
})

it('AES256 encrypt with salt and HMAC', async function () {
  const cipherText = await jsonEncrypt.encrypt({
    data: JSON.stringify(plainText),
    privateFields: ['Account.Order.$.OrderID'],
    password: password,
    salt: 'somesalt',
    hmacKey: 'another key for the hmac'
  })
  const decrypted = await jsonEncrypt.decrypt({
    data: JSON.stringify(cipherText),
    privateFields: ['Account.Order.$.OrderID'],
    password: password,
    salt: 'somesalt',
    hmacKey: 'another key for the hmac'
  })
  expect(decrypted).to.deep.equal(plainText)
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
    privateFields: ['Account.Order.$.OrderID'],
    pubKeys: [publicKeyArmored]
  })
  const decrypted = await jsonEncrypt.decrypt({
    data: cipherText,
    password: password,
    privateFields: ['Account.Order.$.OrderID'],
    privKey: privateKeyArmored
  })
  expect(decrypted).to.deep.equal(plainText)
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
    privateFields: ['Account.Order.$.OrderID'],
    pubKeys: [key1.publicKeyArmored, key2.publicKeyArmored]
  })
  const decrypted = await jsonEncrypt.decrypt({
    data: cipherText,
    password: password,
    privateFields: ['Account.Order.$.OrderID'],
    privKey: key1.privateKeyArmored
  })
  expect(decrypted).to.deep.equal(plainText)
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
    privateFields: ['Account.Order.$.OrderID'],
    pubKeys: [publicKeyArmored]
  })
  const decrypted = await jsonEncrypt.decrypt({
    data: cipherText,
    password: password,
    privateFields: ['Account.Order.$.OrderID'],
    privKey: privateKeyArmored
  })
  expect(decrypted).to.deep.equal(plainText)
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
    privateFields: ['Account.Order.$.OrderID'],
    pubKeys: [key1.publicKeyArmored, key2.publicKeyArmored]
  })
  const decrypted = await jsonEncrypt.decrypt({
    data: cipherText,
    password: password,
    privateFields: ['Account.Order.$.OrderID'],
    privKey: key1.privateKeyArmored
  })
  expect(decrypted).to.deep.equal(plainText)
})

it('Encrypt with public fields (all encrypted by default)', async function () {
  const cipherText = await jsonEncrypt.encrypt({
    data: JSON.stringify(plainText),
    publicFields: ['Account.Order.$.OrderID'],
    password: password
  })
  const decrypted = await jsonEncrypt.decrypt({
    data: JSON.stringify(cipherText),
    publicFields: ['Account.Order.$.OrderID'],
    password: password
  })
  expect(cipherText.Account.Order[0].Product[0].ProductID).to.equal(858383)
  expect(cipherText.Account.Order[0].OrderID).to.be.an('string')
  expect(decrypted).to.deep.equal(plainText)
})
