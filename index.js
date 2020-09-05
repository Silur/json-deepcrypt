const openpgp = require('openpgp')
const Joi = require('joi')
const jsonwalk = require('jsonwalk')
const sha256 = require('js-sha256').sha256

function b64encode (buf) {
  const binstr = Array.prototype.map.call(buf, function (ch) {
    return String.fromCharCode(ch)
  }).join('')
  if (typeof btoa === 'function') { return btoa(binstr) }

  return Buffer.from(binstr).toString('base64')
}

function b64decode (str) {
  if (typeof atob === 'undefined') {
    const ret = new Uint8Array(Buffer.from(str, 'base64')
      .toString().split('')
      .map(function (c) { return c.charCodeAt(0) }))
    return ret
  } else {
    const ret = new Uint8Array(atob(str).split('')
      .map(function (c) { return c.charCodeAt(0) }))
    return ret
  }
}

module.exports = {
  encrypt: async function (params) {
    if (params.data && typeof params.data === 'object') { params.data = JSON.stringify(params.data) }
    const paramValidator = Joi.object({
      data: Joi.string().required(),
      publicFields: Joi.array().items(Joi.string()).default([]),
      privateFields: Joi.array().items(Joi.string()).default([]),
      password: Joi.string(),
      salt: Joi.string().default(''),
      hmacKey: Joi.string(),
      pubKeys: Joi.array().items(Joi.string())
    })
    const {error, value} = paramValidator.validate(params)
    if (error) throw new Error(error)
    params = value
    if (params.publicFields.length === 0 && params.privateFields.length === 0) { throw new Error('Either privateFields or publicFields should be non-empty') }
    if (params.publicFields.length !== 0 && params.privateFields.length !== 0) { throw new Error('privateFields and publicFields should not be provided simultaneously') }
    async function inner (jsonKey, value) {
      // Use symmetric encryption
      if (!params.pubKeys) {
        if(!params.password || !params.salt) {
          throw new Error('password and salt is mandatory for symmetric mode')
        }
        const c = await openpgp.encrypt({
          message: openpgp.message.fromText(value),
          passwords: [params.password + params.salt],
          armor: false // we do this manually
        })
        const encoded = b64encode(c.message.packets.write())
        if (params.hmacKey) {
          const hmac = sha256.hmac(params.hmacKey, value)
          return `_data:${encoded};_hmac:${hmac}`
        }
        return `_data:${encoded}`
      } else {
        const publicKeys = await Promise.all(params.pubKeys.map(async (key) => {
          return (await openpgp.key.readArmored(key)).keys[0]
        }))
        const c = await openpgp.encrypt({
          message: openpgp.message.fromText(value),
          publicKeys,
          armor: false
        })
        const encoded = b64encode(c.message.packets.write())
        if (params.hmacKey) {
          const hmac = sha256.hmac(params.hmacKey, value)
          return `_data:${encoded};_hmac:${hmac}`
        }
        return `_data:${encoded}`
      }
    }
    const reverse = params.privateFields.length !== 0
    const ret = await jsonwalk.walk(JSON.parse(params.data),
      reverse ? params.privateFields : params.publicFields,
      inner, reverse)
    return ret
  },

  decrypt: async function (params) {
    if (params.data && typeof params.data === 'object') { params.data = JSON.stringify(params.data) }
    const paramValidator = Joi.object({
      data: Joi.string().required(),
      password: Joi.string().required(),
      publicFields: Joi.array().items(Joi.string()).default([]),
      privateFields: Joi.array().items(Joi.string()).default([]),
      salt: Joi.string().default(''),
      hmacKey: Joi.string(),
      privKey: Joi.string()
    })
    const {error, value} = paramValidator.validate(params)
    if (error) throw new Error(error)
    params = value
    if (params.publicFields.length === 0 && params.privateFields.length === 0) { throw new Error('Either privateFields or publicFields should be non-empty') }
    if (params.publicFields.length !== 0 && params.privateFields.length !== 0) { throw new Error('privateFields and publicFields should not be provided simultaneously') }
    async function inner (jsonKey, value) {
      if (value.match(/_data.*/) === null) {
        throw new Error(`${jsonKey} should have an encrypted _data part`)
      }
      const valueAndMac = value.split(';')
      if (valueAndMac.length === 0) { throw new Error('ciphertext format error') }

      value = valueAndMac[0].replace('_data:', '')
      if (!params.privKey) {
        if(!params.password || !params.salt) {
          throw new Error('password and salt is mandatory for symmetric mode')
        }
        const { data: decrypted } = await openpgp.decrypt({
          message: await openpgp.message.read(b64decode(value)),
          passwords: [params.password + params.salt],
          format: 'string'
        })
        if (params.hmacKey) {
          if (valueAndMac.length !== 2) { throw new Error('ciphertext does not contain a _hmac part') }
          const checkHmac = valueAndMac[1].replace('_hmac:', '')
          const actualMac = sha256.hmac(params.hmacKey, decrypted)
          if (checkHmac !== actualMac) {
            throw new Error('hmac verification error')
          }
        }
        return decrypted
      } else {
        const { keys: [privateKey] } = await openpgp.key.readArmored(params.privKey)
        await privateKey.decrypt(params.password)
        const { data: decrypted } = await openpgp.decrypt({
          message: await openpgp.message.read(b64decode(value)),
          privateKeys: privateKey,
          armor: false
        })
        if (params.hmacKey) {
          if (valueAndMac.length !== 2) { throw new Error('ciphertext does not contain a _hmac part') }
          const checkHmac = valueAndMac[1].replace('_hmac:', '')
          const actualMac = sha256.hmac(params.hmacKey, decrypted)
          if (checkHmac !== actualMac) {
            throw new Error('hmac verification error')
          }
        }
        return decrypted
      }
    }
    const reverse = params.privateFields.length !== 0
    const ret = await jsonwalk.walk(JSON.parse(params.data),
      reverse ? params.privateFields : params.publicFields,
      inner, reverse)
    return ret
  },
  walk: jsonwalk.walk
}
