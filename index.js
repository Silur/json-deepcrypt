const openpgp = require('openpgp')
const Joi = require('joi')
const jsonwalk = require('jsonwalk')

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
    const paramValidator = Joi.object({
      data: Joi.string().required(),
      password: Joi.string().required(),
      salt: Joi.string().default(''),
      pubKeys: Joi.array().items(Joi.string())
    })
    const {error, value} = paramValidator.validate(params)
    if (error) throw new Error(error)
    params = value
    // Use symmetric encryption
    if (!params.pubKeys) {
      const c = await openpgp.encrypt({
        message: openpgp.message.fromText(params.data),
        passwords: [params.password + params.salt],
        armor: false // we do this manually
      })
      const encoded = b64encode(c.message.packets.write())
      return encoded
    } else {
      const publicKeys = await Promise.all(params.pubKeys.map(async (key) => {
        return (await openpgp.key.readArmored(key)).keys[0];
      }))
      const c = await openpgp.encrypt({
        message: openpgp.message.fromText(params.data),
        publicKeys,
        armor: false
      })
      const encoded = b64encode(c.message.packets.write())
      return encoded
    }
  },

  decrypt: async function (params) {
    const paramValidator = Joi.object({
      data: Joi.string().required(),
      password: Joi.string().required(),
      salt: Joi.string().default(''),
      privKey: Joi.string()
    })
    const {error, value} = paramValidator.validate(params)
    if (error) throw new Error(error)
    params = value
    if (!params.privKey) {
      const { data: decrypted } = await openpgp.decrypt({
        message: await openpgp.message.read(b64decode(params.data)),
        passwords: [params.password + params.salt],
        format: 'string'
      })
      return decrypted
    } else {
      const { keys: [privateKey] } = await openpgp.key.readArmored(params.privKey);
      await privateKey.decrypt(params.password)
      const { data: decrypted } = await openpgp.decrypt({
        message: await openpgp.message.read(b64decode(params.data)),
        privateKeys: privateKey,
        armor: false
      })
      return decrypted
    }
  },
  walk: jsonwalk.walk
}
