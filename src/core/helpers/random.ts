const crypto = require('crypto')
export const randomID = () => crypto.randomBytes(8).toString('hex')
