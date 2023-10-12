const bsv = require('babbage-bsv')
const isValidPublicKey = (key) => {
  try {
    bsv.PublicKey.fromString(key)
    return true
  } catch (error) {
    return false
  }
}
const isValidSignature = sig => {
  try {
    bsv.crypto.Signature.fromString(sig)
    return true
  } catch (e) {
    return false
  }
}
// Validate the 'shape' of the certificate
module.exports = (certificate) => {
  // Certificate must be an object
  if (typeof certificate !== 'object' || certificate === null) {
    const e = new Error('Certificate must be an object')
    e.code = 'ERR_AUTHRITE_MALFORMED_CERT'
    throw e
  }
  // Fields must be an object
  else if (typeof certificate.fields !== 'object' || certificate.fields === null) {
    const e = new Error('Certificate fields must be an object')
    e.code = 'ERR_AUTHRITE_CERT_MALFORMED_FIELDS'
    throw e
  }
  // At least one field is required
  else if (Object.keys(certificate.fields).length === 0) {
    const e = new Error('At least one certificate field is required')
    e.code = 'ERR_AUTHRITE_CERT_NO_FIELDS'
    throw e
  }
  // Subject is required
  else if (typeof certificate.subject !== 'string') {
    const e = new Error('A certificate subject is required')
    e.code = 'ERR_AUTHRITE_CERT_MISSING_SUBJECT'
    throw e
  }
  // Subject must be a valid public key
  else if (!isValidPublicKey(certificate.subject)) {
    const e = new Error('The certificate subject must be a valid public key')
    e.code = 'ERR_AUTHRITE_CERT_MALFORMED_SUBJECT'
    throw e
  }
  // Certifier is required
  else if (typeof certificate.certifier !== 'string') {
    const e = new Error('A certificate certifier is required')
    e.code = 'ERR_AUTHRITE_CERT_MISSING_CERTIFIER'
    throw e
  }
  // Certifier must be a valid public key
  else if (!isValidPublicKey(certificate.certifier)) {
    const e = new Error('The certificate certifier must be a valid public key')
    e.code = 'ERR_AUTHRITE_CERT_MALFORMED_CERTIFIER'
    throw e
  }
  // Validation key is required
  else if (typeof certificate.validationKey !== 'string') {
    const e = new Error('A certificate validation key is required')
    e.code = 'ERR_AUTHRITE_CERT_MISSING_VALIDATION_KEY'
    throw e
  }
  // Validation key must be the correct length (256 bits or 32 bytes)
  else if (Buffer.byteLength(certificate.validationKey, 'base64') !== 32) {
    const e = new Error('The certificate validation key must be the correct length (256 bits or 32 bytes)')
    e.code = 'ERR_AUTHRITE_CERT_MALFORMED_VALIDATION_KEY'
    throw e
  }
  // Type is required
  else if (typeof certificate.type !== 'string') {
    const e = new Error('A certificate type is required')
    e.code = 'ERR_AUTHRITE_CERT_MISSING_TYPE'
    throw e
  }
  // Type must be the correct length (256 bits, or 32 bytes)
  else if (Buffer.byteLength(certificate.type, 'base64') !== 32) {
    const e = new Error('The certificate type must be the correct length (256 bits, or 32 bytes)')
    e.code = 'ERR_AUTHRITE_CERT_MALFORMED_TYPE'
    throw e
  }
  // Serial number is required
  else if (typeof certificate.serialNumber !== 'string') {
    const e = new Error('A certificate serial number is required')
    e.code = 'ERR_AUTHRITE_CERT_MISSING_SERIAL_NUMBER'
    throw e
  }
  // Serial number must be correct length (256 bits or 32 bytes)
  else if (Buffer.byteLength(certificate.serialNumber, 'base64') !== 32) {
    const e = new Error('The certificate serial number must be correct length (256 bits or 32 bytes)')
    e.code = 'ERR_AUTHRITE_CERT_MALFORMED_SERIAL_NUMBERR'
    throw e
  }
  // Revocation outpoint is required
  else if (typeof certificate.revocationOutpoint !== 'string') {
    const e = new Error('A certificate revocation outpoint is required')
    e.code = 'ERR_AUTHRITE_CERT_MISSING_REVOCATION_OUTPOINT'
    throw e
  }
  // Revocation outpoint must be the correct length (36 bytes)
  else if (Buffer.byteLength(certificate.revocationOutpoint, 'hex') !== 36) {
    const e = new Error('The certificate revocation outpoint must be the correct length (36 bytes)')
    e.code = 'ERR_AUTHRITE_CERT_MALFORMED_REVOCATION_OUTPOINT'
    throw e
  }
  // Signature is required
  else if (typeof certificate.signature !== 'string') {
    const e = new Error('A certificate signature is required')
    e.code = 'ERR_AUTHRITE_CERT_MISSING_SIG'
    throw e
  }
  // Signature must be valid
  else if (!isValidSignature(certificate.signature)) {
    const e = new Error('The certificate signature is in an invalid format, it must be DER')
    e.code = 'ERR_AUTHRITE_CERT_MALFORMED_SIG'
    throw e
  }
  return true
}
