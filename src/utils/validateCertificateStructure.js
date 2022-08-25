const bsv = require('bsv')
const isValidPublicKey = (key) => {
  try {
    bsv.PublicKey.fromString(key)
  } catch (error) {
    return false
  }
  return true
}
// Validate the 'shape' of the certificate
module.exports = (certificate) => {
  let errorMessage
  // Certificate must be an object
  if (typeof certificate !== 'object' || certificate === null) {
    errorMessage = 'Certificate must be an object!'
  }
  // Fields must be an object
  else if (typeof certificate.fields !== 'object' || certificate.fields === null) {
    errorMessage = 'Fields must be an object!'
  }
  // At least one field is required
  else if (Object.keys(certificate.fields).length === 0) {
    errorMessage = 'At least one field is required!'
  }
  // Subject is required
  else if (certificate.subject == null) {
    errorMessage = 'Subject is required!'
  }
  // Subject must be a valid public key
  else if (!isValidPublicKey(certificate.subject)) {
    errorMessage = 'Subject must be a valid public key!'
  }
  // Certifier is required
  else if (certificate.certifier == null) {
    errorMessage = 'Certifier is required!'
  }
  // Certifier must be a valid public key // TODO: Create helper function
  else if (!isValidPublicKey(certificate.certifier)) {
    errorMessage = 'Certifier must be a valid public key'
  }
  // Validation key is required
  else if (certificate.validationKey == null) {
    errorMessage = 'Validation key is required!'
  }
  // Validation key must be the correct length (256 bits or 32 bytes)
  else if (Buffer.byteLength(certificate.validationKey, 'base64') !== 32) {
    errorMessage = 'Validation key must be the correct length (256 bits or 32 bytes)'
  }
  // Type is required
  else if (certificate.type == null) {
    errorMessage = 'Type is required!'
  }
  // Type must be the correct length (256 bits, or 32 bytes)
  else if (Buffer.byteLength(certificate.type, 'base64') !== 32) {
    errorMessage = 'Type must be the correct length (256 bits, or 32 bytes)!'
  }
  // Serial number is required
  else if (certificate.serialNumber == null) {
    errorMessage = 'Serial number is required!'
  }
  // Serial number must be correct length (256 bits or 32 bytes)
  else if (Buffer.byteLength(certificate.serialNumber, 'base64') !== 32) {
    errorMessage = 'Serial number must be correct length (256 bits or 32 bytes)!'
  }
  // Revocation outpoint is required
  else if (certificate.revocationOutpoint == null) {
    errorMessage = 'Revocation outpoint is required!'
  }
  // Revocation outpoint must be the correct length (36 bytes)
  else if (Buffer.byteLength(certificate.revocationOutpoint, 'hex') !== 36) {
    errorMessage = 'Revocation outpoint must be the correct length (36 bytes)!'
  }
  // Signature is required and must be valid
  else if (certificate.signature == null || bsv.crypto.Signature.fromString(certificate.signature) == null) {
    errorMessage = 'Signature is required and must be valid!'
  } else if (!errorMessage) {
    return true
  }
  const e = new Error(errorMessage)
  e.code = 'ERR_INVALID_CERTIFICATE_STRUCTURE'
  throw e
}
