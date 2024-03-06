const { decrypt, getCertificates } = require('@babbage/sdk-ts')

const CLIENT_ERROR_MESSAGE = 'This is user-owned data. To use this function, you must agree to keep it client-side, and it must never leave their device. If you are sharing this data with a third party, you MUST use the Babbage SDK\'s proveCertificate function instead, and specify the verifier\'s identity so the user can review and approve the request. If you agree to keep this data from leaving the user device within your application, you can pass the callerAgreesToKeepDataClientSide parameter to this function to proceed. Note that there will be an immutable record of your application\'s use of this function on the BSV blockchain.'

/**
 * Decrypts a single certificate field for client-only use.
 * @param {Object} obj All parameters are provided in an object
 * @param {Object} obj.certificate The certificate with a field to decrypt
 * @param {String} obj.fieldName The name of the field to decrypt
 * @param {Boolean} [obj.callerAgreesToKeepDataClientSide=false] Whether the caller of this function agrees to keep the data client-side
 *
 * @returns {Promise<String>} The decrypted field value for client-side-only use
 */
const decryptOwnedCertificateField = async ({
  certificate,
  fieldName,
  callerAgreesToKeepDataClientSide = false
}) => {
  if (callerAgreesToKeepDataClientSide !== true) {
    const e = new Error(CLIENT_ERROR_MESSAGE)
    e.code = 'ERR_AUTHORIZED_LEVEL_OF_ACCESS_EXCEEDED'
    throw e
  }
  const fieldValue = Buffer.from(await decrypt({
    ciphertext: Buffer.from(certificate.fields[fieldName], 'base64'),
    protocolID: [2, `authrite certificate field ${Buffer.from(certificate.type, 'base64').toString('hex')}`],
    keyID: `${certificate.serialNumber} ${fieldName}`,
    originator: 'projectbabbage.com'
  })).toString()
  return fieldValue
}

/**
 * Decrypts all fields in a certificate for client-only use.
 * @param {Object} certificate The certificate containing fields to decrypt
 * @param {Boolean} [callerAgreesToKeepDataClientSide=false] Whether the caller of this function agrees to keep the data client-side
 *
 * @returns {Promise<Object>} Decrypted fields object for client-side-only use
 */
const decryptOwnedCertificateFields = async (certificate, callerAgreesToKeepDataClientSide = false) => {
  if (callerAgreesToKeepDataClientSide !== true) {
    const e = new Error(CLIENT_ERROR_MESSAGE)
    e.code = 'ERR_AUTHORIZED_LEVEL_OF_ACCESS_EXCEEDED'
    throw e
  }
  const decryptedFields = {}
  for (const fieldName in certificate.fields) {
    decryptedFields[fieldName] = await decryptOwnedCertificateField({ certificate, fieldName, callerAgreesToKeepDataClientSide })
  }
  return decryptedFields
}

/**
 * Searches for user certificates, returning decrypted certificate fields for client-side-only use
 * @param {Array} obj.certifiers The certifiers to search for
 * @param {Object} obj.types The types to search for
 * @param {Boolean} [obj.callerAgreesToKeepDataClientSide=false] Whether the caller of this function agrees to keep the data client-side
 *
 * @returns {Promise<Array<Object>>} The set of decrypted certificates for client-only use
 */
const decryptOwnedCertificates = async ({ certifiers, types, callerAgreesToKeepDataClientSide = false }) => {
  if (callerAgreesToKeepDataClientSide !== true) {
    const e = new Error(CLIENT_ERROR_MESSAGE)
    e.code = 'ERR_AUTHORIZED_LEVEL_OF_ACCESS_EXCEEDED'
    throw e
  }
  const certificates = await getCertificates({ certifiers, types })
  for (const cert of certificates) {
    cert.fields = await decryptOwnedCertificateFields(cert, callerAgreesToKeepDataClientSide)
  }
  return certificates
}

module.exports = {
  decryptOwnedCertificateField,
  decryptOwnedCertificateFields,
  decryptOwnedCertificates
}
