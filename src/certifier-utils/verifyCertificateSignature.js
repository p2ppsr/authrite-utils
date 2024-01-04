const { getPaymentAddress } = require('sendover')
const bsv = require('babbage-bsv')
const validateCertificateStructure = require('./validateCertificateStructure')
const stringify = require('json-stable-stringify')

/**
 * Verifies that the provided certificate has a valid signature. Also checks
 * the structure of the certificate. Throws errors if the certificate is
 * invalid.
 *
 * Note: Does not guarantee that additional fields are not provided in this certificate structure!
 *
 * @param {Object} certificate The certificate to verify.
 * @returns {Boolean} true if the certificate is valid
 */
const verifyCertificateSignature = (certificate) => {
  // Validate Certificate Structure
  validateCertificateStructure(certificate)

  // Construct a certificate to verify with the required props
  const certificateToVerify = {
    certifier: certificate.certifier,
    fields: certificate.fields,
    revocationOutpoint: certificate.revocationOutpoint,
    serialNumber: certificate.serialNumber,
    subject: certificate.subject,
    type: certificate.type,
    validationKey: certificate.validationKey
  }

  // Derive Certificate Public Key
  const signingPublicKey = getPaymentAddress({
    senderPrivateKey: Buffer.from(certificateToVerify.validationKey, 'base64').toString('hex'),
    recipientPublicKey: certificateToVerify.certifier,
    invoiceNumber: `2-authrite certificate signature ${Buffer.from(certificateToVerify.type, 'base64').toString('hex')}-${certificateToVerify.serialNumber}`,
    returnType: 'publicKey'
  })

  // Verify Signature
  const hasValidSignature = bsv.crypto.ECDSA.verify(
    bsv.crypto.Hash.sha256(Buffer.from(stringify(certificateToVerify))),
    bsv.crypto.Signature.fromString(certificate.signature),
    bsv.PublicKey.fromString(signingPublicKey)
  )

  if (hasValidSignature === true) {
    return true
  } else {
    const e = new Error(`The signature for the Authrite certificate with serial number "${certificateToVerify.serialNumber}" is invalid`)
    e.code = 'ERR_AUTHRITE_CERT_SIG_INVALID'
    e.certificateSerialNumber = certificateToVerify.serialNumber
    throw e
  }
}
module.exports = verifyCertificateSignature
