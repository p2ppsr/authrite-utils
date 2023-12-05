const { getPaymentAddress } = require('sendover')
const bsv = require('babbage-bsv')
const validateCertificateStructure = require('./validateCertificateStructure')
const stringify = require('json-stable-stringify')

/**
 * Verifies that the provided certificate has a valid signature. Also checks
 * the structure of the certificate. Throws errors if the certificate is
 * invalid.
 *
 * @param {Object} certificate The certificate to verify.
 * @returns {Boolean} true if the certificate is valid
 */
const verifyCertificateSignature = (certificate) => {
  // Validate Certificate Structure
  validateCertificateStructure(certificate)
  // Remove Signature
  const signature = certificate.signature
  const keyring = certificate.keyring
  const masterKeyring = certificate.masterKeyring

  delete certificate.signature
  delete certificate.keyring
  delete certificate.masterKeyring
  delete certificate.userId // Make sure a userId is not present!

  // Derive Certificate Public Key
  const signingPublicKey = getPaymentAddress({
    senderPrivateKey: Buffer.from(certificate.validationKey, 'base64').toString('hex'),
    recipientPublicKey: certificate.certifier,
    invoiceNumber: `2-authrite certificate signature ${certificate.type}-${certificate.serialNumber}`,
    returnType: 'publicKey'
  })

  // Verify Signature
  const hasValidSignature = bsv.crypto.ECDSA.verify(
    bsv.crypto.Hash.sha256(Buffer.from(stringify(certificate))),
    bsv.crypto.Signature.fromString(signature),
    bsv.PublicKey.fromString(signingPublicKey)
  )
  certificate.signature = signature
  certificate.keyring = keyring

  // Add back the required props
  if (masterKeyring) certificate.masterKeyring = masterKeyring

  if (hasValidSignature === true) {
    return true
  } else {
    const e = new Error(`The signature for the Authrite certificate with serial number "${certificate.serialNumber}" is invalid`)
    e.code = 'ERR_AUTHRITE_CERT_SIG_INVALID'
    e.certificateSerialNumber = certificate.serialNumber
    throw e
  }
}
module.exports = verifyCertificateSignature
