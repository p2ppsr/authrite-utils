const { getPaymentAddress } = require('sendover')
const bsv = require('babbage-bsv')
const validateCertificateStructure = require('./utils/validateCertificateStructure')
const stringify = require('json-stable-stringify')

/**
 * Verifies that the provided certificate has a valid signature. Also checks the structure of the certificate.
 * @param {Object} certificate The certificate to verify.
 * @returns {Boolean} the result of the verification.
 */
const verifyCertificateSignature = (certificate) => {
  // Validate Certificate Structure
  validateCertificateStructure(certificate)
  // Remove Signature
  const signature = certificate.signature
  delete certificate.signature

  // Derive Certificate Public Key
  const signingPublicKey = getPaymentAddress({
    senderPrivateKey: bsv.PrivateKey.fromHex(Buffer.from(certificate.validationKey, 'base64').toString('hex')),
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
  return hasValidSignature
}
module.exports = verifyCertificateSignature
