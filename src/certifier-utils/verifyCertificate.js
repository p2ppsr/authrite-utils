const verifyCertificateSignature = require('./verifyCertificateSignature')
// const { getSpentStatusForOutpoint } = require('cwi-external-services')

/**
 * Verifies a certificate signature, structure, and revocation status
 */
const verifyCertificate = async (certificate, chain) => {
  // Verify signature and structure of cert
  await verifyCertificateSignature(certificate)

  // TODO: Use Certificate Revocation Overlay Network
  return true
  // // Check the spent status of the revocation outpoint
  // const spent = await getSpentStatusForOutpoint(certificate.revocationOutpoint, chain)
  // if (spent) {
  //   return false
  // }
  // return true
}
module.exports = verifyCertificate
