const verifyCertificateSignature = require('./verifyCertificateSignature')
const { getSpentStatusForOutpoint } = require('cwi-external-services')

/**
 * Verifies a certificate signature, structure, and revocation status
 */
const verifyCertificate = async (certificate, chain) => {
  // Verify signature and structure of cert
  await verifyCertificateSignature(certificate)

  // Check the spent status of the revocation outpoint
  const results = await getSpentStatusForOutpoint(certificate.revocationOutpoint, chain)
  return results.spent
}
module.exports = verifyCertificate
