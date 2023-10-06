module.exports = {
  getResponseAuthHeaders: require('./server-side/getResponseAuthHeaders'),
  validateAuthHeaders: require('./server-side/validateAuthHeaders'),
  validateCertificates: require('./server-side/validateCertificates'),
  verifyCertificate: require('./certifier-utils/verifyCertificate'),
  verifyCertificateSignature: require('./certifier-utils/verifyCertificateSignature'),
  decryptCertificateFields: require('./certifier-utils/decryptCertificateFields'),
  ...require('./certifier-utils/certifierServerHelpers'),
  ...require('./certifier-utils/certifierClientHelpers')
}
