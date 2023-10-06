module.exports = {
  // Client-Side
  createRequestSignature: require('./client-side/createRequestSignature'),
  getCertificatesToInclude: require('./client-side/getCertificatesToInclude'),
  getRequestAuthHeaders: require('./client-side/getRequestAuthHeaders'),
  verifyServerInitialResponse: require('./client-side/verifyServerInitialResponse'),
  verifyServerResponse: require('./client-side/verifyServerResponse'),

  // Server-Side
  getResponseAuthHeaders: require('./server-side/getResponseAuthHeaders'),
  validateAuthHeaders: require('./server-side/validateAuthHeaders'),
  validateCertificates: require('./server-side/validateCertificates'),

  // Certifier Utils
  verifyCertificate: require('./certifier-utils/verifyCertificate'),
  verifyCertificateSignature: require('./certifier-utils/verifyCertificateSignature'),
  decryptCertificateFields: require('./certifier-utils/decryptCertificateFields'),
  ...require('./certifier-utils/certifierServerHelpers'),
  ...require('./certifier-utils/certifierClientHelpers')
}
