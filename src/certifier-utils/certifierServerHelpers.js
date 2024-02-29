const { createNonce, verifyNonce } = require('cryptononce')
const crypto = require('crypto')
const bsv = require('babbage-bsv')
const stringify = require('json-stable-stringify')
const { getPaymentPrivateKey } = require('sendover')

/**
 * Authrite Certifier Helper Function
 * Creates a response object in the standard format for initialRequest.
 * @param {Object} obj All parameters for this function are provided in an object
 * @param {string} [obj.clientNonce] random data selected by client. Typically 32 bytes in base64 encoding.
 * @param {string} [obj.certifierPrivateKey] Certifier's private key. 32 random bytes in hex encoding.
 * @param {string} [obj.certificateType] Certificate type identifier. 32 bytes in base64 encoding.
 */
const certifierInitialResponse = ({ clientNonce, certifierPrivateKey, certificateType }) => {
  // Create nonces to use to generate the serialNumber and validation key
  const serverSerialNumberNonce = createNonce(certifierPrivateKey)
  const serverValidationKeyNonce = createNonce(certifierPrivateKey)
  // Calculate the serialNumber and validationKey to use
  const serialNumber = crypto.createHash('sha256').update(clientNonce + serverSerialNumberNonce).digest('base64')
  const validationKey = crypto.createHash('sha256').update(clientNonce + serverValidationKeyNonce).digest('base64')

  return {
    type: certificateType,
    serialNonce: serverSerialNumberNonce,
    validationNonce: serverValidationKeyNonce,
    serialNumber,
    validationKey
  }
}

/**
 * Authrite Certifier Helper Function
 * Checks the standard inputs to signCertificate for common errors.
 * Returns null on success (no errors).
 * Returns an object like { code: 'ERR_INVALID_REQUEST', description: '...' } on failure.
 * @param {Object} obj All parameters for this function are provided in an object
 * @param {string} [obj.clientNonce] random data selected by client. Typically 32 bytes in base64 encoding.
 * @param {string} [obj.certifierPrivateKey] Certifier's private key. 32 random bytes in hex encoding.
 * @param {string} [obj.certificateType] Certificate type identifier. 32 bytes in base64 encoding.
 * @param {string} [obj.messageType] Must be the string 'certificateSigningRequest'.
 * @param {string} [obj.type] The requested certificate type. Must equal certificateType.
 * @param {string} [obj.serverSerialNonce] The serialNonce value returned by prior initialRequest.
 * @param {string} [obj.serverValidationNonce] The validationNonce value returned by prior initialRequest.
 * @param {string} [obj.serialNumber] The serialNumber value returned by prior initialRequest.
 * @param {string} [obj.validationKey] The validationKey value returned by prior initialRequest.
 */
const certifierSignCheckArgs = ({
  clientNonce,
  certifierPrivateKey,
  certificateType,
  messageType,
  type,
  serverSerialNonce,
  serverValidationNonce,
  serialNumber,
  validationKey
}) => {
  if (messageType !== 'certificateSigningRequest') {
    return {
      code: 'ERR_INVALID_REQUEST',
      description: 'Invalid message type!'
    }
  }
  if (type !== certificateType) {
    return {
      code: 'ERR_INVALID_REQUEST',
      description: 'Invalid certificate type ID!'
    }
  }
  // Validate server nonces
  if (!verifyNonce(serverSerialNonce, certifierPrivateKey)) {
    return {
      code: 'ERR_INVALID_NONCE',
      description: 'Server serial nonce provided was not created by this server!'
    }
  }
  if (!verifyNonce(serverValidationNonce, certifierPrivateKey)) {
    return {
      code: 'ERR_INVALID_NONCE',
      description: 'Server validation nonce provided was not created by this server!'
    }
  }
  // The server checks that the hashes match
  const serialNumberToValidate = crypto.createHash('sha256').update(clientNonce + serverSerialNonce).digest('base64')
  if (serialNumberToValidate !== serialNumber) {
    return {
      code: 'ERR_INVALID_SERIAL_NUMBER',
      description: 'Serial number provided did not match the client and server nonces provided.'
    }
  }
  const validationKeyToValidate = crypto.createHash('sha256').update(clientNonce + serverValidationNonce).digest('base64')
  if (validationKeyToValidate !== validationKey) {
    return {
      code: 'ERR_INVALID_VALIDATION_KEY',
      description: 'Validation key provided did not match the client and server nonces provided.'
    }
  }
  return null
}

/**
 * Authrite Certifier Helper Function
 * Checks the standard inputs to signCertificate for common errors.
 * Returns null on success (no errors).
 * Returns an object like { code: 'ERR_INVALID_REQUEST', description: '...' } on failure.
 * @param {Object} obj All parameters for this function are provided in an object
 * @param {string} [obj.clientNonce] random data selected by client. Typically 32 bytes in base64 encoding.
 * @param {string} [obj.certifierPrivateKey] Certifier's private key. 32 random bytes in hex encoding.
 * @param {string} [obj.certificateType] Certificate type identifier. 32 bytes in base64 encoding.
 * @param {string} [obj.messageType] Must be the string 'certificateSigningRequest'.
 * @param {string} [obj.type] The requested certificate type. Must equal certificateType.
 * @param {string} [obj.serverSerialNonce] The serialNonce value returned by prior initialRequest.
 * @param {string} [obj.serverValidationNonce] The validationNonce value returned by prior initialRequest.
 * @param {string} [obj.serialNumber] The serialNumber value returned by prior initialRequest.
 * @param {string} [obj.validationKey] The validationKey value returned by prior initialRequest.
 */
const certifierCreateSignedCertificate = ({
  validationKey,
  certifierPrivateKey,
  certificateType,
  serialNumber,
  subject,
  fields,
  revocationOutpoint
}) => {
  if (subject.length !== 66) {
    console.log('Compressing certificate subject:', subject)
    subject = bsv.PublicKey.fromHex(subject).toCompressed().toString()
  }

  // Create certificate to sign
  const certificate = {
    type: certificateType,
    subject,
    validationKey,
    serialNumber,
    fields,
    revocationOutpoint,
    certifier: bsv.PrivateKey.fromHex(certifierPrivateKey).publicKey.toString()
  }

  const dataToSign = Buffer.from(stringify(certificate))

  // Derive the certificate signing public key (sendover)
  const validationPublicKey = bsv.PrivateKey.fromHex(Buffer.from(validationKey, 'base64').toString('hex')).publicKey.toString()
  const derivedPrivateKey = getPaymentPrivateKey({
    senderPublicKey: validationPublicKey,
    recipientPrivateKey: certifierPrivateKey,
    invoiceNumber: `2-authrite certificate signature ${Buffer.from(certificateType, 'base64').toString('hex')}-${serialNumber}`,
    returnType: 'wif'
  })

  // Compute certificate signature
  const signature = bsv.crypto.ECDSA.sign(
    bsv.crypto.Hash.sha256(dataToSign),
    bsv.PrivateKey.fromWIF(derivedPrivateKey)
  )
  certificate.signature = signature.toString('hex')

  return certificate
}

module.exports = {
  certifierInitialResponse,
  certifierSignCheckArgs,
  certifierCreateSignedCertificate
}
