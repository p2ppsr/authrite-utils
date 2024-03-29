const { getPaymentAddress, getPaymentPrivateKey } = require('sendover')
const { decrypt } = require('cwi-crypto')
// Make sure we are in a Node ENV before assigning!
if (typeof global.crypto !== 'object') {
  const { Crypto } = require('@peculiar/webcrypto')
  global.crypto = new Crypto()
}
const BabbageSDK = require('@babbage/sdk-ts')

/**
 * Verifies that the provided certificate has a valid signature
 * @param {Object} certificate The certificate to verify.
 * @param {Object} keyring The keyring containing the encrypted fieldRevelationKeys.
 * @param {string} verifierPrivateKey A private key as a base64 string belonging to the certificate verifier. If not provided, the BabbageSDK decrypt function will be used instead.
 * @returns {Object} An object containing the decrypted fields.
 */
const decryptCertificateFields = async (certificate, keyring, verifierPrivateKey) => {
  const decryptedFields = {}
  for (const fieldName in keyring) {
    let fieldRevelationKey
    if (!verifierPrivateKey) {
      // Use the BabbageSDK to decrypt if no verifierPrivateKey was provided
      fieldRevelationKey = await BabbageSDK.decrypt({
        ciphertext: Buffer.from(keyring[fieldName], 'base64'),
        protocolID: [2, 'authrite certificate field encryption'],
        keyID: `${certificate.serialNumber} ${fieldName}`,
        returnType: 'string'
      })
    } else {
      // 1. Derive their private key:
      const derivedPrivateKeyringKey = getPaymentPrivateKey({
        senderPublicKey: certificate.subject,
        recipientPrivateKey: verifierPrivateKey,
        invoiceNumber: `2-authrite certificate field encryption-${certificate.serialNumber} ${fieldName}`,
        returnType: 'babbage-bsv'
      })
      // 2. Derive the sender’s public key:
      const derivedPublicKeyringKey = getPaymentAddress({
        senderPrivateKey: verifierPrivateKey,
        recipientPublicKey: certificate.subject,
        invoiceNumber: `2-authrite certificate field encryption-${certificate.serialNumber} ${fieldName}`,
        returnType: 'babbage-bsv'
      })
      // 3. Use the shared secret between the keys from step 1 and step 2 for decryption.
      const sharedSecret = (derivedPublicKeyringKey.point.mul(derivedPrivateKeyringKey).toBuffer().slice(1)).toString('hex')

      // Encrypted (decryption key) revelation key --> Decrypt it using shared secret
      const decryptionKey = await global.crypto.subtle.importKey(
        'raw',
        Uint8Array.from(Buffer.from(sharedSecret, 'hex')), // Note: convert from base64 unless sent as a buffer
        {
          name: 'AES-GCM'
        },
        true,
        ['decrypt']
      )
      fieldRevelationKey = await decrypt(new Uint8Array(Buffer.from(keyring[fieldName], 'base64')), decryptionKey, 'Uint8Array')
    }

    // (decryption key) revelation key --> Decrypt the field using the revelation key
    const fieldRevelationCryptoKey = await global.crypto.subtle.importKey(
      'raw',
      fieldRevelationKey,
      {
        name: 'AES-GCM'
      },
      true,
      ['decrypt']
    )
    // Get the field value
    const fieldValue = await decrypt(new Uint8Array(Buffer.from(certificate.fields[fieldName], 'base64')), fieldRevelationCryptoKey, 'Uint8Array')
    decryptedFields[fieldName] = Buffer.from(fieldValue).toString()
  }
  return decryptedFields
}
module.exports = decryptCertificateFields
