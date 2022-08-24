const { getPaymentAddress, getPaymentPrivateKey } = require('sendover')
const { decrypt } = require('@cwi/crypto')
const { Crypto } = require('@peculiar/webcrypto')
global.crypto = new Crypto()

/**
 * Verifies that the provided certificate has a valid signature
 * @param {Object} certificate The certificate to verify.
 * @param {Object} keyring The keyring containing the encrypted fieldRevelationKeys.
 * @param {string} caPublicKey The public key belonging to the certificate authrity that signed the certificate.
 * @returns {Object} An object containing the decrypted fields.
 */
const decryptCertificateFields = async (certificate, keyring, caPublicKey, verifierPrivateKey) => {
  const decryptedFields = {}
  for (const fieldName in keyring) {
    // 1. Derive their private key:
    const derivedPrivateKeyringKey = getPaymentPrivateKey({
      senderPublicKey: caPublicKey,
      recipientPrivateKey: verifierPrivateKey,
      invoiceNumber: `2-authrite certificate field encryption cert-${certificate.serialNumber} ${fieldName}`,
      returnType: 'bsv'
    })
    // 2. Derive the sender’s public key:
    const derivedPublicKeyringKey = getPaymentAddress({
      senderPrivateKey: verifierPrivateKey,
      recipientPublicKey: caPublicKey,
      invoiceNumber: `2-authrite certificate field encryption cert-${certificate.serialNumber} ${fieldName}`,
      returnType: 'bsv'
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
    const fieldRevelationKey = await decrypt(new Uint8Array(Buffer.from(keyring[fieldName], 'base64')), decryptionKey, 'Uint8Array')

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
