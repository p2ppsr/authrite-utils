const { decrypt } = require('@babbage/sdk')

const decryptOwnedCertificateField = async ({
    certificate,
    fieldName
}) => {
    const fieldValue = Buffer.from(await decrypt({
        ciphertext: Buffer.from(certificate.fields[fieldName], 'base64'),
        protocolID: [2, `authrite certificate field ${Buffer.from(certificate.type, 'base64').toString('hex')}`],
        keyID: `${certificate.serialNumber} ${fieldName}`,
        originator: 'projectbabbage.com',
    })).toString()
    return fieldValue
}

const decryptOwnedCertificateFields = async (certificate) => {
    const decryptedFields = {}
    for (const fieldName in certificate.fields) {
        decryptedFields[fieldName] = await decryptOwnedCertificateField({ certificate, fieldName })
    }
    return decryptedFields
}

module.exports = {
    decryptOwnedCertificateField,
    decryptOwnedCertificateFields
}