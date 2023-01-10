const { decrypt, getCertificates } = require('@babbage/sdk')

const CLIENT_ERROR_MESSAGE = 'This is user-owned data. To use this function, you must agree to keep it client-side, and it must never leave their device. If you are sharing this data with a third party, you MUST use the Babbage SDK\'s proveCertificate function instead, and specify the verifier\'s identity so the user can review and approve the request. If you agree to keep this data from leaving the user device within your application, you can pass the callerAgreesToKeepDataClientSide parameter to this function to proceed. Note that there will be an immutable record of your application\'s use of this function on the BSV blockchain.'

const decryptOwnedCertificateField = async ({
    certificate,
    fieldName,
    callerAgreesToKeepDataClientSide = false
}) => {
    if (callerAgreesToKeepDataClientSide !== true) {
        const e = new Error(CLIENT_ERROR_MESSAGE)
        e.code = 'ERR_AUTHORIZED_LEVEL_OF_ACCESS_EXCEEDED'
        throw e
    }
    const fieldValue = Buffer.from(await decrypt({
        ciphertext: Buffer.from(certificate.fields[fieldName], 'base64'),
        protocolID: [2, `authrite certificate field ${Buffer.from(certificate.type, 'base64').toString('hex')}`],
        keyID: `${certificate.serialNumber} ${fieldName}`,
        originator: 'projectbabbage.com',
    })).toString()
    return fieldValue
}

const decryptOwnedCertificateFields = async (certificate, callerAgreesToKeepDataClientSide = false) => {
    if (callerAgreesToKeepDataClientSide !== true) {
        const e = new Error(CLIENT_ERROR_MESSAGE)
        e.code = 'ERR_AUTHORIZED_LEVEL_OF_ACCESS_EXCEEDED'
        throw e
    }
    const decryptedFields = {}
    for (const fieldName in certificate.fields) {
        decryptedFields[fieldName] = await decryptOwnedCertificateField({ certificate, fieldName, callerAgreesToKeepDataClientSide })
    }
    return decryptedFields
}

const decryptOwnedCertificates = async ({ certifiers, types, callerAgreesToKeepDataClientSide = false }) => {
    if (callerAgreesToKeepDataClientSide !== true) {
        const e = new Error(CLIENT_ERROR_MESSAGE)
        e.code = 'ERR_AUTHORIZED_LEVEL_OF_ACCESS_EXCEEDED'
        throw e
    }
    let certificates = await getCertificates({ certifiers, types })
    for (let cert of certificates) {
        cert.fields = await decryptOwnedCertificateFields(cert, callerAgreesToKeepDataClientSide)
    }
    return certificates
}
module.exports = {
    decryptOwnedCertificateField,
    decryptOwnedCertificateFields,
    decryptOwnedCertificates
}
