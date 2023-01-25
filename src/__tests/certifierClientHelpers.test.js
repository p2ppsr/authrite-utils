const sdk = require('@babbage/sdk')
sdk.decrypt = jest.fn()
sdk.getCertificates = jest.fn()

const { decryptOwnedCertificateField, decryptOwnedCertificateFields, decryptOwnedCertificates } = require('../certifierClientHelpers')

const CLIENT_ERROR_MESSAGE = 'This is user-owned data. To use this function, you must agree to keep it client-side, and it must never leave their device. If you are sharing this data with a third party, you MUST use the Babbage SDK\'s proveCertificate function instead, and specify the verifier\'s identity so the user can review and approve the request. If you agree to keep this data from leaving the user device within your application, you can pass the callerAgreesToKeepDataClientSide parameter to this function to proceed. Note that there will be an immutable record of your application\'s use of this function on the BSV blockchain.'

describe('certifierClientHelpers', () => {
    beforeEach(() => {
    })
    afterEach(() => {
        jest.clearAllMocks()
    })

    it('decryptOwnedCertificateField', async () => {
        const validInputs = {
            certificate: {
                "serialNumber": "0OYFNEYOyvvlSVr8tpDiFKEFwMSfOHikXi8MmrHSw1Y=",
                "validationKey": "gCALYqNvIfOjuzUDgXHYYI/heH7+sFJgHZdEC7YWI4E=",
                "certifier": "025384871bedffb233fdb0b4899285d73d0f0a2b9ad18062a062c01c8bdb2f720a",
                "subject": "02a1c81d78f5c404fd34c418525ba4a3b52be35328c30e67234bfcf30eb8a064d8",
                "type": "jVNgF8+rifnz00856b4TkThCAvfiUE4p+t/aHYl1u0c=",
                "revocationOutpoint": "000000000000000000000000000000000000000000000000000000000000000000000000",
                "signature": "3045022100c7bad855cc37dcd160450c964c279ceacf1d6322c59e51e5d7a48c519376b5170220454d04eb8f994b0bb02552ed9bcc117dca6b005fca6281b4758409f100113471",
                "fields": {
                    "domain": "8RKRWodTM0l81N9tontvefNvyXAwMAI5LMUM+TAHjexbpTScalrH4k8jMUt2mP46ukpd54J1HcfrHRs=",
                    "identity": "KXg6mQGqezbceTti/3gnM17g4zP4JEwaV1rwXTaGOf+TTNh3wLbXUAbnYiXZ8yAePaZOKg==",
                    "when": "voSUOCCtff4cMfvBnigPNG5wTO5mwP6uXGjEqPllBlsxIEeXwyhRxvMwImc+RMr5O6EimF6NTKY3dENWtoc0rBKhC6ljSkPJ",
                    "stake": "hZmzeGpCJtzBMtntoJ0ntof+CGGAZWfLlRAH6WXjmjY8adbR0h6lFmx6y5p7pccDFhoLqQ=="
                }
            },
            fieldName: 'domain',
            callerAgreesToKeepDataClientSide: true
        }
        const fieldValue = 'twitter.com'
        const decryptArgs = {
            ciphertext: Buffer.from(validInputs.certificate.fields[validInputs.fieldName], 'base64'),
            protocolID: [2, `authrite certificate field ${Buffer.from(validInputs.certificate.type, 'base64').toString('hex')}`],
            keyID: `${validInputs.certificate.serialNumber} ${validInputs.fieldName}`,
            originator: 'projectbabbage.com'
        }
        sdk.decrypt.mockReturnValueOnce(Buffer.from(fieldValue))
        expect(await decryptOwnedCertificateField(validInputs)).toBe(fieldValue)
        expect(sdk.decrypt).toHaveBeenCalledWith(decryptArgs)

        delete validInputs.callerAgreesToKeepDataClientSide
        try { await decryptOwnedCertificateField(validInputs); expect(true).toBe(fasle) } catch (e) {
            expect(e.code).toBe('ERR_AUTHORIZED_LEVEL_OF_ACCESS_EXCEEDED')
            expect(e.message).toBe(CLIENT_ERROR_MESSAGE)
        }
    }) 

    it('decryptOwnedCertificateFields', async () => {
        const certificate = {
            "serialNumber": "0OYFNEYOyvvlSVr8tpDiFKEFwMSfOHikXi8MmrHSw1Y=",
            "validationKey": "gCALYqNvIfOjuzUDgXHYYI/heH7+sFJgHZdEC7YWI4E=",
            "certifier": "025384871bedffb233fdb0b4899285d73d0f0a2b9ad18062a062c01c8bdb2f720a",
            "subject": "02a1c81d78f5c404fd34c418525ba4a3b52be35328c30e67234bfcf30eb8a064d8",
            "type": "jVNgF8+rifnz00856b4TkThCAvfiUE4p+t/aHYl1u0c=",
            "revocationOutpoint": "000000000000000000000000000000000000000000000000000000000000000000000000",
            "signature": "3045022100c7bad855cc37dcd160450c964c279ceacf1d6322c59e51e5d7a48c519376b5170220454d04eb8f994b0bb02552ed9bcc117dca6b005fca6281b4758409f100113471",
            "fields": {
                "domain": "8RKRWodTM0l81N9tontvefNvyXAwMAI5LMUM+TAHjexbpTScalrH4k8jMUt2mP46ukpd54J1HcfrHRs=",
                "identity": "KXg6mQGqezbceTti/3gnM17g4zP4JEwaV1rwXTaGOf+TTNh3wLbXUAbnYiXZ8yAePaZOKg==",
                "when": "voSUOCCtff4cMfvBnigPNG5wTO5mwP6uXGjEqPllBlsxIEeXwyhRxvMwImc+RMr5O6EimF6NTKY3dENWtoc0rBKhC6ljSkPJ",
                "stake": "hZmzeGpCJtzBMtntoJ0ntof+CGGAZWfLlRAH6WXjmjY8adbR0h6lFmx6y5p7pccDFhoLqQ=="
            }
        }
        sdk.decrypt.mockReturnValueOnce(Buffer.from('twitter.com'))
        sdk.decrypt.mockReturnValueOnce(Buffer.from('@bob'))
        sdk.decrypt.mockReturnValueOnce(Buffer.from('2023-01-25T00:39:06.928Z'))
        sdk.decrypt.mockReturnValueOnce(Buffer.from('$100'))
        const decryptedFields = {
            "domain": "twitter.com",
            "identity": "@bob",
            "when": "2023-01-25T00:39:06.928Z",
            "stake": "$100"
        }
        expect(await decryptOwnedCertificateFields(certificate, true)).toEqual(decryptedFields)

        try { await decryptOwnedCertificateFields(certificate); expect(true).toBe(fasle) } catch (e) {
            expect(e.code).toBe('ERR_AUTHORIZED_LEVEL_OF_ACCESS_EXCEEDED')
            expect(e.message).toBe(CLIENT_ERROR_MESSAGE)
        }
    }) 

    it('decryptOwnedCertificates', async () => {
        const validInputs = {
            "certifiers": ["025384871bedffb233fdb0b4899285d73d0f0a2b9ad18062a062c01c8bdb2f720a"],
            "types": {
                "jVNgF8+rifnz00856b4TkThCAvfiUE4p+t/aHYl1u0c=": ["domain", "identity", "when", "stake"]
            },
            "callerAgreesToKeepDataClientSide": true
        }
        const certificate = {
            "serialNumber": "0OYFNEYOyvvlSVr8tpDiFKEFwMSfOHikXi8MmrHSw1Y=",
            "validationKey": "gCALYqNvIfOjuzUDgXHYYI/heH7+sFJgHZdEC7YWI4E=",
            "certifier": "025384871bedffb233fdb0b4899285d73d0f0a2b9ad18062a062c01c8bdb2f720a",
            "subject": "02a1c81d78f5c404fd34c418525ba4a3b52be35328c30e67234bfcf30eb8a064d8",
            "type": "jVNgF8+rifnz00856b4TkThCAvfiUE4p+t/aHYl1u0c=",
            "revocationOutpoint": "000000000000000000000000000000000000000000000000000000000000000000000000",
            "signature": "3045022100c7bad855cc37dcd160450c964c279ceacf1d6322c59e51e5d7a48c519376b5170220454d04eb8f994b0bb02552ed9bcc117dca6b005fca6281b4758409f100113471",
            "fields": {
                "domain": "8RKRWodTM0l81N9tontvefNvyXAwMAI5LMUM+TAHjexbpTScalrH4k8jMUt2mP46ukpd54J1HcfrHRs=",
                "identity": "KXg6mQGqezbceTti/3gnM17g4zP4JEwaV1rwXTaGOf+TTNh3wLbXUAbnYiXZ8yAePaZOKg==",
                "when": "voSUOCCtff4cMfvBnigPNG5wTO5mwP6uXGjEqPllBlsxIEeXwyhRxvMwImc+RMr5O6EimF6NTKY3dENWtoc0rBKhC6ljSkPJ",
                "stake": "hZmzeGpCJtzBMtntoJ0ntof+CGGAZWfLlRAH6WXjmjY8adbR0h6lFmx6y5p7pccDFhoLqQ=="
            }
        }

        sdk.getCertificates.mockReturnValueOnce([ certificate ])
        sdk.decrypt.mockReturnValueOnce(Buffer.from('twitter.com'))
        sdk.decrypt.mockReturnValueOnce(Buffer.from('@bob'))
        sdk.decrypt.mockReturnValueOnce(Buffer.from('2023-01-25T00:39:06.928Z'))
        sdk.decrypt.mockReturnValueOnce(Buffer.from('$100'))
        const decryptedFields = {
            "domain": "twitter.com",
            "identity": "@bob",
            "when": "2023-01-25T00:39:06.928Z",
            "stake": "$100"
        }
        expect(await decryptOwnedCertificates(validInputs)).toEqual([ { ...certificate, fields: decryptedFields } ]) 

        delete validInputs.callerAgreesToKeepDataClientSide
        try { await decryptOwnedCertificates(validInputs); expect(true).toBe(fasle) } catch (e) {
            expect(e.code).toBe('ERR_AUTHORIZED_LEVEL_OF_ACCESS_EXCEEDED')
            expect(e.message).toBe(CLIENT_ERROR_MESSAGE)
        }
    }) 

})