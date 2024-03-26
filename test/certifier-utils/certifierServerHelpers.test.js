/* eslint-env jest */
const cryptoNonce = require('cryptononce')
cryptoNonce.createNonce = jest.fn() // mock just createNonce, affects next require...
const { certifierInitialResponse, certifierSignCheckArgs, certifierCreateSignedCertificate } = require('../../src/index')

describe('certifierServerHelpers', () => {
  beforeEach(() => {
  })
  afterEach(() => {
  })

  it('certifierInitialResponse', async () => {
    const clientNonce = '3FgMwZeRciC106l6UOqPfrx557ify+SKGDE6x7WnwNs='
    const certifierPrivateKey = '45f4c64e021024c5300c69113881e57acaaeda60c3281b2a229386d8f83c4c6f'
    const certificateType = 'jVNgF8+rifnz00856b4TkThCAvfiUE4p+t/aHYl1u0c='
    cryptoNonce.createNonce.mockReturnValueOnce('PXdNRjN8qqQjWoOlmZ8Sdo5sX8uXdtPPf4dxol2mTgM=')
    cryptoNonce.createNonce.mockReturnValueOnce('siHmcs7ZOeldZdybK8d5KcK35tjnfjneL14Dqh6CmWw=')
    const result = {
      type: 'jVNgF8+rifnz00856b4TkThCAvfiUE4p+t/aHYl1u0c=',
      serialNonce: 'PXdNRjN8qqQjWoOlmZ8Sdo5sX8uXdtPPf4dxol2mTgM=',
      validationNonce: 'siHmcs7ZOeldZdybK8d5KcK35tjnfjneL14Dqh6CmWw=',
      serialNumber: '3N82XhwZBBKigtBRXpN7mxMjUKCKsPT8Lfifi3Z0UZo=',
      validationKey: 'RVS0F3q5k65z/J/ORl3pBnjwr7zXmG6VWw2GaDYwOc4='
    }
    expect(certifierInitialResponse({ clientNonce, certifierPrivateKey, certificateType }))
      .toEqual(result)
  })

  it('certifierSignCheckArgs', async () => {
    const validInput = {
      certificateType: 'jVNgF8+rifnz00856b4TkThCAvfiUE4p+t/aHYl1u0c=',
      certifierPrivateKey: '45f4c64e021024c5300c69113881e57acaaeda60c3281b2a229386d8f83c4c6f',
      clientNonce: '3FgMwZeRciC106l6UOqPfrx557ify+SKGDE6x7WnwNs=',
      messageType: 'certificateSigningRequest',
      serialNumber: '3N82XhwZBBKigtBRXpN7mxMjUKCKsPT8Lfifi3Z0UZo=',
      serverSerialNonce: 'PXdNRjN8qqQjWoOlmZ8Sdo5sX8uXdtPPf4dxol2mTgM=',
      serverValidationNonce: 'siHmcs7ZOeldZdybK8d5KcK35tjnfjneL14Dqh6CmWw=',
      type: 'jVNgF8+rifnz00856b4TkThCAvfiUE4p+t/aHYl1u0c=',
      validationKey: 'RVS0F3q5k65z/J/ORl3pBnjwr7zXmG6VWw2GaDYwOc4='
    }
    expect(certifierSignCheckArgs(validInput)).toBe(null)
    expect(certifierSignCheckArgs({ ...validInput, messageType: 'foo' })).toEqual({
      code: 'ERR_INVALID_REQUEST',
      description: 'Invalid message type!'
    })
    expect(certifierSignCheckArgs({ ...validInput, type: 'foo' })).toEqual({
      code: 'ERR_INVALID_REQUEST',
      description: 'Invalid certificate type ID!'
    })
    expect(certifierSignCheckArgs({ ...validInput, serverSerialNonce: 'foo' })).toEqual({
      code: 'ERR_INVALID_NONCE',
      description: 'Server serial nonce provided was not created by this server!'
    })
    expect(certifierSignCheckArgs({ ...validInput, serverValidationNonce: 'foo' })).toEqual({
      code: 'ERR_INVALID_NONCE',
      description: 'Server validation nonce provided was not created by this server!'
    })
    expect(certifierSignCheckArgs({ ...validInput, serialNumber: 'foo' })).toEqual({
      code: 'ERR_INVALID_SERIAL_NUMBER',
      description: 'Serial number provided did not match the client and server nonces provided.'
    })
    expect(certifierSignCheckArgs({ ...validInput, validationKey: 'foo' })).toEqual({
      code: 'ERR_INVALID_VALIDATION_KEY',
      description: 'Validation key provided did not match the client and server nonces provided.'
    })
  })

  it('certifierCreateSignedCertificate', async () => {
    const validInput = {
      certificateType: 'jVNgF8+rifnz00856b4TkThCAvfiUE4p+t/aHYl1u0c=',
      fields: {
        domain: 'QFxmakDQu6h+mrNJqxRkwGFWAhW1zg3SGKSDgHCIrJipUeRnLgDCDS/pYjT05H0Hg7Tx5CZADNDLB8I=',
        identity: '8H8y7naW/kyhKPX2Bqe1upNiKXVPhkoUP0um5foSEkwhM5kxFpVx+RTSL426Tz6v7JdW5Q==',
        when: 'Ewt71zoGl3Dt8seJZWPyYCNKVw1ooxo54lIAoVwGZOCf4+ggRW/PEmNAw3df3Oxika8EteWUE3yC+/oJbgMDygTXg41umTY/',
        stake: 'gG9XmHRD5YR1NSaaV5vHBPklMRKYNM95SSO+KoH/Pw+BPych/OPsRHsI+Fo9ergO0hfHOA=='
      },
      revocationOutpoint: '000000000000000000000000000000000000000000000000000000000000000000000000',
      serialNumber: '3N82XhwZBBKigtBRXpN7mxMjUKCKsPT8Lfifi3Z0UZo=',
      subject: '02a1c81d78f5c404fd34c418525ba4a3b52be35328c30e67234bfcf30eb8a064d8',
      validationKey: 'RVS0F3q5k65z/J/ORl3pBnjwr7zXmG6VWw2GaDYwOc4=',
      certifierPrivateKey: '45f4c64e021024c5300c69113881e57acaaeda60c3281b2a229386d8f83c4c6f'
    }
    const certificate = {
      type: validInput.certificateType,
      fields: validInput.fields,
      revocationOutpoint: validInput.revocationOutpoint,
      serialNumber: validInput.serialNumber,
      subject: validInput.subject,
      validationKey: validInput.validationKey,
      certifier: '025384871bedffb233fdb0b4899285d73d0f0a2b9ad18062a062c01c8bdb2f720a',
      signature: '304502210098be7a070657e01075fa0bbd60fec56842d790354e2ba1bd705a0f29934c76d6022034e658ac9d5ad813f477c484759c6900a7445f95acd9dd12819a87ecee34b380'
    }
    expect(certifierCreateSignedCertificate(validInput)).toEqual(certificate)
  })
})
