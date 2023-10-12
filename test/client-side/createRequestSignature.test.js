/* eslint-env jest */
const bsv = require('babbage-bsv')
const crypto = require('crypto')
const { getPaymentPrivateKey } = require('sendover')
const createRequestSignature = require('../../src/client-side/createRequestSignature')

// Mock Test Data
const TEST_CLIENT_PRIVATE_KEY = '0d7889a0e56684ba795e9b1e28eb906df43454f8172ff3f6807b8cf9464994df'
const TEST_SERVER_PRIVATE_KEY = '6dcc124be5f382be631d49ba12f61adbce33a5ac14f6ddee12de25272f943f8b'
const SERVER_NONCE = 'Ea2SOkMQiMbdCv4uinGmVIqAT+mRkq9VSIX+LG6cKso='
const EXPECTED_REQUEST_SIGNATURE = '3044022035eafcb7f5e61c20eb9d81bf9fe0f03313f219ca23a480b49efc2e483514973c02207c38dac41324411d89907f28183b2541257da80c1a45c02a8b41c2ee2a2ada18'

jest.mock('sendover', () => ({
  getPaymentPrivateKey: jest.fn(() => TEST_CLIENT_PRIVATE_KEY)
}))

/**
 * Unit tests for createRequestSignature
 */
describe('createRequestSignature', () => {
  afterEach(() => {
    jest.clearAllMocks()
  })
  it('calls getPaymentPrivateKey to derive a client private key to use in the signature creation', async () => {
    // Generate a random request nonce to use, and request signature
    const requestNonce = crypto.randomBytes(32).toString('base64')
    const requestSignature = await createRequestSignature({
      dataToSign: 'messageTest',
      requestNonce,
      serverInitialNonce: SERVER_NONCE,
      clientPrivateKey: TEST_CLIENT_PRIVATE_KEY,
      serverPublicKey: new bsv.PrivateKey(TEST_SERVER_PRIVATE_KEY).publicKey.toString('hex')
    })

    // Make sure the expected functions are called
    expect(getPaymentPrivateKey).toHaveBeenCalled()
    expect(requestSignature).toEqual(EXPECTED_REQUEST_SIGNATURE)
  })
})
