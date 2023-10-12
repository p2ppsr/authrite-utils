/* eslint-env jest */
const bsv = require('babbage-bsv')
const crypto = require('crypto')
const getRequestAuthHeaders = require('../../src/client-side/getRequestAuthHeaders')

// Mock Test Data
const AUTHRITE_VERSION = '0.2'
const TEST_CLIENT_PRIVATE_KEY = '0d7889a0e56684ba795e9b1e28eb906df43454f8172ff3f6807b8cf9464994df'
const CLIENT_NONCE = 'HtoBsUgDzj5orHDv1N2zdtiQpDM+aKwGY4VthxDYRHg='
const SERVER_NONCE = 'Ea2SOkMQiMbdCv4uinGmVIqAT+mRkq9VSIX+LG6cKso='

/**
 * Unit tests for getRequestAuthHeaders
 */
describe('getRequestAuthHeaders', () => {
  afterEach(() => {
    jest.clearAllMocks()
  })
  it('constructs the correct BRC-31 compliant auth headers', async () => {
    // Generate a random request nonce to use, and request signature
    const requestNonce = crypto.randomBytes(32).toString('base64')
    // Generate the mock request auth headers a client would send to a server
    const authHeaders = await getRequestAuthHeaders({
      authriteVersion: AUTHRITE_VERSION,
      clientPublicKey: new bsv.PrivateKey(TEST_CLIENT_PRIVATE_KEY).publicKey.toString('hex'),
      requestNonce,
      clientInitialNonce: CLIENT_NONCE,
      serverInitialNonce: SERVER_NONCE,
      requestSignature: 'MOCK_SIG'
    })

    // Make sure the expected functions are called
    expect(authHeaders).toEqual({
      'x-authrite': AUTHRITE_VERSION,
      'x-authrite-identity-key': new bsv.PrivateKey(TEST_CLIENT_PRIVATE_KEY).publicKey.toString('hex'),
      'x-authrite-nonce': requestNonce,
      'x-authrite-initialnonce': CLIENT_NONCE,
      'x-authrite-yournonce': SERVER_NONCE,
      'x-authrite-signature': 'MOCK_SIG',
      'x-authrite-certificates': '[]'
    })
  })
})
