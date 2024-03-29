/* eslint-env jest */
const bsv = require('babbage-bsv')
const getResponseAuthHeaders = require('../../src/server-side/getResponseAuthHeaders')

// Mock Test Data
const AUTHRITE_VERSION = '0.2'
const TEST_CLIENT_PRIVATE_KEY = '0d7889a0e56684ba795e9b1e28eb906df43454f8172ff3f6807b8cf9464994df'
const TEST_SERVER_PRIVATE_KEY = '6dcc124be5f382be631d49ba12f61adbce33a5ac14f6ddee12de25272f943f8b'
const CLIENT_NONCE = 'HtoBsUgDzj5orHDv1N2zdtiQpDM+aKwGY4VthxDYRHg='
const SERVER_NONCE = 'Ea2SOkMQiMbdCv4uinGmVIqAT+mRkq9VSIX+LG6cKso='

/**
 * Basic tests for the getResponseAuthHeaders helper function which is currently only used authrite server-side code
 */
describe('getResponseAuthHeaders', () => {
  afterEach(() => {
    jest.clearAllMocks()
  })
  it('get headers necessary for authenticating an initial request response', async () => {
    const headers = await getResponseAuthHeaders({
      authrite: AUTHRITE_VERSION,
      messageType: 'initialResponse',
      serverPrivateKey: TEST_SERVER_PRIVATE_KEY,
      clientPublicKey: new bsv.PrivateKey(TEST_CLIENT_PRIVATE_KEY).publicKey.toString('hex'),
      clientNonce: CLIENT_NONCE,
      serverNonce: SERVER_NONCE,
      messageToSign: 'messageTest',
      certificates: [],
      requestedCertificates: []
    })

    expect(headers).toEqual({
      authrite: '0.2',
      messageType: 'initialResponse',
      identityKey: '03b51d497f8c67c1416cfe1a58daa5a576a63eb0b64608922d5c4f98b6a1d9b103',
      nonce: 'Ea2SOkMQiMbdCv4uinGmVIqAT+mRkq9VSIX+LG6cKso=',
      certificates: [],
      requestedCertificates: [],
      signature: '3044022069db36033d2c0b3e61a7070fdd408d261bdd291488384185a127a916790a492002206da7627711f0e67855a3470a0e95e8d89893e559db900154e451c9f6ea635bb2'
    })
  })
  it('get headers necessary for authenticating a standard response', async () => {
    const headers = await getResponseAuthHeaders({
      authrite: AUTHRITE_VERSION,
      serverPrivateKey: TEST_SERVER_PRIVATE_KEY,
      clientPublicKey: new bsv.PrivateKey(TEST_CLIENT_PRIVATE_KEY).publicKey.toString('hex'),
      clientNonce: CLIENT_NONCE,
      serverNonce: SERVER_NONCE,
      messageToSign: 'messageTest',
      certificates: [],
      requestedCertificates: []
    })

    expect(headers).toEqual({
      'x-authrite': '0.2',
      'x-authrite-identity-key': '03b51d497f8c67c1416cfe1a58daa5a576a63eb0b64608922d5c4f98b6a1d9b103',
      'x-authrite-nonce': 'Ea2SOkMQiMbdCv4uinGmVIqAT+mRkq9VSIX+LG6cKso=',
      'x-authrite-yournonce': 'HtoBsUgDzj5orHDv1N2zdtiQpDM+aKwGY4VthxDYRHg=',
      'x-authrite-certificates': '[]',
      'x-authrite-signature': '3044022069db36033d2c0b3e61a7070fdd408d261bdd291488384185a127a916790a492002206da7627711f0e67855a3470a0e95e8d89893e559db900154e451c9f6ea635bb2'
    })
  })
})
