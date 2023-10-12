/* eslint-env jest */
const bsv = require('babbage-bsv')
const crypto = require('crypto')
const validateAuthHeaders = require('../../src/server-side/validateAuthHeaders')
const getRequestAuthHeaders = require('../../src/client-side/getRequestAuthHeaders')
const createRequestSignature = require('../../src/client-side/createRequestSignature')

// Mock Test Data
const AUTHRITE_VERSION = '0.2'
const TEST_CLIENT_PRIVATE_KEY = '0d7889a0e56684ba795e9b1e28eb906df43454f8172ff3f6807b8cf9464994df'
const TEST_SERVER_PRIVATE_KEY = '6dcc124be5f382be631d49ba12f61adbce33a5ac14f6ddee12de25272f943f8b'
const CLIENT_NONCE = 'HtoBsUgDzj5orHDv1N2zdtiQpDM+aKwGY4VthxDYRHg='
const SERVER_NONCE = 'Ea2SOkMQiMbdCv4uinGmVIqAT+mRkq9VSIX+LG6cKso='

/**
 * Basic tests for the validateAuthHeaders helper function which is currently only used authrite server-side code
 */
describe('validateAuthHeaders', () => {
  afterEach(() => {
    jest.clearAllMocks()
  })
  it('fails to validates request auth headers with incorrect data to sign', async () => {
    // Generate a random request nonce to use, and request signature
    const requestNonce = crypto.randomBytes(32).toString('base64')
    const requestSignature = await createRequestSignature({
      dataToSign: 'messageTest',
      requestNonce,
      serverInitialNonce: SERVER_NONCE,
      clientPrivateKey: TEST_CLIENT_PRIVATE_KEY,
      serverPublicKey: new bsv.PrivateKey(TEST_SERVER_PRIVATE_KEY).publicKey.toString('hex')
    })
    // Generate the mock request auth headers a client would send to a server
    const authHeaders = await getRequestAuthHeaders({
      authriteVersion: AUTHRITE_VERSION,
      clientPublicKey: new bsv.PrivateKey(TEST_CLIENT_PRIVATE_KEY).publicKey.toString('hex'),
      requestNonce,
      clientInitialNonce: CLIENT_NONCE,
      serverInitialNonce: SERVER_NONCE,
      requestSignature
    })

    // Verify the request auth headers sent from the mock client
    // Note: Currently validateAuthHeaders does not validate the authrite version, just the key-derivation and signature
    const verified = await validateAuthHeaders({
      messageToSign: 'messageTestWrong',
      authHeaders,
      serverPrivateKey: TEST_SERVER_PRIVATE_KEY
    })

    expect(verified).toEqual(false)
  })
  it('successfully validates request auth headers', async () => {
    // Generate a random request nonce to use, and request signature
    const requestNonce = crypto.randomBytes(32).toString('base64')
    const requestSignature = await createRequestSignature({
      dataToSign: 'messageTest',
      requestNonce,
      serverInitialNonce: SERVER_NONCE,
      clientPrivateKey: TEST_CLIENT_PRIVATE_KEY,
      serverPublicKey: new bsv.PrivateKey(TEST_SERVER_PRIVATE_KEY).publicKey.toString('hex')
    })
    // Generate the mock request auth headers a client would send to a server
    const authHeaders = await getRequestAuthHeaders({
      authriteVersion: AUTHRITE_VERSION,
      clientPublicKey: new bsv.PrivateKey(TEST_CLIENT_PRIVATE_KEY).publicKey.toString('hex'),
      requestNonce,
      clientInitialNonce: CLIENT_NONCE,
      serverInitialNonce: SERVER_NONCE,
      requestSignature
    })

    // Verify the request auth headers sent from the mock client
    // Note: Currently validateAuthHeaders does not validate the authrite version, just the key-derivation and signature
    const verified = await validateAuthHeaders({
      messageToSign: 'messageTest',
      authHeaders,
      serverPrivateKey: TEST_SERVER_PRIVATE_KEY
    })

    expect(verified).toEqual(true)
  })
})
