/* eslint-env jest */
const verifyCertificate = require('../../src/certifier-utils/verifyCertificate')
// const stringify = require('json-stable-stringify')

// TODO: Test once we have the recovcation overlay network
// const REVOKED_CERT = { // TODO: Obtain a revoked certificate somehow
//   "type": "z40BOInXkI8m7f/wBrv4MJ09bZfzZbTj2fJqCtONqCY=",
//   "subject": "0294c479f762f6baa97fbcd4393564c1d7bd8336ebd15928135bbcf575cd1a71a1",
//   "validationKey": "hZzj1l2t8n/JWWBC4OHZqzmis3hg3vxkAetAxYQGdrE=",
//   "serialNumber": "uY4dx5/CNJLnVYH1K8589Y7aYZLbGhqFi+26MZRZGMQ=",
//   "certifier": "036dc48522aba1705afbb43df3c04dbd1da373b6154341a875bceaa2a3e7f21528",
//   "revocationOutpoint": "3fac514bf159ef578d743cfc74132687362516eec0e67217313ec824ae1392c500000000",
//   "signature": "304402202249812533771e3699720b0265a204842bac7ad6518d5cc0ffd313469997270c0220527818b6a3c3f5850ca8012401248873d5ed6b612f35c80d841ecd3ec38aa3bf",
//   "fields": {
//     "firstName": "W10hvbc3ghxa7yrWb3uKWNHNbuQ115W56jcowwwUDJhEX+vawG2nqLVNCdLqUGQT/IDL90BQGfY9yd0=",
//     "lastName": "L5Yg2zh3FpwHQjirzLgPChYFIiw7uEc5WSrjHfbrf6NDEH9YH0g8X98CIHfqwhMog4SEU/2p",
//     "profilePhoto": "b8SQEF2Y9rTPdudj8fvBQJl1U6hTkcbjUSMEdNFryhxZ96Pc2BlvITLKm1JhoNxPPvtQB/ogOH6yasbkVT5IojW56FTIqVoRJc9d+HH8Mcn1E1O7UQgj6WjHaHzk2ItteYvGEg=="
//   }
// }

const VALID_CERT = {
  "type": "z40BOInXkI8m7f/wBrv4MJ09bZfzZbTj2fJqCtONqCY=",
  "subject": "0294c479f762f6baa97fbcd4393564c1d7bd8336ebd15928135bbcf575cd1a71a1",
  "validationKey": "hZzj1l2t8n/JWWBC4OHZqzmis3hg3vxkAetAxYQGdrE=",
  "serialNumber": "uY4dx5/CNJLnVYH1K8589Y7aYZLbGhqFi+26MZRZGMQ=",
  "certifier": "036dc48522aba1705afbb43df3c04dbd1da373b6154341a875bceaa2a3e7f21528",
  "revocationOutpoint": "3fac514bf159ef578d743cfc74132687362516eec0e67217313ec824ae1392c500000000",
  "signature": "304402202249812533771e3699720b0265a204842bac7ad6518d5cc0ffd313469997270c0220527818b6a3c3f5850ca8012401248873d5ed6b612f35c80d841ecd3ec38aa3bf",
  "fields": {
    "firstName": "W10hvbc3ghxa7yrWb3uKWNHNbuQ115W56jcowwwUDJhEX+vawG2nqLVNCdLqUGQT/IDL90BQGfY9yd0=",
    "lastName": "L5Yg2zh3FpwHQjirzLgPChYFIiw7uEc5WSrjHfbrf6NDEH9YH0g8X98CIHfqwhMog4SEU/2p",
    "profilePhoto": "b8SQEF2Y9rTPdudj8fvBQJl1U6hTkcbjUSMEdNFryhxZ96Pc2BlvITLKm1JhoNxPPvtQB/ogOH6yasbkVT5IojW56FTIqVoRJc9d+HH8Mcn1E1O7UQgj6WjHaHzk2ItteYvGEg=="
  }
}

describe('verifyCertificate', () => {
  // it('Fails verifying for revoked certificate', async () => {
  //   const decryptedFields = await verifyCertificate(REVOKED_CERT, 'test')
  //   expect(decryptedFields).toEqual(false)
  // })
  it('Verifies successfully for valid certificate', async () => {
    const decryptedFields = await verifyCertificate(VALID_CERT, 'test')
    expect(decryptedFields).toEqual(true)
  })
})
