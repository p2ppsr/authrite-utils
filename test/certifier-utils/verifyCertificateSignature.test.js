/* eslint-env jest */
const verifyCertificateSignature = require('../../src/certifier-utils/verifyCertificateSignature')
const stringify = require('json-stable-stringify')

// TODO get correct vectors and properly test

describe('verifyCertificateSignature', () => {
  it('Verifies a signature', () => {
    const signedCert = {
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
      },
      "masterKeyring": {
        "firstName": "y7gKN18jZedraZEv5NLgXdyCQHe015i5VvBsBWAaqqbvLO4atGZStngsc/mSWAcEWtnbIUciC/xKrRrvQ2W7xy6lSlkebgt67Ju/lor7tAw=",
        "lastName": "EWQstCO2ElZyn2jLm4La1lRtVhuxnww83CAC810B/aT4pzleiobZfObDt8HAcJiyeZ/lkC2/m3T/ZB5+EVEMThRWRJ7ulkHFpeeUHC2MYqI=",
        "profilePhoto": "jIq1/Fr9MEQqIilnaUAqq2dMD58lj/pHxDwq1v5VmjJncRhH7aW1jvqQat44tEbgm4ud6WhFs1kc5KA5bFVoqH2OenjM6vHC0SZhZrzUk5g="
      }
    }
    // This is the stable stringify of a valid signed certificate:
    const validSignedCertString = '{"certifier":"036dc48522aba1705afbb43df3c04dbd1da373b6154341a875bceaa2a3e7f21528","fields":{"firstName":"W10hvbc3ghxa7yrWb3uKWNHNbuQ115W56jcowwwUDJhEX+vawG2nqLVNCdLqUGQT/IDL90BQGfY9yd0=","lastName":"L5Yg2zh3FpwHQjirzLgPChYFIiw7uEc5WSrjHfbrf6NDEH9YH0g8X98CIHfqwhMog4SEU/2p","profilePhoto":"b8SQEF2Y9rTPdudj8fvBQJl1U6hTkcbjUSMEdNFryhxZ96Pc2BlvITLKm1JhoNxPPvtQB/ogOH6yasbkVT5IojW56FTIqVoRJc9d+HH8Mcn1E1O7UQgj6WjHaHzk2ItteYvGEg=="},"masterKeyring":{"firstName":"y7gKN18jZedraZEv5NLgXdyCQHe015i5VvBsBWAaqqbvLO4atGZStngsc/mSWAcEWtnbIUciC/xKrRrvQ2W7xy6lSlkebgt67Ju/lor7tAw=","lastName":"EWQstCO2ElZyn2jLm4La1lRtVhuxnww83CAC810B/aT4pzleiobZfObDt8HAcJiyeZ/lkC2/m3T/ZB5+EVEMThRWRJ7ulkHFpeeUHC2MYqI=","profilePhoto":"jIq1/Fr9MEQqIilnaUAqq2dMD58lj/pHxDwq1v5VmjJncRhH7aW1jvqQat44tEbgm4ud6WhFs1kc5KA5bFVoqH2OenjM6vHC0SZhZrzUk5g="},"revocationOutpoint":"3fac514bf159ef578d743cfc74132687362516eec0e67217313ec824ae1392c500000000","serialNumber":"uY4dx5/CNJLnVYH1K8589Y7aYZLbGhqFi+26MZRZGMQ=","signature":"304402202249812533771e3699720b0265a204842bac7ad6518d5cc0ffd313469997270c0220527818b6a3c3f5850ca8012401248873d5ed6b612f35c80d841ecd3ec38aa3bf","subject":"0294c479f762f6baa97fbcd4393564c1d7bd8336ebd15928135bbcf575cd1a71a1","type":"z40BOInXkI8m7f/wBrv4MJ09bZfzZbTj2fJqCtONqCY=","validationKey":"hZzj1l2t8n/JWWBC4OHZqzmis3hg3vxkAetAxYQGdrE="}'
    // Verify that we can parse the valid stringify version into an object and stringify again
    const parsedValidSignedCert = JSON.parse(validSignedCertString)
    expect(stringify(parsedValidSignedCert)).toEqual(validSignedCertString)
    // Verify that the signedCert object stringify is the same as what we know is valid.
    expect(stringify(signedCert)).toEqual(validSignedCertString)
    // Finally do the actual work of verifying...
    const result = verifyCertificateSignature(signedCert)
    expect(result).toEqual(true)
  })
})
