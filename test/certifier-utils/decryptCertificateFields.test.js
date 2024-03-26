/* eslint-env jest */
const decryptCertificateFields = require('../../src/certifier-utils/decryptCertificateFields')
// const stringify = require('json-stable-stringify')

const VALID_CERT = { "type": "z40BOInXkI8m7f/wBrv4MJ09bZfzZbTj2fJqCtONqCY=", "subject": "0294c479f762f6baa97fbcd4393564c1d7bd8336ebd15928135bbcf575cd1a71a1", "validationKey": "hZzj1l2t8n/JWWBC4OHZqzmis3hg3vxkAetAxYQGdrE=", "serialNumber": "uY4dx5/CNJLnVYH1K8589Y7aYZLbGhqFi+26MZRZGMQ=", "fields": { "firstName": "W10hvbc3ghxa7yrWb3uKWNHNbuQ115W56jcowwwUDJhEX+vawG2nqLVNCdLqUGQT/IDL90BQGfY9yd0=", "lastName": "L5Yg2zh3FpwHQjirzLgPChYFIiw7uEc5WSrjHfbrf6NDEH9YH0g8X98CIHfqwhMog4SEU/2p", "profilePhoto": "b8SQEF2Y9rTPdudj8fvBQJl1U6hTkcbjUSMEdNFryhxZ96Pc2BlvITLKm1JhoNxPPvtQB/ogOH6yasbkVT5IojW56FTIqVoRJc9d+HH8Mcn1E1O7UQgj6WjHaHzk2ItteYvGEg==" }, "certifier": "036dc48522aba1705afbb43df3c04dbd1da373b6154341a875bceaa2a3e7f21528", "revocationOutpoint": "3fac514bf159ef578d743cfc74132687362516eec0e67217313ec824ae1392c500000000", "signature": "304402202249812533771e3699720b0265a204842bac7ad6518d5cc0ffd313469997270c0220527818b6a3c3f5850ca8012401248873d5ed6b612f35c80d841ecd3ec38aa3bf", "keyring": { "firstName": "tbZrXu95LgYpPKjFlfG27FwuDuZtPecLS9b5VrM5gwavKv8x2YgbBX73MeQCqN44SewZRdnypwXv9V5iIPhOFEVmm8b/VsKOyt5amJqvdHk=", "lastName": "JahRRK3Dgj4PoyISqErmGqsYPpB6TR2qEZLRtuFcceL79AM0leq4t8fESD4aDnDSG6xVE90WunrWolXzi0hy6BCDRtH2JlxuCE1uKhboGNA=", "profilePhoto": "AVKEPB41/PQniwtlQP+e4QEjT+lqe4ZyHuwg7E9wbTAWgIljuJLuIwt7Pr9rdc63Jay2ggkpeLp+c6B0MWiQLyvckkKlbHEcZh6MZiERi1o=" } }
const keyring = { "firstName": "Wxx2rHpFKucosJ/wLTpq2rYWHNx8SbBCHs3LKxFOuUGXPJaPs+6vz+uT1IS7ObmTnWTCccBZfIuZv/OmjSBwjsz8GYV6mK8g4IdfaQGSNCs=", "lastName": "FUNtrRHrpjSkeUooBFaGv3AL/Gpc0Xifd9skrOwMcCh/7OtFnUFi2CooJPv4JPMsoSpVuO0EbxEzqwaH+g/SdBITKnPPRq/LlSrYGotk6Z8=", "profilePhoto": "08nX9eV7RAo/+CJ5Rh493JnOVvFvRtGSZh7F72Om6HtVFlOK/ogX3syDbwi8VCuLoGIEn7a9EzAnpcak/w0teKd5E+9HMh9qUpzb80D+66M=" }
const verifierPrivateKey = '45f4c64e021024c5300c69113881e57acaaeda60c3281b2a229386d8f83c4c6f'

describe('decryptCertificateFields', () => {
  it('Decrypts some fields', async () => {
    const decryptedFields = await decryptCertificateFields(VALID_CERT, keyring, verifierPrivateKey)
    expect(decryptedFields).toEqual({
      "firstName": "ALEXANDER J",
      "lastName": "SAMPLE",
      "profilePhoto": "XUTrp3Mg64NSmCRCohwakMDHGCSUDF6Rpkuki7kW4D1Lb4ySLd7T"
    })
  })
})
