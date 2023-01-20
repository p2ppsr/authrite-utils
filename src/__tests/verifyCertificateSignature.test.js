const verifyCertificateSignature = require('../verifyCertificateSignature')
const stringify = require('json-stable-stringify')

// TODO get correct vectors and properly test

describe('verifyCertificateSignature', () => {
  it('Verifies a signature', () => {
    var signedCert = {
      certifier: '025384871bedffb233fdb0b4899285d73d0f0a2b9ad18062a062c01c8bdb2f720a',
      fields: {
        domain: '4Rp/1H7RKPE5zxhzIM5C098sRpvxRlfugVKum6spOGMQ15JBaAh+wntQuxa656JPh3iQ88nDQhqdjzE=',
        identity: 'LZzi8GCRF4SjU63lTorT9ej/Nb8MhW1hASeiJSYT7VOO+pMXJXVingKc+3+ZSW82oIl6BA==',
        stake: '1Y4Z1a216atKFQOrUeU+xz8j4PdbD9bIZblHeKMjJNcI1MZYVP0KO6D0LCN0w7A66Pwx2g==',
        when: 'flSOcvWx+MSunYkGeBRkTlj9aDlHxYADecf3Lr13gh/ndrJtouvB+3/75o3C4jpwG2550nxWAHBgR6s5oW+K5PDzKj9G1nPN'
      },
      keyring: {
        domain: 'Ccj/ALyluOam0ikjmw6RKHMIvXCBUEMk8EhGcGiYhQBr+tIcHd4BlNMqtDs43YNSKstuevLG6bYRE3NunWioZpRssyRPphZt96pd22IofPY=',
        identity:'2MREiStrbQrGiNes07dPdHZrNG/PsaWH2OGcoKPOB4IRTiBQ+Jwn05VTHI5hKg6wdl4oBYT6NZtdNXg58PevOeYDHEwrynEkYl0Ox7Xq8Xc=',
        stake:'dUOMJybp8WhhUTFeu5IbyGidinlLRvlzjFXxx5f/rXLLOqfWcVhaqZ+KrXDDilsyikAtJI2iIrD2gyLP8lYR9/DTEFeB0ghNMxtOjYe6jSs=',
        when:'oxAAHLRBD6hxF0nTo63IajDQlypxBgSXas8uaNqpQ1fcFWwBEt5c/oZQZBY1MATrsl2BZ8wOHcnTRKjGMnkX1514bqBAMwtKmvhSXss8eTo='
      },
      revocationOutpoint: '000000000000000000000000000000000000000000000000000000000000000000000000',
      serialNumber: 'zFpvOxvuewvvUnmE4DncNHELvlTUVs0bVOK/Z9KR3tc=',
      signature: '3044022074333e79941faa3608aae2322e1eedbdef9a473d252f43434b357f55e76ed8050220749baff081ff52472342fe21212e2f069a052d9904f4e92c0cee8203a82af21c',
      subject: '02a1c81d78f5c404fd34c418525ba4a3b52be35328c30e67234bfcf30eb8a064d8',
      type: 'jVNgF8+rifnz00856b4TkThCAvfiUE4p+t/aHYl1u0c=',
      validationKey: 'i0P2MiTG/gt1Q0aUjAfmUp0i9vIq8YEzC5FAYPzE1PU='
    }
    // This is the stable stringify of a valid signed certificate:
    const validSignedCertString = '{"certifier":"025384871bedffb233fdb0b4899285d73d0f0a2b9ad18062a062c01c8bdb2f720a","fields":{"domain":"4Rp/1H7RKPE5zxhzIM5C098sRpvxRlfugVKum6spOGMQ15JBaAh+wntQuxa656JPh3iQ88nDQhqdjzE=","identity":"LZzi8GCRF4SjU63lTorT9ej/Nb8MhW1hASeiJSYT7VOO+pMXJXVingKc+3+ZSW82oIl6BA==","stake":"1Y4Z1a216atKFQOrUeU+xz8j4PdbD9bIZblHeKMjJNcI1MZYVP0KO6D0LCN0w7A66Pwx2g==","when":"flSOcvWx+MSunYkGeBRkTlj9aDlHxYADecf3Lr13gh/ndrJtouvB+3/75o3C4jpwG2550nxWAHBgR6s5oW+K5PDzKj9G1nPN"},"keyring":{"domain":"Ccj/ALyluOam0ikjmw6RKHMIvXCBUEMk8EhGcGiYhQBr+tIcHd4BlNMqtDs43YNSKstuevLG6bYRE3NunWioZpRssyRPphZt96pd22IofPY=","identity":"2MREiStrbQrGiNes07dPdHZrNG/PsaWH2OGcoKPOB4IRTiBQ+Jwn05VTHI5hKg6wdl4oBYT6NZtdNXg58PevOeYDHEwrynEkYl0Ox7Xq8Xc=","stake":"dUOMJybp8WhhUTFeu5IbyGidinlLRvlzjFXxx5f/rXLLOqfWcVhaqZ+KrXDDilsyikAtJI2iIrD2gyLP8lYR9/DTEFeB0ghNMxtOjYe6jSs=","when":"oxAAHLRBD6hxF0nTo63IajDQlypxBgSXas8uaNqpQ1fcFWwBEt5c/oZQZBY1MATrsl2BZ8wOHcnTRKjGMnkX1514bqBAMwtKmvhSXss8eTo="},"revocationOutpoint":"000000000000000000000000000000000000000000000000000000000000000000000000","serialNumber":"zFpvOxvuewvvUnmE4DncNHELvlTUVs0bVOK/Z9KR3tc=","signature":"3044022074333e79941faa3608aae2322e1eedbdef9a473d252f43434b357f55e76ed8050220749baff081ff52472342fe21212e2f069a052d9904f4e92c0cee8203a82af21c","subject":"02a1c81d78f5c404fd34c418525ba4a3b52be35328c30e67234bfcf30eb8a064d8","type":"jVNgF8+rifnz00856b4TkThCAvfiUE4p+t/aHYl1u0c=","validationKey":"i0P2MiTG/gt1Q0aUjAfmUp0i9vIq8YEzC5FAYPzE1PU="}'
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
