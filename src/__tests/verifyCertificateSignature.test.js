const verifyCertificateSignature = require('../verifyCertificateSignature')

// TODO get correct vectors and properly test

describe('verifyCertificateSignature', () => {
  it('Verifies a signature', () => {
    const result = verifyCertificateSignature({ type: '4h2EuSOrHF2B0FgURmDZ4WsaYjnoY4mtGo2Q5IDf5wM', subject: '048d4af3922796e50f8c6ecd4722116c5476a9b51e213a64e3be147ec6c9f69db363cf69e532c048b0bbf037579629d24b6c81c5a9b920f5bd00a40c7bb973b397', validationKey: 'GMescrTfSmpVf314Ay6IbIMQe2eGnFEhDn+a0+tA/ZA=', serialNumber: 'OEE5H1HlBUph7M9PKMTvpf/PqRmBFilKvkgphIHGp/Q=', fields: { cool: 'B7esmhOkTStK6C/RBMyCk5f4TQqhvmSu5/i+UQHC9Cp4z8omX53lS1l/DRdXYpaQKySjBw==', paymail: 'W7mpFCivMYiuv0wTra04jWLJTs7y4ZZMigXY+TBKhGojEHIwEsMVC6+fGzOWeNC5msFRtSaNqu2I3nyyfQzZcvxngevnx16mgtibb3lSgNH4OlP+s6XJqu1f5Q==' }, certifier: '04cab461076409998157f05bb90f07886380186fd3d88b99c549f21de4d2511b8388cfd9e557bba8263a1e8b0a293d6696e2ac3e9e9343d6941b4434f7a62156e8', revocationOutpoint: '000000000000000000000000000000000000000000000000000000000000000000000000', signature: '304402200942504fcd7aba6cb355cdf3bf5ff81a1c8f7f35e4871a0e5f6dccc8e3ed51f00220759fabf50f80f47e7fd037b1292b07cbdf748566e2a389160d7cc0c769bf1a55' })
    expect(result).toEqual(true)
  })
})
