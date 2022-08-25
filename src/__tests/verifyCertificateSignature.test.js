const verifyCertificateSignature = require('../verifyCertificateSignature')

// TODO get vectors and properly test

describe('verifyCertificateSignature', () => {
  it('Verifies a signature', () => {
    const result = verifyCertificateSignature(JSON.parse('{"type":"4h2EuSOrHF2B0FgURmDZ4WsaYjnoY4mtGo2Q5IDf5wM","validationKey":"nPvQpPquGRe3ECnr84B7PMTK15qNa1A23nED6YF+PEQ=","serialNumber":"hBIET6Zc1yuOdfKWH/3bOfDQREVxw4x+FoxIDNRZ010=","fields":{"cool":"aqTTO77D41o+sWDUKVFW19HQaI1YAYePtsbZ1fzILc2VDY8h7S8oxmAjePdowFe0/3qBog==","paymail":"8M3tN+jrEsWwHoN59Y30x80aw+58+EydYkaHE3rsRFdcxYbG/UF7hE9+rIL8y/VzB+yeCQPMnwlZ/4AjxYljfr87ty0kR14G0SC5g5yjQOV3bO9Rfofd/Mvw9g=="},"certifier":"04cab461076409998157f05bb90f07886380186fd3d88b99c549f21de4d2511b8388cfd9e557bba8263a1e8b0a293d6696e2ac3e9e9343d6941b4434f7a62156e8","revocationOutpoint":"000000000000000000000000000000000000000000000000000000000000000000000000","signature":"304402206f106464590ccdea52115e6b6a8d931e7ffda6e428c70fcc58c3e5032bcbd53102202c8e4b4b626d78fd7a03795c32bcc60e1df19fae004d13ee8bccc53eb25d444c"}'))
    expect(result).toEqual(true)
  })
})
