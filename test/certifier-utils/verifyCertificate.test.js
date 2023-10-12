/* eslint-env jest */
const verifyCertificate = require('../../src/certifier-utils/verifyCertificate')
// const stringify = require('json-stable-stringify')

const REVOKED_CERT = {
  type: 'z40BOInXkI8m7f/wBrv4MJ09bZfzZbTj2fJqCtONqCY=',
  subject: '032e5bd6b837cfb30208bbb1d571db9ddf2fb1a7b59fb4ed2a31af632699f770a1',
  validationKey: 'xkG+nIhcIWi90a5RbtDep7qSko4Un6iOHbOCQ6EGK2I=',
  serialNumber: 'dk4jtc5NvDFv3q4osTGKPsthzMh9KGbHGErniKcGYU8=',
  fields: {
    firstName: 'JfZF6836hO2ioST+DjTacWqb3iAUhvSnz5RIiJgJbn9cPDXfol8mdgapd3DuchzAt3neirnXSUSa/mk=',
    lastName: '4zpMIbzhyAfhkRGSS0I9Ch8bY6vfbJzR5Y/f3ywIDc5lyISXHcw+D/qmmlD6bzSnhHvyheZs',
    profilePhoto: 'hlxORYAgTNKGGJ1DDmmgenKE7rjn1H1kAznPexb09cTn6LlksoCM1DguTS4PrcBL2gxZV7QPUMkqXWsuiDQOjGeXsF3isrTsAkyp4i/zIdilNJh+ejiYlwHf+OcvcGmyAzsVT889s47dH6BlCSOD4uS/7A=='
  },
  revocationOutpoint: '48dfc2056403e3d5259c6167112418712885b920d19c16abe726e9cf0d8e96ff00000000',
  certifier: '036dc48522aba1705afbb43df3c04dbd1da373b6154341a875bceaa2a3e7f21528',
  signature: '30440220151abdc8384e083b29b79a30ecf61f6be5b74a171f60ebe79b016713ee249921022039e4b1373eba8d0006bc3d6e0b4b683cfbef5c80012c66af43e1b93575782e09'
}

const VALID_CERT = {
  type: 'z40BOInXkI8m7f/wBrv4MJ09bZfzZbTj2fJqCtONqCY=',
  subject: '032e5bd6b837cfb30208bbb1d571db9ddf2fb1a7b59fb4ed2a31af632699f770a1',
  validationKey: '/rWeLx2nSEErK9VjtgbRkhSjziO7POqlGFjC6s86nUE=',
  serialNumber: 'wUaSy3dr8fXO+MRz63mnwN8FjkYzKuMb6+pif7e2I9s=',
  fields: {
    firstName: 'nok1fRqrhDnTyufDMdkWU/DqfIgrg4sbd7BPlZ0VfI3Ej/ovdAZJwsgdTLOTV+1xp7LxTy0LhhmN6Qk=',
    lastName: 'suOYBVVXMS3PBvJOFkD48vWvVGXepqr6ZN9ifs1ynrmCJiKqCw4R2VjZtYCtQGdl5iutvvr6',
    profilePhoto: 'R+kT5mVz6Ky5n7Vt63zOqXyWLb0V0mLMO068WC0x2bNNxJfBYiUBwhJr/rnphFrbAZBv02vBbW0s56Sl1Jl2bDntnqcMf06U1Brw99OmRJZBXqkb6lVp6C9XfURgnf+A4T5MNikS8rwWEfo9/kVVlOaMWkU='
  },
  revocationOutpoint: 'bb8aa224127c78fad7f6d81ae1eb0b5776055f6531855cbbc12792dc0cc628e900000000',
  certifier: '036dc48522aba1705afbb43df3c04dbd1da373b6154341a875bceaa2a3e7f21528',
  signature: '3045022100d645b5092fc1d1c0e69e8956ea4da168a008aa10b65c90275340c66004de982f022011310c131a0c7f66fa8b450737cf81701c307122dcaa9fd45aa26248175cc64d'
}

describe('verifyCertificate', () => {
  it('Fails verifying for revoked certificate', async () => {
    const decryptedFields = await verifyCertificate(REVOKED_CERT, 'test')
    expect(decryptedFields).toEqual(false)
  })
  it('Verifies successfully for valid certificate', async () => {
    const decryptedFields = await verifyCertificate(VALID_CERT, 'test')
    expect(decryptedFields).toEqual(true)
  })
})
