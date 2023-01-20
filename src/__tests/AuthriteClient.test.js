const { AuthriteClient } = require('../AuthriteClient')

describe('AuthriteClient', () => {
  it('clients share Authrite',async  () => {
    const client1 = new AuthriteClient('foo1.com')
    const client2 = new AuthriteClient('foo2.com')

    expect(client1.authrite === client2.authrite).toBe(true)
  })

  it('createSignedRequest',async  () => {
    const client1 = new AuthriteClient('foo1.com')
    const client2 = new AuthriteClient('foo2.com')

    expect(client1.authrite === client2.authrite).toBe(true)
  })
})