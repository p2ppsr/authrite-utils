const sdk = require('@babbage/sdk')
const { Authrite } = require('authrite-js')

/**
 * Helper class for making signed authrite requests to a specific server.
 * 
 * Shares a common Authrite instance to allow caching for certificates.
 */
class AuthriteClient {
    constructor(serverURL) {
        // Authrite caches certificates for multiple clients.
        // For performance, there should be only one.
        if (!AuthriteClient.Authrite) {
            AuthriteClient.Authrite = new Authrite()
        }

        this.serverURL = serverURL
    }

    async createSignedRequest(path, body) {
        let result = await AuthriteClient.Authrite.request(
            `${this.serverURL}${path}`,
            {
                body,
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                }
            }
        )
        result = JSON.parse(Buffer.from(result.body).toString('utf8'))
        if (typeof result === 'object' && result.status === 'error') {
            const e = new Error(result.description)
            Object
                .keys(result)
                .filter(x => x !== 'status' && x !== 'description')
                .forEach(x => { e[x] = result[x] })
            throw e
        }
        return result
    }

    async createCertificate({
        certificateType,
        fieldObject,
        certifierUrl,
        certifierPublicKey
    }) {
        const certificate = await sdk.createCertificate({
            certificateType,
            fieldObject,
            certifierUrl,
            certifierPublicKey
        })
        AuthriteClient.Authrite.addCertificate(certificate)
        return certificate
    }
}

module.exports = {
    AuthriteClient
}
