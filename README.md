# authrite-utils

This package offers essential utility functions used by [authrite-js](https://github.com/p2ppsr/authrite-js) for tasks like mutual authentication. Additionally, it provides a valuable resource for those looking to implement the Authrite specification on a communication channel not yet supported.

## API

<!-- Generated by documentation.js. Update this documentation by updating the source code. -->

#### Table of Contents

*   [createRequestSignature](#createrequestsignature)
    *   [Parameters](#parameters)
*   [getCertificatesToInclude](#getcertificatestoinclude)
    *   [Parameters](#parameters-1)
*   [getRequestAuthHeaders](#getrequestauthheaders)
    *   [Parameters](#parameters-2)
*   [verifyServerInitialResponse](#verifyserverinitialresponse)
    *   [Parameters](#parameters-3)
*   [verifyServerResponse](#verifyserverresponse)
    *   [Parameters](#parameters-4)
*   [getResponseAuthHeaders](#getresponseauthheaders)
    *   [Parameters](#parameters-5)
*   [validateAuthHeaders](#validateauthheaders)
    *   [Parameters](#parameters-6)
*   [validateCertificates](#validatecertificates)
    *   [Parameters](#parameters-7)
*   [verifyCertificate](#verifycertificate)
    *   [Parameters](#parameters-8)
*   [verifyCertificateSignature](#verifycertificatesignature)
    *   [Parameters](#parameters-9)
*   [decryptCertificateFields](#decryptcertificatefields)
    *   [Parameters](#parameters-10)
*   [certifierInitialResponse](#certifierinitialresponse)
    *   [Parameters](#parameters-11)
*   [certifierSignCheckArgs](#certifiersigncheckargs)
    *   [Parameters](#parameters-12)
*   [certifierCreateSignedCertificate](#certifiercreatesignedcertificate)
    *   [Parameters](#parameters-13)
*   [decryptOwnedCertificateField](#decryptownedcertificatefield)
    *   [Parameters](#parameters-14)
*   [decryptOwnedCertificateFields](#decryptownedcertificatefields)
    *   [Parameters](#parameters-15)
*   [decryptOwnedCertificates](#decryptownedcertificates)
    *   [Parameters](#parameters-16)

### createRequestSignature

Creates a valid ECDSA message signature to include in an Authrite request

#### Parameters

*   `obj` **[object](https://developer.mozilla.org/docs/Web/JavaScript/Reference/Global_Objects/Object)** all params given in an object

    *   `obj.dataToSign` **([string](https://developer.mozilla.org/docs/Web/JavaScript/Reference/Global_Objects/String) | [buffer](https://nodejs.org/api/buffer.html))** the data that should be signed with the derived private key
    *   `obj.requestNonce` **[string](https://developer.mozilla.org/docs/Web/JavaScript/Reference/Global_Objects/String)** random data provided by the client
    *   `obj.serverInitialNonce` **[string](https://developer.mozilla.org/docs/Web/JavaScript/Reference/Global_Objects/String)** random session data provided by the server
    *   `obj.clientPrivateKey` **[string](https://developer.mozilla.org/docs/Web/JavaScript/Reference/Global_Objects/String)?** optional private key to use as the signing strategy
    *   `obj.serverPublicKey` **[string](https://developer.mozilla.org/docs/Web/JavaScript/Reference/Global_Objects/String)** the identity key of the server the request should be sent to

### getCertificatesToInclude

Provide a list of certificates with acceptable type and certifier values for the request, based on what the server requested

#### Parameters

*   `obj` **[object](https://developer.mozilla.org/docs/Web/JavaScript/Reference/Global_Objects/Object)** all params provided in an object

    *   `obj.signingStrategy` **[string](https://developer.mozilla.org/docs/Web/JavaScript/Reference/Global_Objects/String)** specifies which signing strategy should be used
    *   `obj.servers` **[object](https://developer.mozilla.org/docs/Web/JavaScript/Reference/Global_Objects/Object)** the servers the current Authrite instance is interacting with
    *   `obj.certificates` **[Array](https://developer.mozilla.org/docs/Web/JavaScript/Reference/Global_Objects/Array)** the current available certificates
    *   `obj.baseUrl` &#x20;

### getRequestAuthHeaders

Construct BRC-31 compliant authentication headers to send to the server
Note: Currently assumes initial param validation has been done. TODO: Add it here as well
Note: Also doesn't currently support the initial request response here. TODO: add it here as well

#### Parameters

*   `obj` **[object](https://developer.mozilla.org/docs/Web/JavaScript/Reference/Global_Objects/Object)** all params given in an object

    *   `obj.authriteVersion` **[string](https://developer.mozilla.org/docs/Web/JavaScript/Reference/Global_Objects/String)** the current version of Authrite being used
    *   `obj.clientPublicKey` **[string](https://developer.mozilla.org/docs/Web/JavaScript/Reference/Global_Objects/String)** of the current client making the request
    *   `obj.requestNonce` **[string](https://developer.mozilla.org/docs/Web/JavaScript/Reference/Global_Objects/String)** random nonce provided by the client
    *   `obj.serverInitialNonce` **[string](https://developer.mozilla.org/docs/Web/JavaScript/Reference/Global_Objects/String)** initial session nonce provided by the server
    *   `obj.requestSignature` **[string](https://developer.mozilla.org/docs/Web/JavaScript/Reference/Global_Objects/String)** message signature provided as a hex string
    *   `obj.certificatesToInclude` **[Array](https://developer.mozilla.org/docs/Web/JavaScript/Reference/Global_Objects/Array)** authrite certificates provided to the server upon request
    *   `obj.clientInitialNonce` &#x20;

Returns **[object](https://developer.mozilla.org/docs/Web/JavaScript/Reference/Global_Objects/Object)** valid auth headers

### verifyServerInitialResponse

Verifies a server's initial response as part of the initial handshake

#### Parameters

*   `obj` **[object](https://developer.mozilla.org/docs/Web/JavaScript/Reference/Global_Objects/Object)** all params given in an object

    *   `obj.authriteVersion` **[string](https://developer.mozilla.org/docs/Web/JavaScript/Reference/Global_Objects/String)** the current version of Authrite being used by the server
    *   `obj.baseUrl` **[string](https://developer.mozilla.org/docs/Web/JavaScript/Reference/Global_Objects/String)** the baseUrl of the server
    *   `obj.signingStrategy` **[string](https://developer.mozilla.org/docs/Web/JavaScript/Reference/Global_Objects/String)** specifies which signing strategy should be used
    *   `obj.clientPrivateKey` **([string](https://developer.mozilla.org/docs/Web/JavaScript/Reference/Global_Objects/String) | [buffer](https://nodejs.org/api/buffer.html) | [undefined](https://developer.mozilla.org/docs/Web/JavaScript/Reference/Global_Objects/undefined))?** clientPrivateKey to use for key derivation
    *   `obj.clients` **[object](https://developer.mozilla.org/docs/Web/JavaScript/Reference/Global_Objects/Object)** object whose keys are base URLs and whose values are instances of the Client class
    *   `obj.servers` **[object](https://developer.mozilla.org/docs/Web/JavaScript/Reference/Global_Objects/Object)** object whose keys are base URLs and whose values are instances of the Server class
    *   `obj.serverResponse` **[object](https://developer.mozilla.org/docs/Web/JavaScript/Reference/Global_Objects/Object)** contains the server's response including the required authentication data
    *   `obj.certificates` **[Array](https://developer.mozilla.org/docs/Web/JavaScript/Reference/Global_Objects/Array)** the current available certificates

### verifyServerResponse

Verifies a server's response after the initial handshake has happened

#### Parameters

*   `obj` **[object](https://developer.mozilla.org/docs/Web/JavaScript/Reference/Global_Objects/Object)** all params given in an object

    *   `obj.messageToVerify` **[string](https://developer.mozilla.org/docs/Web/JavaScript/Reference/Global_Objects/String)** the message signed to verify
    *   `obj.headers` **[object](https://developer.mozilla.org/docs/Web/JavaScript/Reference/Global_Objects/Object)** the authentication headers provided by the server
    *   `obj.baseUrl` **[string](https://developer.mozilla.org/docs/Web/JavaScript/Reference/Global_Objects/String)** the baseUrl of the server
    *   `obj.signingStrategy` **[string](https://developer.mozilla.org/docs/Web/JavaScript/Reference/Global_Objects/String)** specifies which signing strategy should be used
    *   `obj.clients` **[object](https://developer.mozilla.org/docs/Web/JavaScript/Reference/Global_Objects/Object)** the clients the current Authrite instance is interacting with
    *   `obj.servers` **[object](https://developer.mozilla.org/docs/Web/JavaScript/Reference/Global_Objects/Object)** the servers the current Authrite instance is interacting with
    *   `obj.clientPrivateKey` **([string](https://developer.mozilla.org/docs/Web/JavaScript/Reference/Global_Objects/String) | [buffer](https://nodejs.org/api/buffer.html) | [undefined](https://developer.mozilla.org/docs/Web/JavaScript/Reference/Global_Objects/undefined))?** clientPrivateKey to use for key derivation

### getResponseAuthHeaders

Constructs the required server response headers for a given client
Supports initial request, and subsequent requests

#### Parameters

*   `obj` **[object](https://developer.mozilla.org/docs/Web/JavaScript/Reference/Global_Objects/Object)** all params given in an object

    *   `obj.authrite` **[string](https://developer.mozilla.org/docs/Web/JavaScript/Reference/Global_Objects/String)** the version of authrite being used
    *   `obj.messageType` **[string](https://developer.mozilla.org/docs/Web/JavaScript/Reference/Global_Objects/String)** type of message to respond to
    *   `obj.serverPrivateKey` **[string](https://developer.mozilla.org/docs/Web/JavaScript/Reference/Global_Objects/String)** server private key to use to derive the signing private key
    *   `obj.clientPublicKey` **[string](https://developer.mozilla.org/docs/Web/JavaScript/Reference/Global_Objects/String)** public key of the sender
    *   `obj.clientNonce` **[string](https://developer.mozilla.org/docs/Web/JavaScript/Reference/Global_Objects/String)** random data provided by the client
    *   `obj.serverNonce` **[string](https://developer.mozilla.org/docs/Web/JavaScript/Reference/Global_Objects/String)** random data provided by the server
    *   `obj.messageToSign` **[string](https://developer.mozilla.org/docs/Web/JavaScript/Reference/Global_Objects/String)** expected message to be signed (optional, default `'test'`)
    *   `obj.certificates` **[Array](https://developer.mozilla.org/docs/Web/JavaScript/Reference/Global_Objects/Array)** provided certificates as requested by the client (optional, default `[]`)
    *   `obj.requestedCertificates` **[Array](https://developer.mozilla.org/docs/Web/JavaScript/Reference/Global_Objects/Array)** a structure indicating which certificates the client should provide

Returns **[object](https://developer.mozilla.org/docs/Web/JavaScript/Reference/Global_Objects/Object)** the required response headers for authentication

### validateAuthHeaders

Used to validate client auth headers provided in a request

#### Parameters

*   `obj` **[object](https://developer.mozilla.org/docs/Web/JavaScript/Reference/Global_Objects/Object)** all params given in an object

    *   `obj.messageToSign` **[string](https://developer.mozilla.org/docs/Web/JavaScript/Reference/Global_Objects/String)** the message signed when the signature was created
    *   `obj.authHeaders` **[object](https://developer.mozilla.org/docs/Web/JavaScript/Reference/Global_Objects/Object)** provided by the client for authentication
    *   `obj.serverPrivateKey` **[string](https://developer.mozilla.org/docs/Web/JavaScript/Reference/Global_Objects/String)** server private key to use to derive the signingPublicKey

Returns **[boolean](https://developer.mozilla.org/docs/Web/JavaScript/Reference/Global_Objects/Boolean)** the validation result

### validateCertificates

Validates an array of certificates provided in a request

#### Parameters

*   `obj` **[object](https://developer.mozilla.org/docs/Web/JavaScript/Reference/Global_Objects/Object)** all params given in an object

    *   `obj.serverPrivateKey` **[string](https://developer.mozilla.org/docs/Web/JavaScript/Reference/Global_Objects/String)** the server's private key to use in the field decryption process
    *   `obj.identityKey` **identityKey** of the client initiating the request
    *   `obj.certificates` **[Array](https://developer.mozilla.org/docs/Web/JavaScript/Reference/Global_Objects/Array)** provided to the server by the client

Returns **([Array](https://developer.mozilla.org/docs/Web/JavaScript/Reference/Global_Objects/Array) | [object](https://developer.mozilla.org/docs/Web/JavaScript/Reference/Global_Objects/Object))** array of the validated certificates, or an Error object to return to the client

### verifyCertificate

Verifies a certificate signature, structure, and revocation status

#### Parameters

*   `certificate` &#x20;
*   `chain` &#x20;

### verifyCertificateSignature

Verifies that the provided certificate has a valid signature. Also checks
the structure of the certificate. Throws errors if the certificate is
invalid.

#### Parameters

*   `certificate` **[Object](https://developer.mozilla.org/docs/Web/JavaScript/Reference/Global_Objects/Object)** The certificate to verify.

Returns **[Boolean](https://developer.mozilla.org/docs/Web/JavaScript/Reference/Global_Objects/Boolean)** true if the certificate is valid

### decryptCertificateFields

Verifies that the provided certificate has a valid signature

#### Parameters

*   `certificate` **[Object](https://developer.mozilla.org/docs/Web/JavaScript/Reference/Global_Objects/Object)** The certificate to verify.
*   `keyring` **[Object](https://developer.mozilla.org/docs/Web/JavaScript/Reference/Global_Objects/Object)** The keyring containing the encrypted fieldRevelationKeys.
*   `verifierPrivateKey` **[string](https://developer.mozilla.org/docs/Web/JavaScript/Reference/Global_Objects/String)** A private key as a base64 string belonging to the certificate verifier. If not provided, the BabbageSDK decrypt function will be used instead.

Returns **[Object](https://developer.mozilla.org/docs/Web/JavaScript/Reference/Global_Objects/Object)** An object containing the decrypted fields.

### certifierInitialResponse

Authrite Certifier Helper Function
Creates a response object in the standard format for initialRequest.

#### Parameters

*   `obj` **[Object](https://developer.mozilla.org/docs/Web/JavaScript/Reference/Global_Objects/Object)** All parameters for this function are provided in an object

    *   `obj.clientNonce` **[string](https://developer.mozilla.org/docs/Web/JavaScript/Reference/Global_Objects/String)?** random data selected by client. Typically 32 bytes in base64 encoding.
    *   `obj.certifierPrivateKey` **[string](https://developer.mozilla.org/docs/Web/JavaScript/Reference/Global_Objects/String)?** Certifier's private key. 32 random bytes in hex encoding.
    *   `obj.certificateType` **[string](https://developer.mozilla.org/docs/Web/JavaScript/Reference/Global_Objects/String)?** Certificate type identifier. 32 bytes in base64 encoding.

### certifierSignCheckArgs

Authrite Certifier Helper Function
Checks the standard inputs to signCertificate for common errors.
Returns null on success (no errors).
Returns an object like { code: 'ERR\_INVALID\_REQUEST', description: '...' } on failure.

#### Parameters

*   `obj` **[Object](https://developer.mozilla.org/docs/Web/JavaScript/Reference/Global_Objects/Object)** All parameters for this function are provided in an object

    *   `obj.clientNonce` **[string](https://developer.mozilla.org/docs/Web/JavaScript/Reference/Global_Objects/String)?** random data selected by client. Typically 32 bytes in base64 encoding.
    *   `obj.certifierPrivateKey` **[string](https://developer.mozilla.org/docs/Web/JavaScript/Reference/Global_Objects/String)?** Certifier's private key. 32 random bytes in hex encoding.
    *   `obj.certificateType` **[string](https://developer.mozilla.org/docs/Web/JavaScript/Reference/Global_Objects/String)?** Certificate type identifier. 32 bytes in base64 encoding.
    *   `obj.messageType` **[string](https://developer.mozilla.org/docs/Web/JavaScript/Reference/Global_Objects/String)?** Must be the string 'certificateSigningRequest'.
    *   `obj.type` **[string](https://developer.mozilla.org/docs/Web/JavaScript/Reference/Global_Objects/String)?** The requested certificate type. Must equal certificateType.
    *   `obj.serverSerialNonce` **[string](https://developer.mozilla.org/docs/Web/JavaScript/Reference/Global_Objects/String)?** The serialNonce value returned by prior initialRequest.
    *   `obj.serverValidationNonce` **[string](https://developer.mozilla.org/docs/Web/JavaScript/Reference/Global_Objects/String)?** The validationNonce value returned by prior initialRequest.
    *   `obj.serialNumber` **[string](https://developer.mozilla.org/docs/Web/JavaScript/Reference/Global_Objects/String)?** The serialNumber value returned by prior initialRequest.
    *   `obj.validationKey` **[string](https://developer.mozilla.org/docs/Web/JavaScript/Reference/Global_Objects/String)?** The validationKey value returned by prior initialRequest.

### certifierCreateSignedCertificate

Authrite Certifier Helper Function
Checks the standard inputs to signCertificate for common errors.
Returns null on success (no errors).
Returns an object like { code: 'ERR\_INVALID\_REQUEST', description: '...' } on failure.

#### Parameters

*   `obj` **[Object](https://developer.mozilla.org/docs/Web/JavaScript/Reference/Global_Objects/Object)** All parameters for this function are provided in an object

    *   `obj.validationKey` **[string](https://developer.mozilla.org/docs/Web/JavaScript/Reference/Global_Objects/String)?** The validationKey value returned by prior initialRequest.
    *   `obj.certifierPrivateKey` **[string](https://developer.mozilla.org/docs/Web/JavaScript/Reference/Global_Objects/String)?** Certifier's private key. 32 random bytes in hex encoding.
    *   `obj.certificateType` **[string](https://developer.mozilla.org/docs/Web/JavaScript/Reference/Global_Objects/String)?** Certificate type identifier. 32 bytes in base64 encoding.
    *   `obj.serialNumber` **[string](https://developer.mozilla.org/docs/Web/JavaScript/Reference/Global_Objects/String)?** The serialNumber value returned by prior initialRequest.
    *   `obj.clientNonce` **[string](https://developer.mozilla.org/docs/Web/JavaScript/Reference/Global_Objects/String)?** random data selected by client. Typically 32 bytes in base64 encoding.
    *   `obj.messageType` **[string](https://developer.mozilla.org/docs/Web/JavaScript/Reference/Global_Objects/String)?** Must be the string 'certificateSigningRequest'.
    *   `obj.type` **[string](https://developer.mozilla.org/docs/Web/JavaScript/Reference/Global_Objects/String)?** The requested certificate type. Must equal certificateType.
    *   `obj.serverSerialNonce` **[string](https://developer.mozilla.org/docs/Web/JavaScript/Reference/Global_Objects/String)?** The serialNonce value returned by prior initialRequest.
    *   `obj.serverValidationNonce` **[string](https://developer.mozilla.org/docs/Web/JavaScript/Reference/Global_Objects/String)?** The validationNonce value returned by prior initialRequest.
    *   `obj.subject` &#x20;
    *   `obj.fields` &#x20;
    *   `obj.revocationOutpoint` &#x20;

### decryptOwnedCertificateField

Decrypts a single certificate field for client-only use.

#### Parameters

*   `obj` **[Object](https://developer.mozilla.org/docs/Web/JavaScript/Reference/Global_Objects/Object)** All parameters are provided in an object

    *   `obj.certificate` **[Object](https://developer.mozilla.org/docs/Web/JavaScript/Reference/Global_Objects/Object)** The certificate with a field to decrypt
    *   `obj.fieldName` **[String](https://developer.mozilla.org/docs/Web/JavaScript/Reference/Global_Objects/String)** The name of the field to decrypt
    *   `obj.callerAgreesToKeepDataClientSide` **[Boolean](https://developer.mozilla.org/docs/Web/JavaScript/Reference/Global_Objects/Boolean)** Whether the caller of this function agrees to keep the data client-side (optional, default `false`)

Returns **[Promise](https://developer.mozilla.org/docs/Web/JavaScript/Reference/Global_Objects/Promise)<[String](https://developer.mozilla.org/docs/Web/JavaScript/Reference/Global_Objects/String)>** The decrypted field value for client-side-only use

### decryptOwnedCertificateFields

Decrypts all fields in a certificate for client-only use.

#### Parameters

*   `certificate` **[Object](https://developer.mozilla.org/docs/Web/JavaScript/Reference/Global_Objects/Object)** The certificate containing fields to decrypt
*   `callerAgreesToKeepDataClientSide` **[Boolean](https://developer.mozilla.org/docs/Web/JavaScript/Reference/Global_Objects/Boolean)** Whether the caller of this function agrees to keep the data client-side (optional, default `false`)

Returns **[Promise](https://developer.mozilla.org/docs/Web/JavaScript/Reference/Global_Objects/Promise)<[Object](https://developer.mozilla.org/docs/Web/JavaScript/Reference/Global_Objects/Object)>** Decrypted fields object for client-side-only use

### decryptOwnedCertificates

Searches for user certificates, returning decrypted certificate fields for client-side-only use

#### Parameters

*   `$0` **[Object](https://developer.mozilla.org/docs/Web/JavaScript/Reference/Global_Objects/Object)**&#x20;

    *   `$0.certifiers` &#x20;
    *   `$0.types` &#x20;
    *   `$0.callerAgreesToKeepDataClientSide`   (optional, default `false`)

Returns **[Promise](https://developer.mozilla.org/docs/Web/JavaScript/Reference/Global_Objects/Promise)<[Array](https://developer.mozilla.org/docs/Web/JavaScript/Reference/Global_Objects/Array)<[Object](https://developer.mozilla.org/docs/Web/JavaScript/Reference/Global_Objects/Object)>>** The set of decrypted certificates for client-only use

## License

The license for the code in this repository is the Open BSV License.
