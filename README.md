# Oracle-Certs Library

`oracle-certs` is a Go library for requesting certificates from a Step CA server running on DIMO [Storage Node](https://github.com/DIMO-Network/dimo-node).
This certificate allows the external oracles to securely(using MTLS) transmit data to [DIS](https://github.com/DIMO-Network/dis) service running on DIMO Storage Node.

## Prerequisites
In order to request certificates, you need to have valid wallet which owns the connection or wallet which was granted permissions to request certificates for the connection.

### Required Parameters

To request certificates, the following parameters must be provided:

- **`ethAddress`**: The Ethereum address of the wallet that owns the connection or has permission to request certificates.
- **`privateKey`**: The private key associated with the Ethereum wallet.
- **`clientSecret`**: The client secret used for authentication with the OAuth server.
- **`oauthURL`**: The URL of the OAuth server for obtaining a JWT token.
- **`stepCAUrl`**: The URL of the Step CA server for signing the certificate.
- **`fingerprint`**: The SHA256 fingerprint of the CA certificate.
- **`connectionAddr`**: The Ethereum connection address to be included in the certificate's SAN field.

These parameters can be passed directly to the library functions or set as environment variables for convenience.

## Features

- Get JWT token using the wallet of the owner of the connection
- Exchange JWT token for TLS certificate

## Installation

To use the library, add it to your Go project using:

```bash
go get github.com/DIMO-Network/oracle-certs
