
# cert-utils v1.2.0 ![stable](https://img.shields.io/badge/stability-stable-4EBA0F.svg?style=flat)

> npm install aleclarson/cert-utils#1.2.0

```js
const certUtils = require('cert-utils');
```

### certUtils.der(cert)

Convert a certificate to DER format.

```js
certUtils.der(
  fs.readFileSync('cert.pem')
).then(cert => {
  console.log(cert); // <= `cert` is a Buffer object
});
```

### certUtils.req(options)

Generate a CSR in either PEM or DER format.

**Options:**
- `key: string|buffer` The private key in PEM format
- `format: string?` The output format (defaults to `PEM`)
- `domain: string?` The validated domain, overrides `domains`
- `domains: string|array?` The validated domain(s)
- `subject: object?` The details embedded in the CSR, all keys are optional strings
  - `email`
  - `country`
  - `state`
  - `city`
  - `company`
  - `division`

```js
certUtils.req({
  key: fs.readFileSync('key.pem'),
  domain: 'example.com',
  subject: {
    email: 'you@example.com',
    country: 'US',
    state: 'CA',
    city: 'Palo Alto',
    company: 'Google',
  }
}).then(csr => {
  console.log(csr); // <= `csr` is a Buffer object
});
```
