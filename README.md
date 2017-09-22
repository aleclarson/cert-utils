
# csr-gen v1.1.0 ![stable](https://img.shields.io/badge/stability-stable-4EBA0F.svg?style=flat)

```js
const generateCsr = require('csr-gen');

generateCsr({
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

### Options

- `der: boolean?` Output the CSR in DER format (defaults to `false`)
- `key: string|buffer` The private key in PEM format (required)
- `domain: string?` The validated domain, overrides `domains`
- `domains: string|array?` The validated domain(s)
- `subject: object?` The details embedded in the CSR, all keys are optional strings
  - `email`
  - `country`
  - `state`
  - `city`
  - `company`
  - `division`
