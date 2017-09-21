
# csr-gen v1.0.0 ![stable](https://img.shields.io/badge/stability-stable-4EBA0F.svg?style=flat)

```js
const generateCsr = require('csr-gen');

generateCsr({
  key: fs.readFileSync('key.pem'),
  domain: 'example.com',
  // domains: ['example.com', 'www.example.com'],
  subject: {
    email: 'you@example.com',
    country: 'US',
    state: 'CA',
    city: 'Palo Alto',
    company: 'Google',
    // division: 'DevOps', <= optional
  }
}).then(csr => {
  console.log(csr); // <= `csr` is a Buffer object
});
```

