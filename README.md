# simple-lamport
Lamport one-time signature scheme library.

## Installation

```
npm install simple-lamport
```

## Usage

```
const SimpleLamport = require('simple-lamport');

let lamport = new SimpleLamport();

// Generate private key and public key
let { privateKey, publicKey } = lamport.generateKeys();

// Sign message
let signature = lamport.sign('hello world', privateKey);

// Verify message; returns true or false
lamport.verify(message, signature, publicKey);
```

### License

MIT
