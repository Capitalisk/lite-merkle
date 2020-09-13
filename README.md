# proper-merkle
Merkle signature scheme client library.

## Overview

This library provides a quantum-resistant mechanism for cryptographically signing messages such that multiple signatures can be associated with a single public key.
It supports generating an unlimited number of MSS trees of various sizes from a single secret seed; this allows a single seed to be used to sign an unlimited number of messages.
Lamport OTS is used as the underlying one-time signature scheme.

## Installation

```bash
npm install proper-merkle
```

## Usage

### Basic

```js
const ProperMerkle = require('proper-merkle');l

(async () => {
  // The leafCount option represents the number of signatures which can be generated
  // from a single MSS tree. Trees with more leaves take longer to compute.
  let merkle = new ProperMerkle({
    leafCount: 128,
    signatureFormat: 'base64'
  });

  let seed = merkle.generateSeed();

  // Generate Merkle Signature Scheme tree; second argument is the index of the tree.
  // An unlimited number of MSS trees can be generated from a single seed.
  // For synchronous call, use generateMSSTreeSync method.
  let mssTree = await merkle.generateMSSTree(seed, 0);

  let message = 'hello world';

  // Sign message; third argument is the leaf/key index within the MSS tree.
  // Each leaf index should only be used once (to produce a single signature).
  let signature = merkle.sign(message, mssTree, 0);

  // Verify message; returns true or false.
  // publicRootHash is the Merkle root; it should be used as the public key.
  merkle.verify(message, signature, mssTree.publicRootHash);
})();

```

### Signing unlimited messages

Generating large MSS trees is expensive so it is recommended to generate smaller trees and to chain them together.
This can be achieved by using one of the keys (leaves) from the current MSS tree to sign a message which contains the `publicRootHash` of the next MSS tree in the `generateMSSTree` sequence (at currentIndex + 1); it's important to do this before the current MSS tree runs out of keys. Never use the same key/leaf index multiple times.

## License

MIT
