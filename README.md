# simple-merkle
Merkle signature scheme client library.

## Installation

```bash
npm install simple-merkle
```

## Usage

### Basic

```js
const SimpleMerkle = require('simple-merkle');

(async () => {
  let merkle = new SimpleMerkle();

  let seed = merkle.generateSeed();

  // Generate Merkle Signature Scheme tree.
  // For synchronous call, use merkle.generateMSSTreeFromSeedSync(seed, 0)
  let mssTree = await merkle.generateMSSTreeFromSeed(seed, 0);

  let message = 'hello world';

  // Sign message; third argument is the leaf/key index in the MSS tree.
  let signature = merkle.sign(message, mssTree, 0);

  // Verify message; returns true or false.
  merkle.verify(message, signature, mssTree.publicRootHash);
})();

```

## License

MIT
