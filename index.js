const LiteLamport = require('lite-lamport');

const DEFAULT_LEAF_COUNT = 64;
const HASH_ELEMENT_BYTE_SIZE = 32;
const SEED_BYTE_SIZE = 32;
const DEFAULT_SEED_ENCODING = 'base64';
const DEFAULT_NODE_ENCODING = 'base64';
const KEY_SIG_ENCODING = 'base64';
const KEY_ENTRY_COUNT = 264;

class LiteMerkle {
  constructor(options) {
    options = options || {};
    this.signatureFormat = options.signatureFormat || 'base64';

    let leafCount = options.leafCount == null ? DEFAULT_LEAF_COUNT : options.leafCount;
    let power = Math.log2(leafCount);
    if (power % 1 !== 0) {
      throw new Error('The leafCount option must be a power of 2');
    }
    this.leafCount = leafCount;
    this.asyncPauseAfterCount = options.asyncPauseAfterCount || 5;
    this.seedEncoding = options.seedEncoding || DEFAULT_SEED_ENCODING;
    this.nodeEncoding = options.nodeEncoding || DEFAULT_NODE_ENCODING;

    this.lamport = new LiteLamport({
      keyFormat: KEY_SIG_ENCODING,
      signatureFormat: KEY_SIG_ENCODING,
      seedEncoding: this.seedEncoding
    });
  }

  generateSeed() {
    return this.lamport.generateSeed();
  }

  // Asynchronous version of the method.
  async generateMSSTree(seed, treeName) {
    let treeSeed = this.deriveSeed(seed, treeName);
    let privateKeys = [];
    let publicKeys = [];
    let merkleLeaves = [];

    for (let i = 0; i < this.leafCount; i++) {
      let keyPair = this.lamport.generateKeysFromSeed(treeSeed, i);
      privateKeys.push(keyPair.privateKey);
      publicKeys.push(keyPair.publicKey);
      merkleLeaves.push(this.lamport.sha256(keyPair.publicKey, this.nodeEncoding));
      if (i % this.asyncPauseAfterCount === 0) {
        await this._wait(0);
      }
    }

    let tree = [merkleLeaves];
    let lastLayer = merkleLeaves;

    while (lastLayer.length > 1) {
      let currentLayer = [];
      let len = lastLayer.length;

      for (let i = 0; i < len; i += 2) {
        let leftItem = lastLayer[i];
        let rightItem = lastLayer[i + 1];
        let combinedHash = this.computeCombinedHash(leftItem, rightItem);
        currentLayer.push(combinedHash);
        if (i % this.asyncPauseAfterCount === 0) {
          await this._wait(0);
        }
      }
      tree.push(currentLayer);
      lastLayer = currentLayer;
    }

    return {
      treeName,
      privateKeys,
      publicKeys,
      tree,
      publicRootHash: lastLayer[0]
    };
  }

  // Synchronous version of the method.
  generateMSSTreeSync(seed, treeName) {
    let treeSeed = this.deriveSeed(seed, treeName);
    let privateKeys = [];
    let publicKeys = [];
    let merkleLeaves = [];

    for (let i = 0; i < this.leafCount; i++) {
      let keyPair = this.lamport.generateKeysFromSeed(treeSeed, i);
      privateKeys.push(keyPair.privateKey);
      publicKeys.push(keyPair.publicKey);
      merkleLeaves.push(this.lamport.sha256(keyPair.publicKey, this.nodeEncoding));
    }

    let tree = [merkleLeaves];
    let lastLayer = merkleLeaves;

    while (lastLayer.length > 1) {
      let currentLayer = [];
      let len = lastLayer.length;

      for (let i = 0; i < len; i += 2) {
        let leftItem = lastLayer[i];
        let rightItem = lastLayer[i + 1];
        let combinedHash = this.computeCombinedHash(leftItem, rightItem);
        currentLayer.push(combinedHash);
      }
      tree.push(currentLayer);
      lastLayer = currentLayer;
    }

    return {
      treeName,
      privateKeys,
      publicKeys,
      tree,
      publicRootHash: lastLayer[0]
    };
  }

  sign(message, mssTree, leafIndex) {
    let privateKey = mssTree.privateKeys[leafIndex];
    let publicKey = mssTree.publicKeys[leafIndex];
    let authPath = this.computeAuthPath(mssTree, leafIndex);
    let signature = this.lamport.sign(message, privateKey);

    return this.encodeSignature({
      publicKey,
      authPath,
      signature
    });
  }

  verify(message, signature, publicRootHash) {
    let signaturePacket;
    try {
      signaturePacket = this.decodeSignature(signature);
    } catch (error) {
      return false;
    }
    let signatureIsValid = this.lamport.verify(message, signaturePacket.signature, signaturePacket.publicKey);
    if (!signatureIsValid) {
      return false;
    }
    return this.verifyPublicKey(signaturePacket.publicKey, signaturePacket.authPath, publicRootHash);
  }

  verifyPublicKey(publicKey, authPath, publicRootHash) {
    let publicKeyHash = this.lamport.sha256(publicKey, this.nodeEncoding);
    let compoundHash = publicKeyHash;
    for (let authItem of authPath) {
      compoundHash = this.computeCombinedHash(compoundHash, authItem);
    }
    return compoundHash === publicRootHash;
  }

  verifyPrivateKey(privateKey, authPath, publicRootHash) {
    let publicKey = this.lamport.getPublicKeyFromPrivateKey(privateKey);
    return this.verifyPublicKey(publicKey, authPath, publicRootHash);
  }

  computeAuthPath(mssTree, leafIndex) {
    let { tree } = mssTree;
    let authPath = [];
    let treeMaxIndex = tree.length - 1;
    let currentIndex = leafIndex;

    for (let i = 0; i < treeMaxIndex; i++) {
      let currentLayer = tree[i];
      let isEven = currentIndex % 2 === 0;
      let sibling = isEven ? currentLayer[currentIndex + 1] : currentLayer[currentIndex - 1];
      authPath.push(sibling);
      currentIndex = currentIndex >> 1;
    }

    return authPath;
  }

  computeCombinedHash(stringA, stringB) {
    let lesserItem;
    let greaterItem;
    if (stringA > stringB) {
      greaterItem = stringA;
      lesserItem = stringB;
    } else {
      greaterItem = stringB;
      lesserItem = stringA;
    }
    return this.lamport.sha256(`${lesserItem}${greaterItem}`, this.nodeEncoding);
  }

  encodeSignature({publicKey, authPath, signature}) {
    let signaturePacket = Buffer.concat([
      Buffer.from(publicKey, KEY_SIG_ENCODING),
      Buffer.concat(authPath.map(item => Buffer.from(item, this.nodeEncoding))),
      Buffer.from(signature, KEY_SIG_ENCODING)
    ]);

    if (this.signatureFormat === 'buffer') {
      return signaturePacket;
    }
    return signaturePacket.toString(this.signatureFormat);
  }

  decodeSignature(encodedSignaturePacket) {
    let signatureBuffer;
    if (this.signatureFormat === 'buffer') {
      signatureBuffer = encodedSignaturePacket;
    } else {
      signatureBuffer = Buffer.from(encodedSignaturePacket, this.signatureFormat);
    }
    let publicKeyByteLength = HASH_ELEMENT_BYTE_SIZE * KEY_ENTRY_COUNT;
    let authPathEntryCount = Math.log2(this.leafCount);
    let authPathByteLength = HASH_ELEMENT_BYTE_SIZE * authPathEntryCount;
    let signatureBufferOffset = publicKeyByteLength + authPathByteLength;

    let publicKey = signatureBuffer.slice(0, publicKeyByteLength).toString(KEY_SIG_ENCODING);

    let authPathBuffer = signatureBuffer.slice(publicKeyByteLength, signatureBufferOffset);
    let authPath = [];

    for (let i = 0; i < authPathEntryCount; i++) {
      let startOffset = i * HASH_ELEMENT_BYTE_SIZE;
      authPath.push(
        authPathBuffer.slice(startOffset, startOffset + HASH_ELEMENT_BYTE_SIZE).toString(this.nodeEncoding)
      );
    }

    let signature = signatureBuffer.slice(signatureBufferOffset).toString(KEY_SIG_ENCODING);

    return {
      publicKey,
      authPath,
      signature
    };
  }

  deriveSeed(seed, treeName) {
    let seedBuffer = Buffer.from(seed, this.seedEncoding);
    if (seedBuffer.byteLength < SEED_BYTE_SIZE) {
      throw new Error(
        `Failed to derive new seed for tree name ${
          treeName
        } because the specified seed encoded as ${
          this.seedEncoding
        } did not meet the minimum seed length requirement of ${
          SEED_BYTE_SIZE
        } bytes - Check that the seed encoding is correct`
      );
    }
    return this.lamport.hmacSha256(seed, this.seedEncoding, treeName, this.seedEncoding);
  }

  async _wait(duration) {
    return new Promise((resolve, reject) => {
      setTimeout(resolve, duration);
    });
  }
}

module.exports = LiteMerkle;
