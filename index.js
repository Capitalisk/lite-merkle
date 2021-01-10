const SimpleLamport = require('simple-lamport');
const DEFAULT_LEAF_COUNT = 32;
const HASH_ELEMENT_BYTE_SIZE = 32;
const SIG_ENTRY_COUNT = 256;
const KEY_ENTRY_COUNT = 512;
const DEFAULT_SEED_ENCODING = 'hex';
const KEY_SIG_ENCODING = 'base64';

class ProperMerkle {
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

    this.lamport = new SimpleLamport({
      keyFormat: KEY_SIG_ENCODING,
      signatureFormat: KEY_SIG_ENCODING,
      seedEncoding: this.seedEncoding
    });
  }

  generateSeed() {
    return this.lamport.generateSeed();
  }

  // Asynchronous version of the method.
  async generateMSSTree(seed, treeIndex) {
    let treeSeed = this._getTreeSeed(seed, treeIndex);
    let privateKeys = [];
    let publicKeys = [];
    let merkleLeaves = [];

    for (let i = 0; i < this.leafCount; i++) {
      let keyPair = this.lamport.generateKeysFromSeed(treeSeed, i);
      privateKeys.push(keyPair.privateKey);
      publicKeys.push(keyPair.publicKey);
      merkleLeaves.push(this.lamport.hash(keyPair.publicKey));
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
    let publicRootHash = lastLayer[0];

    return {
      treeIndex,
      privateKeys,
      publicKeys,
      tree,
      publicRootHash
    };
  }

  // Synchronous version of the method.
  generateMSSTreeSync(seed, treeIndex) {
    let treeSeed = this._getTreeSeed(seed, treeIndex);
    let privateKeys = [];
    let publicKeys = [];
    let merkleLeaves = [];

    for (let i = 0; i < this.leafCount; i++) {
      let keyPair = this.lamport.generateKeysFromSeed(treeSeed, i);
      privateKeys.push(keyPair.privateKey);
      publicKeys.push(keyPair.publicKey);
      merkleLeaves.push(this.lamport.hash(keyPair.publicKey));
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
    let publicRootHash = lastLayer[0];

    return {
      treeIndex,
      privateKeys,
      publicKeys,
      tree,
      publicRootHash
    };
  }

  sign(message, mssTree, leafIndex) {
    let privateKey = mssTree.privateKeys[leafIndex];
    let publicKey = mssTree.publicKeys[leafIndex];
    let signature = this.lamport.sign(message, privateKey);
    let authPath = this.computeAuthPath(mssTree, leafIndex);

    let signatureBuffer = Buffer.concat([
      Buffer.from(publicKey, KEY_SIG_ENCODING),
      Buffer.from(signature, KEY_SIG_ENCODING),
      Buffer.concat(authPath.map(item => Buffer.from(item, KEY_SIG_ENCODING)))
    ]);

    return this.encodeSignature(signatureBuffer);
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
    let publicKeyHash = this.lamport.hash(signaturePacket.publicKey);
    let { authPath } = signaturePacket;

    let compoundHash = publicKeyHash;
    for (let authItem of authPath) {
      compoundHash = this.computeCombinedHash(compoundHash, authItem);
    }
    return compoundHash === publicRootHash;
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
    return this.lamport.hash(`${lesserItem}${greaterItem}`);
  }

  encodeSignature(rawSignaturePacket) {
    if (this.signatureFormat === 'buffer') {
      return rawSignaturePacket;
    }
    return rawSignaturePacket.toString(this.signatureFormat);
  }

  decodeSignature(encodedSignaturePacket) {
    let signatureBuffer;
    if (this.signatureFormat === 'buffer') {
      signatureBuffer = encodedSignaturePacket;
    } else {
      signatureBuffer = Buffer.from(encodedSignaturePacket, this.signatureFormat);
    }
    let publicKeyByteLength = HASH_ELEMENT_BYTE_SIZE * KEY_ENTRY_COUNT;
    let signatureByteLength = HASH_ELEMENT_BYTE_SIZE * SIG_ENTRY_COUNT;
    let authPathByteLength = HASH_ELEMENT_BYTE_SIZE * SIG_ENTRY_COUNT;
    let authBufferOffset = publicKeyByteLength + signatureByteLength;

    let publicKey = signatureBuffer.slice(0, publicKeyByteLength).toString(KEY_SIG_ENCODING);
    let signature = signatureBuffer.slice(publicKeyByteLength, authBufferOffset).toString(KEY_SIG_ENCODING);

    let authPathBuffer = signatureBuffer.slice(authBufferOffset);
    let bufferLength = authPathBuffer.length;
    let authPathEntryCount = bufferLength / HASH_ELEMENT_BYTE_SIZE;
    let authPath = [];

    for (let i = 0; i < authPathEntryCount; i++) {
      let startOffset = i * HASH_ELEMENT_BYTE_SIZE;
      authPath.push(
        authPathBuffer.slice(startOffset, startOffset + HASH_ELEMENT_BYTE_SIZE).toString(KEY_SIG_ENCODING)
      );
    }

    return {
      publicKey,
      signature,
      authPath
    };
  }

  _getTreeSeed(seed, treeIndex) {
    return this.lamport.hmacHash(seed, this.seedEncoding, treeIndex.toString(), this.seedEncoding);
  }

  async _wait(duration) {
    return new Promise((resolve, reject) => {
      setTimeout(resolve, duration);
    });
  }
}

module.exports = ProperMerkle;
