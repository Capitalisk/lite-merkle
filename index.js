const SimpleLamport = require('simple-lamport');
const DEFAULT_LEAF_COUNT = 128;

class SimpleMerkle {
  constructor(options) {
    options = options || {};

    let leafCount = options.leafCount == null ? DEFAULT_LEAF_COUNT : options.leafCount;
    let power = Math.log2(leafCount);
    if (power % 1 !== 0) {
      throw new Error('The leafCount option must be a power of 2');
    }
    this.leafCount = leafCount;

    this.lamport = new SimpleLamport({
      keyFormat: options.keyFormat,
      signatureFormat: options.signatureFormat,
      hashEncoding: options.hashEncoding,
      hashElementByteSize: options.hashElementByteSize,
      seedEncoding: options.seedEncoding,
      seedByteSize: options.seedByteSize,
      hashFunction: options.hashFunction,
    });
  }

  generateSeed() {
    return this.lamport.generateSeed();
  }

  generateMSSTreeFromSeed(seed, treeIndex) {
    let treeSeed = `${seed}-${treeIndex}`;
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
    let signaturePacket = {
      publicKey,
      signature,
      authPath,
      treeIndex: mssTree.treeIndex,
      leafIndex
    };

    // TODO 222: Optimize serialization

    return Buffer.from(JSON.stringify(signaturePacket), 'utf8').toString('base64');
  }

  verify(message, signature, publicRootHash) {
    let signaturePacket;
    try {
      signaturePacket = JSON.parse(Buffer.from(signature, 'base64').toString('utf8'));
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
}

module.exports = SimpleMerkle;
