const assert = require('assert');
const ProperMerkle = require('../index');
const hash = require('hash.js');

describe('Unit tests', async () => {
  let merkle;

  beforeEach(async () => {
    merkle = new ProperMerkle({
      leafCount: 32,
      signatureFormat: 'base64'
    });
  });

  describe('Generate MSS tree from seed', async () => {
    it('should return a valid MSS tree from seed', async () => {
      let seed = merkle.generateSeed();
      let mssTree = await merkle.generateMSSTree(seed, 'main-0');

      assert.equal('treeName' in mssTree, true);
      assert.equal('privateKeys' in mssTree, true);
      assert.equal('publicKeys' in mssTree, true);
      assert.equal('tree' in mssTree, true);
      assert.equal('publicRootHash' in mssTree, true);
    });
  });

  describe('Generate MSS tree from seed sync', async () => {
    it('should return a valid MSS tree from seed', async () => {
      let seed = merkle.generateSeed();
      let mssTree = merkle.generateMSSTreeSync(seed, 'main-0');

      assert.equal('treeName' in mssTree, true);
      assert.equal('privateKeys' in mssTree, true);
      assert.equal('publicKeys' in mssTree, true);
      assert.equal('tree' in mssTree, true);
      assert.equal('publicRootHash' in mssTree, true);
    });
  });

  describe('Sign', async () => {
    let seed;
    let mssTree;
    let publicRootHash;

    beforeEach(async () => {
      seed = merkle.generateSeed();
      mssTree = await merkle.generateMSSTree(seed, 'main-0');
      publicRootHash = mssTree.publicRootHash;
    });

    it('should return signature as a string with the correct length', async () => {
      let signature = merkle.sign('test message', mssTree, 0);
      assert.equal(Buffer.byteLength(signature, 'base64'), 512 * 32 + 256 * 32 + 32 * 5);
    });
  });

  describe('Verify', async () => {
    let seed;
    let mssTree;
    let publicRootHash;

    beforeEach(async () => {
      seed = merkle.generateSeed();
      mssTree = await merkle.generateMSSTree(seed, 'main-0');
      publicRootHash = mssTree.publicRootHash;
    });

    it('should return true if signature is valid', async () => {
      let message = 'hello world';
      let signature = merkle.sign(message, mssTree, 0);
      let verified = merkle.verify(message, signature, publicRootHash);
      assert.equal(verified, true);
    });

    it('should return false if signature is not valid', async () => {
      let message = 'hello world';
      let signature = merkle.sign(message, mssTree, 0);
      let verified = merkle.verify('different message', signature, publicRootHash);
      assert.equal(verified, false);
    });
  });
});
