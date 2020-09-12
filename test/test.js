const assert = require('assert');
const SimpleMerkle = require('../index');
const hash = require('hash.js');

describe('Unit tests', async () => {

  let merkle;

  beforeEach(async () => {
    merkle = new SimpleMerkle({
      seedEncoding: 'hex',
      hashEncoding: 'base64'
    });
  });

  describe('Generate keys from seed', async () => {
    it('should return a valid private key and public key pair from seed', async () => {
      let seed = merkle.generateSeed();
      let mssTree = merkle.generateMSSTreeFromSeed(seed, 0);
    });
  });

  describe('Sign', async () => {
    let privateKey;
    let publicKey;

    beforeEach(async () => {
      let keyPair = merkle.generateKeys();
      privateKey = keyPair.privateKey;
      publicKey = keyPair.publicKey;
    });

    it('should return signature as a string made up of 256 entries', async () => {
      let signature = merkle.sign('test message', privateKey);
      let rawSignature = JSON.parse(signature);
      assert.equal(rawSignature.length, 256);
    });
  });

  describe('Verify', async () => {
    let seed;
    let mssTree;
    let publicRootHash;

    beforeEach(async () => {
      seed = merkle.generateSeed();
      mssTree = merkle.generateMSSTreeFromSeed(seed, 0);
      publicRootHash = mssTree.publicRootHash;
    });

    it.only('should return true if signature is valid', async () => {
      let message = 'hello world';
      let signature = merkle.sign(message, mssTree, 0);
      console.log(55555, signature.length); // TODO 222
      let verified = merkle.verify(message, signature, publicRootHash);
      assert.equal(verified, true);
    });

    it('should return false if signature is not valid', async () => {
      let message = 'hello world';
      let signature = merkle.sign(message, privateKey);
      let badSignature = merkle.sign('different message', privateKey);
      let verified = merkle.verify(message, badSignature, publicKey);
      assert.equal(verified, false);
    });
  });
});
