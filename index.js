const hash = require('hash.js');
const randomBytes = require('randombytes');

class SimpleLamport {
  constructor(options) {
    options = options || {};
    this.hashEncoding = options.hashEncoding || 'base64';
    this.hashElementByteSize = options.hashElementByteSize || 32;
    this.seedEncoding = options.seedEncoding || 'hex';
    this.seedByteSize = options.seedByteSize || 32;
    if (options.hashFunction) {
      this.hash = options.hashFunction;
    } else {
      this.hash = this.sha256;
    }
  }

  generateSeed() {
    return randomBytes(this.seedByteSize).toString(this.seedEncoding);
  }

  generateKeysFromSeed(seed, index) {
    if (index == null) {
      index = 0;
    }
    let privateKey = [
      this.generateRandomArrayFromSeed(256, `${seed}-${index}-a`),
      this.generateRandomArrayFromSeed(256, `${seed}-${index}-b`)
    ];

    let publicKey = privateKey.map((privateKeyPart) => {
      return privateKeyPart.map((encodedString) => this.hash(encodedString, this.hashEncoding));
    });

    return {
      privateKey: JSON.stringify(privateKey),
      publicKey: JSON.stringify(publicKey)
    };
  }

  generateKeys() {
    let privateKey = [
      this.generateRandomArray(256, this.hashElementByteSize),
      this.generateRandomArray(256, this.hashElementByteSize)
    ];

    let publicKey = privateKey.map((privateKeyPart) => {
      return privateKeyPart.map((encodedString) => this.hash(encodedString, this.hashEncoding));
    });

    return {
      privateKey: JSON.stringify(privateKey),
      publicKey: JSON.stringify(publicKey)
    };
  }

  sign(message, privateKey) {
    let privateKeyRaw = JSON.parse(privateKey);
    let messageHash = this.sha256(message, this.hashEncoding);
    let messageBitArray = this.convertEncodedStringToBitArray(messageHash);
    let signature = messageBitArray.map((bit, index) => privateKeyRaw[bit][index]);

    return JSON.stringify(signature);
  }

  verify(message, signature, publicKey) {
    let signatureRaw = JSON.parse(signature);
    let publicKeyRaw = JSON.parse(publicKey);
    let messageHash = this.sha256(message, this.hashEncoding);
    let messageBitArray = this.convertEncodedStringToBitArray(messageHash);

    return messageBitArray.every((bit, index) => {
      let signatureItemHash = this.hash(signatureRaw[index], this.hashEncoding);
      let targetPublicKeyItem = publicKeyRaw[bit][index];
      return signatureItemHash === targetPublicKeyItem;
    });
  }

  sha256(message, encoding) {
    let shasum = hash.sha256().update(message).digest('hex');
    if (encoding === 'hex') {
      return shasum;
    }
    return Buffer.from(shasum, 'hex').toString(encoding || 'base64');
  }

  generateRandomArray(length, elementBytes) {
    let randomArray = [];
    for (let i = 0; i < length; i++) {
      randomArray.push(randomBytes(elementBytes).toString(this.hashEncoding));
    }
    return randomArray;
  }

  generateRandomArrayFromSeed(length, seed) {
    let randomArray = [];
    for (let i = 0; i < length; i++) {
      randomArray.push(this.hash(`${seed}-${i}`).toString(this.hashEncoding));
    }
    return randomArray;
  }

  convertEncodedStringToBitArray(encodedString) {
    let buffer = Buffer.from(encodedString, this.hashEncoding);

    let bitArray = [];
    for (let byte of buffer) {
      for (let i = 0; i < 8; i++) {
        bitArray.push(byte >> (7 - i) & 1);
      }
    }
    return bitArray;
  }
}

module.exports = SimpleLamport;
