const hash = require('hash.js');
const randomBytes = require('randombytes');

class SimpleLamport {
  constructor(options) {
    options = options || {};
    this.encoding = options.encoding || 'base64';
    if (options.hashFunction) {
      this.hash = options.hashFunction;
    } else {
      this.hash = this.sha256;
    }
    this.byteSize = options.byteSize || 32;
  }

  sha256(message, encoding) {
    let shasum = hash.sha256().update(message).digest('hex');
    if (encoding === 'hex') {
      return shasum;
    }
    return Buffer.from(shasum, 'hex').toString(encoding);
  }

  generateRandomArray(length, byteSize) {
    let randomArray = [];
    for (let i = 0; i < length; i++) {
      randomArray.push(randomBytes(byteSize).toString(this.encoding));
    }
    return randomArray;
  }

  convertEncodedStringToBitArray(encodedString) {
    let buffer = Buffer.from(encodedString, this.encoding);

    let bitArray = [];
    for (let byte of buffer) {
      for (let i = 0; i < 8; i++) {
        bitArray.push(byte >> (7 - i) & 1);
      }
    }
    return bitArray;
  }

  generateKeys() {
    let privateKey = [
      this.generateRandomArray(256, this.byteSize),
      this.generateRandomArray(256, this.byteSize)
    ];

    let publicKey = privateKey.map((privateKeyPart) => {
      return privateKeyPart.map((encodedString) => this.hash(encodedString, this.encoding));
    });

    return {
      privateKey: JSON.stringify(privateKey),
      publicKey: JSON.stringify(publicKey)
    };
  }

  sign(message, privateKey) {
    let privateKeyRaw = JSON.parse(privateKey);
    let messageHash = this.sha256(message, this.encoding);
    let messageBitArray = this.convertEncodedStringToBitArray(messageHash);
    let signature = messageBitArray.map((bit, index) => privateKeyRaw[bit][index]);

    return JSON.stringify(signature);
  }

  verify(message, signature, publicKey) {
    let signatureRaw = JSON.parse(signature);
    let publicKeyRaw = JSON.parse(publicKey);
    let messageHash = this.sha256(message, this.encoding);
    let messageBitArray = this.convertEncodedStringToBitArray(messageHash);

    return messageBitArray.every((bit, index) => {
      let signatureItemHash = this.hash(signatureRaw[index], this.encoding);
      let targetPublicKeyItem = publicKeyRaw[bit][index];
      return signatureItemHash === targetPublicKeyItem;
    });
  }
}

module.exports = SimpleLamport;
