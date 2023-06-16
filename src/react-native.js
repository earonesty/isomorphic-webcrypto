import 'react-native-get-random-values'

const str2buf = require('str2buf');
const b64u = require('b64u-lite');
const b64 = require('b64-lite');

if(global.window.navigator === undefined)
  global.window.navigator = {};

global.window.navigator.userAgent = '';
global.atob = typeof atob === 'undefined' ? b64.atob : atob;
global.btoa = typeof btoa === 'undefined' ? b64.btoa : btoa;
global.msrCryptoPermanentForceSync = true;

const crypto = require('msrcrypto');

function standardizeAlgoName(algo) {
  const upper = algo.toUpperCase();
  return upper === 'RSASSA-PKCS1-V1_5' ? 'RSASSA-PKCS1-v1_5' : upper;
}

function ensureUint8Array(buffer) {
  if (typeof buffer === 'string' || buffer instanceof String)
    return str2buf.toUint8Array(buffer);
  if (!buffer) return;
  if (buffer instanceof ArrayBuffer) return new Uint8Array(buffer);
  if (buffer instanceof Uint8Array) return buffer;
  return buffer;
}

// wrap all methods to ensure they're secure
const methods = [
  'decrypt',
  'digest',
  'deriveKey',
  'encrypt',
  'exportKey',
  'generateKey',
  'importKey',
  'sign',
  'unwrapKey',
  'verify',
  'wrapKey'
]
methods.map(key => {
  const original = crypto.subtle[key]
  const proxy = function() {
    const args = Array.from(arguments)
    const before = crypto.subtle[key];
    return crypto.ensureSecure()
    .then(() => {
      const after = crypto.subtle[key];
      if (before === after) {
        return original.apply(crypto.subtle, args)
      } else {
        return crypto.subtle[key].apply(crypto.subtle, args)
      }
    });
  }
  crypto.subtle[key] = proxy;
  crypto.subtle[key].name = key;
})

const originalGenerateKey = crypto.subtle.generateKey;
crypto.subtle.generateKey = function generateKey() {
  const algo = arguments[0];
  if (algo) {
    if (algo.name) algo.name = algo.name.toLowerCase();
    if (algo.hash && algo.hash.name) algo.hash.name = algo.hash.name.toLowerCase();
  }
  return originalGenerateKey.apply(this, arguments)
  .then(res => {
    if (res.publicKey) {
      res.publicKey.usages = ['verify'];
      res.publicKey.algorithm.name = standardizeAlgoName(res.publicKey.algorithm.name);
      res.privateKey.usages = ['sign'];
      res.privateKey.algorithm.name = standardizeAlgoName(res.privateKey.algorithm.name);
    } else {
      res.algorithm.name = standardizeAlgoName(res.algorithm.name);
      res.usages = res.algorithm.name === 'HMAC' ? ['sign', 'verify'] : ['encrypt', 'decrypt'];
    }
    return res;
  });
}

const originalExportKey = crypto.subtle.exportKey;
crypto.subtle.exportKey = function exportKey() {
  const key = arguments[1];
  return originalExportKey.apply(this, arguments)
  .then(res => {
    if (res.kty === 'RSA' || res.kty === 'EC') {
      if (res.d) {
        res.key_ops = ['sign'];
      } else {
        res.key_ops = ['verify'];
      }
    }
    switch(res.alg) {
      case 'EC-256':
      case 'EC-384':
      case 'EC-521':
        delete res.alg;
    }
    return res;
  });
}

const originalDigest = crypto.subtle.digest;
crypto.subtle.digest = function digest() {
  arguments[1] = ensureUint8Array(arguments[1]);
  return originalDigest.apply(this, arguments);
}

module.exports = crypto
