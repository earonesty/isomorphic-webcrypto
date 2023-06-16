import 'react-native-get-random-values'

const grv = crypto.getRandomValues

const str2buf = require('str2buf');
const b64u = require('b64u-lite');
const b64 = require('b64-lite');

if(global.window.navigator === undefined)
  global.window.navigator = {};

global.window.navigator.userAgent = '';
global.atob = typeof atob === 'undefined' ? b64.atob : atob;
global.btoa = typeof btoa === 'undefined' ? b64.btoa : btoa;
global.msrCryptoPermanentForceSync = true;

global.crypto = require('msrcrypto');

const crypto = global.crypto

crypto.getRandomValues = grv

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
