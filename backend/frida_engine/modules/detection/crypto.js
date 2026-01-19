/*
 * Modules / Detection / Crypto Usage
 * 
 * Monitors usage of Cryptographic primitives.
 */

const Safe = require('../../core/safe.js');
const Loader = require('../../core/loader.js');
const Emitter = require('../../core/emitter.js');

function load() {
    
    // 1. Cipher.getInstance
    Safe.java('javax.crypto.Cipher', function(Cipher) {
        Safe.hook(Cipher, 'getInstance', function(transformation) {
            Emitter.emit('crypto_usage', {
                primitive: 'Cipher',
                algorithm: transformation
            });
            
            // Check for weak algos
            if (transformation.startsWith('DES') || transformation.includes('ECB')) {
                 Emitter.emit('crypto_risk', {
                    issue: 'Weak Algorithm Detected',
                    algorithm: transformation
                });
            }
            
            return this.getInstance(transformation);
        });
    });

    // 2. MessageDigest.getInstance
    Safe.java('java.security.MessageDigest', function(MD) {
        Safe.hook(MD, 'getInstance', function(algo) {
            Emitter.emit('crypto_usage', {
                primitive: 'MessageDigest',
                algorithm: algo
            });
            
             if (algo === 'MD5' || algo === 'SHA-1') {
                 Emitter.emit('crypto_risk', {
                    issue: 'Weak Hash Detected',
                    algorithm: algo
                });
            }
            
            return this.getInstance(algo);
        });
    });
    
    // 3. SecretKeySpec (Key generation)
    Safe.java('javax.crypto.spec.SecretKeySpec', function(SKS) {
        // Constructor is special in Frida: $init
        Safe.hook(SKS, '$init', function(key, algo) {
             Emitter.emit('crypto_usage', {
                primitive: 'SecretKeySpec',
                algorithm: algo,
                key_length_bytes: key ? key.length : 0 
            });
            return this.$init(key, algo);
        });
    });
}

Loader.register('crypto', 'detection', load);
