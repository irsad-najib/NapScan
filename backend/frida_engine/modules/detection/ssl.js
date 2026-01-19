/*
 * Modules / Detection / SSL Pinning
 * 
 * Detects common classes and methods associated with SSL Pinning and Certificate Validation.
 * Does NOT actively bypass.
 */

const Safe = require('../../core/safe.js');
const Loader = require('../../core/loader.js');
const Emitter = require('../../core/emitter.js');

function load() {
    
    // 1. TrustManagerImpl (Common Android internal)
    Safe.java('com.android.org.conscrypt.TrustManagerImpl', function(cls) {
        Safe.hook(cls, 'checkServerTrusted', function(chain, authType) {
            Emitter.emit('ssl_pinning_detected', {
                class: 'com.android.org.conscrypt.TrustManagerImpl',
                method: 'checkServerTrusted',
                backtrace: Thread.backtrace(this.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress).join('\\n')
            });
            return this.checkServerTrusted(chain, authType);
        });
    });

    // 2. OkHttp CertificatePinner
    Safe.java('okhttp3.CertificatePinner', function(cls) {
        Safe.hook(cls, 'check', function(hostname, cleanedPeerCertificates) {
             Emitter.emit('ssl_pinning_detected', {
                class: 'okhttp3.CertificatePinner',
                method: 'check',
                host: hostname
             });
             return this.check(hostname, cleanedPeerCertificates);
        });
    });

    // 3. OkHttp Builder (Pinning setup)
    Safe.java('okhttp3.OkHttpClient$Builder', function(cls) {
        Safe.hook(cls, 'certificatePinner', function(pinner) {
            Emitter.emit('ssl_pinning_detected', {
                class: 'okhttp3.OkHttpClient$Builder',
                method: 'certificatePinner',
                details: 'App is configuring CertificatePinner'
            });
            return this.certificatePinner(pinner);
        });
    });

    // 4. HttpsURLConnection (HostnameVerifier)
    Safe.java('javax.net.ssl.HttpsURLConnection', function(cls) {
        Safe.hook(cls, 'setDefaultHostnameVerifier', function(verifier) {
             Emitter.emit('ssl_pinning_detected', {
                class: 'javax.net.ssl.HttpsURLConnection',
                method: 'setDefaultHostnameVerifier',
                verifier: verifier ? verifier.toString() : 'null'
            });
            return this.setDefaultHostnameVerifier(verifier);
        });
        
        Safe.hook(cls, 'setHostnameVerifier', function(verifier) {
             Emitter.emit('ssl_pinning_detected', {
                class: 'javax.net.ssl.HttpsURLConnection',
                method: 'setHostnameVerifier',
                verifier: verifier ? verifier.$className : 'null'
            });
            return this.setHostnameVerifier(verifier);
        });
    });
}

Loader.register('ssl_pinning', 'detection', load);
