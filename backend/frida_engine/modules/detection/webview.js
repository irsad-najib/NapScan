/*
 * Modules / Detection / WebView
 * 
 * Monitors WebView configuration for security risks.
 */

const Safe = require('../../core/safe.js');
const Loader = require('../../core/loader.js');
const Emitter = require('../../core/emitter.js');

function load() {
    
    // 1. WebSettings (JavaScript enabled, etc)
    Safe.java('android.webkit.WebSettings', function(WebSettings) {
        Safe.hook(WebSettings, 'setJavaScriptEnabled', function(flag) {
            if (flag) {
                Emitter.emit('webview_risk', {
                    issue: 'JavaScript Enabled',
                    details: 'setJavaScriptEnabled(true) called'
                });
            }
            return this.setJavaScriptEnabled(flag);
        });
        
        Safe.hook(WebSettings, 'setAllowFileAccess', function(flag) {
            if (flag) {
                Emitter.emit('webview_risk', {
                    issue: 'File Access Enabled',
                    details: 'setAllowFileAccess(true) called'
                });
            }
            return this.setAllowFileAccess(flag);
        });
    });

    // 2. WebView (addJavascriptInterface)
    Safe.java('android.webkit.WebView', function(WebView) {
        Safe.hook(WebView, 'addJavascriptInterface', function(obj, name) {
             Emitter.emit('webview_risk', {
                issue: 'JavascriptInterface Added',
                interfaceName: name,
                objectClass: obj ? obj.$className : 'unknown'
            });
            return this.addJavascriptInterface(obj, name);
        });
        
        Safe.hook(WebView, 'loadUrl', function(url) {
            if (url && url.toLowerCase().startsWith('javascript:')) {
                 Emitter.emit('webview_risk', {
                    issue: 'javascript: URL loaded',
                    details: url.substring(0, 50) + "..." // Truncate for sanity
                });
            }
            return this.loadUrl(url);
        });
    });
}

Loader.register('webview', 'detection', load);
