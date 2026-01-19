/*
 * Modules / Detection / Anti-Debug
 * 
 * Detects usage of debugging checks like isDebuggerConnected, ptrace, and time checks.
 */

const Safe = require('../../core/safe.js');
const Loader = require('../../core/loader.js');
const Emitter = require('../../core/emitter.js');

function load() {
    
    // 1. Android Debug Class
    Safe.java('android.os.Debug', function(Debug) {
        Safe.hook(Debug, 'isDebuggerConnected', function() {
            Emitter.emit('anti_debug_detected', {
                method: 'android.os.Debug.isDebuggerConnected',
                result: this.isDebuggerConnected() // Informational
            });
            return this.isDebuggerConnected();
        });
    });

    // 2. System Properties (ro.debuggable)
    Safe.java('android.os.SystemProperties', function(SP) {
        Safe.hook(SP, 'get', function(key) {
             if (key === 'ro.debuggable' || key === 'ro.secure') {
                 Emitter.emit('anti_debug_detected', {
                    method: 'SystemProperties.get',
                    key: key
                });
             }
             return this.get(key);
        });
    });
    
    // 3. Detect Native ptrace usage is harder in pure Java script,
    // but we can look for specific Process checks relevant to it.
    // Often apps check /proc/self/status for TracerPid
    Safe.java('java.io.File', function(File) {
        // We reuse the File hook if we can, but since hooks are per-function instance in our safe wrapper...
        // The previous File hook in 'root' module might conflict if we don't chain carefully?
        // Actually Frida allows multiple hooks on the same method. The order depends on Frida's internal handling.
        // Our 'Safe.hook' uses basic method replacement.
        // If we call Safe.hook twice on same method, the second one wraps the first one (which is now the 'original').
        // So this is SAFE.
        
        Safe.hook(File, 'getPath', function() {
             const path = this.getPath();
             if (path.includes('/proc/') && (path.includes('/status') || path.includes('/cmdline'))) {
                  Emitter.emit('anti_debug_detected', {
                    method: 'File access (proc)',
                    path: path
                });
             }
             return this.getPath();
        });
    });
}

Loader.register('anti_debug', 'detection', load);
