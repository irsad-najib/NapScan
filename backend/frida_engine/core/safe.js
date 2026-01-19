/*
 * Core / Safe Execution
 * 
 * Utilities to interact with Java classes and methods without crashing the app.
 * Defensive programming is key.
 */

const Emitter = require('./emitter.js');

/*
 * Safely runs a callback with a Java class.
 * If class doesn't exist, logs it (internal debug) but doesn't crash.
 */
function safeJava(className, callback) {
    if (!Java.available) {
        return; // Not in Java environment
    }

    Java.perform(function() {
        try {
            const cls = Java.use(className);
            callback(cls);
        } catch (e) {
            // Class probably not found, or other linkage error.
            // This is expected in many apps that don't use the specific library we look for.
            // We can optionally log this in verbose mode.
            if (global.NAPSCAN && global.NAPSCAN.config.core.verbose) {
               Emitter.emit('debug_class_not_found', { class: className });
            }
        }
    });
}

/*
 * Safely hooks a method if it exists.
 * Handles:
 * - Overloads (tries to hook all, or specific checks)
 * - Missing methods
 */
function safeHook(cls, methodName, implementationInfo) {
    // implementationInfo can be a function (universal hook) or object describing overloads
    // For simplicity in this engine, we'll assume it's a replacement function that takes 'original' and args
    // But Frida hooks replace the implementation directly.
    
    // We expect the caller to provide the REPLACEMENT implementation as a function.
    // The wrapper logic here is to ensure we don't crash accessing cls[methodName].
    
    try {
        if (!cls[methodName]) {
             if (global.NAPSCAN && global.NAPSCAN.config.core.verbose) {
               Emitter.emit('debug_method_not_found', { class: cls.$className, method: methodName });
            }
            return;
        }

        const method = cls[methodName];
        
        // Deal with overloads
        const overloads = method.overloads;
        
        overloads.forEach(function(overload) {
            overload.implementation = function() {
                // Capture arguments
                const args = [].slice.call(arguments);
                const original = this; // 'this' is the instance
                
                // We delegate to the caller's implementation
                // Caller signature: (originalContext, originalMethod, args)
                // But Frida implementations are just function(...args).
                // To keep it simple, we expect the caller to return a FUNCTION that acts as the hook.
                
                return implementationInfo.apply(this, args);
            };
        });

    } catch (e) {
        Emitter.error(e, "safeHook: " + cls.$className + "." + methodName);
    }
}

/* 
 * Wrapper for trying a block of code and catching errors silently (or reporting them)
 */
function tryCatch(fn, contextName) {
    try {
        fn();
    } catch (e) {
        Emitter.error(e, contextName);
    }
}

module.exports = {
    java: safeJava,
    hook: safeHook,
    try: tryCatch
};
