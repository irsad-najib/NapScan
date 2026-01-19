/*
 * NapScan Frida Engine - Entrypoint
 * 
 * This is the ONLY file that needs to be injected into the target application.
 * It bootstraps the core system, loads the config, and initializes all modules.
 */

// Import Core
const Boot = require('./core/boot.js');
const Emitter = require('./core/emitter.js');
const Loader = require('./core/loader.js');

// Import Modules (Static requires to ensure they are bundled if using typical bundlers, 
// though Frida handles require relatively well for local files in recent versions.
// If not using frida-compile, this relies on Frida's internal module resolution).

// We need to require them so they register themselves via Loader.register
require('./modules/context.js');
require('./modules/detection/ssl.js');
require('./modules/detection/root.js');
require('./modules/detection/antidebug.js');
require('./modules/detection/crypto.js');
require('./modules/detection/storage.js');
require('./modules/detection/webview.js');

// Main Execution Block
function main() {
    try {
        // 1. Initialize Global State
        Boot.init();
        
        Emitter.emit('engine_start', {
            version: '1.0.0',
            timestamp: new Date().toISOString()
        });

        // 2. Load Modules
        Loader.loadEnabledModules();
        
        Emitter.emit('engine_ready', {
            loaded_modules: Array.from(global.NAPSCAN.state.modulesLoaded)
        });
        
    } catch (e) {
        // Fallback error logging
        console.log(JSON.stringify({
            event: "fatal_init_error",
            error: e.toString(),
            stack: e.stack
        }));
    }
}

// Execute
if (Java.available) {
    Java.perform(main);
} else {
    // Maybe native process?
    Emitter.emit('warning', {
        message: 'Java runtime not available. Some modules may not work.'
    });
    main();
}
