/*
 * Core / Boot
 * 
 * Initializes the global NAPSCAN namespace and runtime state.
 * Use strictly ES5 compatible JS where possible for maximum compatibility with older Android Frida runtimes,
 * though V8 usually handles ES6 fine.
 */

const Config = require('../config.js');

function init() {
    if (global.NAPSCAN) {
        return; // Already initialized
    }

    global.NAPSCAN = {
        startTime: new Date().toISOString(),
        config: Config,
        state: {
            modulesLoaded: new Set(),
            errors: []
        },
        // We will attach utilities here as they load
        utils: {}
    };

    // Prevent multiple initializations from re-running logic
    Object.freeze(global.NAPSCAN.config);
}

module.exports = {
    init: init
};
