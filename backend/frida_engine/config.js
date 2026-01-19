/*
 * NapScan Frida Engine Configuration
 * 
 * Controls module enabling/disabling, environment settings, and verbosity.
 * strictly JSON-serializable structure recommended.
 */

const Config = {
    env: "production", // 'debug' or 'production'
    
    // Core settings
    core: {
        verbose: false, // If true, might emit debug logs (structured)
        marker_start: "[[NAPSCAN_JSON_START]]",
        marker_end: "[[NAPSCAN_JSON_END]]"
    },

    // Module Toggles
    modules: {
        context: {
            enabled: true
        },
        detection: {
            ssl_pinning: {
                enabled: true
            },
            root: {
                enabled: true
            },
            anti_debug: {
                enabled: true
            },
            crypto: {
                enabled: true,
                verbose: false // Set true to log EVERY crypto call (noisy)
            },
            storage: {
                enabled: true
            },
            webview: {
                enabled: true
            }
        },
        observability: {
            network: {
                enabled: false, // Optional, can be noisy
                include_body: false
            }
        }
    }
};

// If we need to inject config from outside (e.g. Python backend injection)
// we can check for a global variable injected by the injector script.
// But for now, we use this static object.

module.exports = Config;
