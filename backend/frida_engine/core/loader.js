const Emitter = require('./emitter.js');

// Internal registry of available modules
const registry = new Map();

function loadModule(name, loadFunction) {
    if (global.NAPSCAN.state.modulesLoaded.has(name)) {
        return;
    }

    try {
        Emitter.emit('module_loading', { name: name });
        loadFunction();
        global.NAPSCAN.state.modulesLoaded.add(name);
        Emitter.emit('module_loaded', { name: name });
    } catch (e) {
        Emitter.error(e, "ModuleLoad: " + name);
    }
}

/*
 * Registers a module for potential loading.
 * Does NOT load it immediately.
 */
function register(moduleName, category, implFn) {
    registry.set(moduleName, {
        category: category,
        implFn: implFn
    });
}

/*
 * Iterates through registered modules and loads them if enabled in config.
 */
function loadEnabledModules() {
    const config = global.NAPSCAN.config;
    
    registry.forEach((mod, moduleName) => {
        let enabled = true;
        const category = mod.category;
        
        // Check config
        if (config.modules[category]) {
            if (config.modules[category][moduleName]) {
                 enabled = config.modules[category][moduleName].enabled;
            } else if (config.modules[category].enabled === false) {
                enabled = false;
            }
        }
        
        if (enabled) {
            loadModule(moduleName, mod.implFn);
        }
    });
}

module.exports = {
    register: register,
    loadEnabledModules: loadEnabledModules
};
