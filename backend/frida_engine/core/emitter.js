/*
 * Core / Emitter
 * 
 * Handles all output from the engine.
 * STRICTLY outputs structured JSON.
 * NO console.log() of plain text allowed.
 */

function emit(eventName, payload) {
    if (!global.NAPSCAN) {
        // Fallback if boot hasn't happened (should generally not happen)
        console.log(JSON.stringify({
            event: "fatal_error",
            message: "NAPSCAN global not initialized",
            original_event: eventName
        }));
        return;
    }

    const output = {
        timestamp: new Date().toISOString(),
        event: eventName,
        data: payload || {}
    };

    try {
        const jsonStr = JSON.stringify(output);
        const start = global.NAPSCAN.config.core.marker_start;
        const end = global.NAPSCAN.config.core.marker_end;
        
        // We use send() which is Frida's native message passing to the python/node host.
        // It is better than console.log format wise.
        // However, if the user requested console log for file piping:
        console.log(start + jsonStr + end);
        
        // Also send properly via Frida message bus if available
        // send(output); 
    } catch (e) {
        // Last resort protection against JSON stringify cycles
        console.log("{\"event\":\"emitter_error\",\"error\":\"" + e.toString() + "\"}");
    }
}

function error(err, context) {
    emit("internal_error", {
        message: err.message || err.toString(),
        stack: err.stack,
        context: context
    });
}

module.exports = {
    emit: emit,
    error: error
};
