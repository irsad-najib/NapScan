/*
 * Modules / Detection / Root Check
 * 
 * Detects checks for rooted devices (su binary, test-keys, partitions).
 */

const Safe = require('../../core/safe.js');
const Loader = require('../../core/loader.js');
const Emitter = require('../../core/emitter.js');

function load() {
    
    // 1. File.exists checks for 'su'
    Safe.java('java.io.File', function(File) {
        Safe.hook(File, 'exists', function() {
            const path = this.getAbsolutePath();
            if (path.endsWith('/su') || path.includes('/superuser')) {
                 Emitter.emit('root_check_detected', {
                    method: 'File.exists',
                    path: path
                });
            }
            return this.exists();
        });
    });

    // 2. Runtime.exec (scanning for mount, ps, su commands)
    Safe.java('java.lang.Runtime', function(Runtime) {
        Safe.hook(Runtime, 'exec', function(cmd) { // handling String version
            // cmd might be string or array
            let cmdStr = "";
            if (Array.isArray(cmd)) {
                cmdStr = cmd.join(' ');
            } else {
                cmdStr = cmd ? cmd.toString() : "";
            }
            
            if (cmdStr.includes('su') || cmdStr.includes('mount') || cmdStr.includes('which')) {
                 Emitter.emit('root_check_detected', {
                    method: 'Runtime.exec',
                    command: cmdStr
                });
            }
            return this.exec(cmd);
        });
    });
    
    // 3. ProcessBuilder (often used alternative to Runtime.exec)
    Safe.java('java.lang.ProcessBuilder', function(ProcessBuilder) {
        Safe.hook(ProcessBuilder, 'start', function() {
            const cmdList = this.command();
            if (cmdList) {
                const cmdStr = cmdList.toString();
                if (cmdStr.includes('su') || cmdStr.includes('mount')) {
                     Emitter.emit('root_check_detected', {
                        method: 'ProcessBuilder.start',
                        command: cmdStr
                    });
                }
            }
            return this.start();
        });
    });

    // 4. PackageManager (checking for root apps)
    Safe.java('android.app.ApplicationPackageManager', function(PackageManager) {
        Safe.hook(PackageManager, 'getPackageInfo', function(pkgName, flags) {
             if (pkgName && (pkgName.includes('supersu') || pkgName.includes('magisk') || pkgName.includes('root'))) {
                Emitter.emit('root_check_detected', {
                    method: 'PackageManager.getPackageInfo',
                    package: pkgName
                });
             }
             return this.getPackageInfo(pkgName, flags);
        });
    });
}

Loader.register('root', 'detection', load);
