/*
 * Modules / Context
 * 
 * Be gathers static information about the application context.
 */

const Safe = require('../core/safe.js');
const Loader = require('../core/loader.js');
const Emitter = require('../core/emitter.js');

function load() {
    Safe.java('android.app.ActivityThread', function(ActivityThread) {
        Safe.try(function() {
            const currentApplication = ActivityThread.currentApplication();
            const context = currentApplication.getApplicationContext();
            
            const packageName = context.getPackageName();
            const pm = context.getPackageManager();
            const pkgInfo = pm.getPackageInfo(packageName, 0);
            
            const appInfo = {
                packageName: packageName,
                versionName: pkgInfo.versionName.value,
                versionCode: pkgInfo.versionCode.value,
                appName: pkgInfo.applicationInfo.value.loadLabel(pm).toString(),
                dataDir: pkgInfo.applicationInfo.value.dataDir.value,
                targetSdkVersion: pkgInfo.applicationInfo.value.targetSdkVersion.value
            };
            
            Emitter.emit('app_info', appInfo);
            
            // Check debuggable flag
            const flags = pkgInfo.applicationInfo.value.flags.value;
            const DEBUGGABLE = 2;
            const isDebuggable = (flags & DEBUGGABLE) !== 0;
            
            if (isDebuggable) {
                Emitter.emit('security_risk', {
                    type: 'debug_flag',
                    details: 'Application is debuggable (android:debuggable="true")'
                });
            }

        }, 'ContextDiscovery');
    });
}

Loader.register('context', 'context', load);
