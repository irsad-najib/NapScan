/*
 * Modules / Detection / Storage
 * 
 * Monitors local data storage usage.
 */

const Safe = require('../../core/safe.js');
const Loader = require('../../core/loader.js');
const Emitter = require('../../core/emitter.js');

function load() {
    
    // 1. SharedPreferences
    Safe.java('android.app.ContextImpl', function(ContextImpl) {
        Safe.hook(ContextImpl, 'getSharedPreferences', function(name, mode) {
            Emitter.emit('storage_detected', {
                type: 'SharedPreferences',
                name: name,
                mode: mode
            });
            return this.getSharedPreferences(name, mode);
        });
    });

    // 2. SQLiteDatabase
    Safe.java('android.database.sqlite.SQLiteDatabase', function(SQLite) {
        Safe.hook(SQLite, 'openDatabase', function(path, factory, flags) {
             Emitter.emit('storage_detected', {
                type: 'SQLite',
                path: path
            });
            return this.openDatabase(path, factory, flags);
        });
        
        Safe.hook(SQLite, 'openOrCreateDatabase', function(path, factory) {
             Emitter.emit('storage_detected', {
                type: 'SQLite',
                path: path
            });
            return this.openOrCreateDatabase(path, factory);
        });
    });
    
    // 3. External Storage (Environment)
    Safe.java('android.os.Environment', function(Env) {
        Safe.hook(Env, 'getExternalStorageDirectory', function() {
            Emitter.emit('storage_detected', {
                type: 'ExternalStorage',
                method: 'getExternalStorageDirectory'
            });
            return this.getExternalStorageDirectory();
        });
    });
}

Loader.register('storage', 'detection', load);
