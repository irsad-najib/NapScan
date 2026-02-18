/*
 * NapScan Dominator Engine (Research Grade)
 * Mode: passive | active | aggressive
 * High Visibility Instrumentation Framework
 */

(function () {
  "use strict";

  // =====================================================
  // CONFIG
  // =====================================================
  const CONFIG = {
    mode: "aggressive", // passive | active | aggressive
    max_events: 5000,
    enable_native_hooks: true,
    enable_intent_probe: true,
    throttle_native: true,
  };

  const MARKER_START = "[[NAPSCAN_JSON_START]]";
  const MARKER_END = "[[NAPSCAN_JSON_END]]";

  let STATE = {
    events: 0,
    modules: {},
  };

  function emit(event, data) {
    if (STATE.events >= CONFIG.max_events) return;
    STATE.events++;

    console.log(
      MARKER_START +
        JSON.stringify({
          ts: new Date().toISOString(),
          mode: CONFIG.mode,
          event,
          data: data || {},
        }) +
        MARKER_END,
    );
  }

  function mark(module) {
    STATE.modules[module] = true;
  }

  emit("engine_start", {
    frida: Frida.version,
    pid: Process.id,
    arch: Process.arch,
  });

  if (!Java.available) {
    emit("java_unavailable", {});
    return;
  }

  // =====================================================
  // JAVA LAYER
  // =====================================================
  Java.perform(function () {
    emit("java_ready", {});

    // -----------------------------------------------
    // Universal Overload Hooker
    // -----------------------------------------------
    function hookAll(clazz, method) {
      try {
        clazz[method].overloads.forEach(function (ov) {
          ov.implementation = function () {
            mark(clazz.$className);
            emit("method_call", {
              class: clazz.$className,
              method: method,
            });
            return ov.apply(this, arguments);
          };
        });
      } catch (_) {}
    }

    // -----------------------------------------------
    // Lifecycle
    // -----------------------------------------------
    try {
      const Activity = Java.use("android.app.Activity");
      hookAll(Activity, "onResume");
    } catch (_) {}

    // -----------------------------------------------
    // Crypto Analyzer
    // -----------------------------------------------
    try {
      const Cipher = Java.use("javax.crypto.Cipher");
      hookAll(Cipher, "getInstance");
      hookAll(Cipher, "init");
      mark("crypto");
    } catch (_) {}

    // -----------------------------------------------
    // SSL Analyzer
    // -----------------------------------------------
    try {
      const SSLContext = Java.use("javax.net.ssl.SSLContext");
      hookAll(SSLContext, "init");
      mark("ssl");
    } catch (_) {}

    try {
      const TM = Java.use("com.android.org.conscrypt.TrustManagerImpl");

      TM.checkServerTrusted.implementation = function () {
        mark("ssl_trust");
        emit("ssl_validation_invoked", {});

        return this.checkServerTrusted.apply(this, arguments);
      };
    } catch (_) {}

    // -----------------------------------------------
    // OkHttp Monitor
    // -----------------------------------------------
    try {
      const Builder = Java.use("okhttp3.OkHttpClient$Builder");
      hookAll(Builder, "build");
      mark("network");
    } catch (_) {}

    // -----------------------------------------------
    // WebView Monitor
    // -----------------------------------------------
    try {
      const WebView = Java.use("android.webkit.WebView");
      hookAll(WebView, "loadUrl");
      mark("webview");
    } catch (_) {}

    // -----------------------------------------------
    // Reflection Exposure
    // -----------------------------------------------
    try {
      const Class = Java.use("java.lang.Class");
      hookAll(Class, "getDeclaredMethods");
      hookAll(Class, "getDeclaredFields");
      mark("reflection");
    } catch (_) {}

    // -----------------------------------------------
    // File System Monitoring
    // -----------------------------------------------
    try {
      const FIS = Java.use("java.io.FileInputStream");
      FIS.$init.overload("java.lang.String").implementation = function (path) {
        mark("filesystem");
        emit("file_read", { path: path });
        return this.$init(path);
      };
    } catch (_) {}

    // -----------------------------------------------
    // SharedPreferences
    // -----------------------------------------------
    try {
      const SP = Java.use("android.app.SharedPreferencesImpl");
      hookAll(SP, "getString");
      mark("sharedprefs");
    } catch (_) {}

    // -----------------------------------------------
    // SQLite Monitoring
    // -----------------------------------------------
    try {
      const SQLite = Java.use("android.database.sqlite.SQLiteDatabase");
      hookAll(SQLite, "execSQL");
      mark("sqlite");
    } catch (_) {}

    // -----------------------------------------------
    // ClassLoader Surveillance
    // -----------------------------------------------
    try {
      const CL = Java.use("java.lang.ClassLoader");
      CL.loadClass.overload("java.lang.String").implementation = function (
        name,
      ) {
        if (
          name.toLowerCase().includes("crypto") ||
          name.toLowerCase().includes("ssl") ||
          name.toLowerCase().includes("auth") ||
          name.toLowerCase().includes("keystore")
        ) {
          emit("security_class_loaded", { name });
        }

        return this.loadClass.call(this, name);
      };
    } catch (_) {}

    // -----------------------------------------------
    // Intent Probe (Controlled)
    // -----------------------------------------------
    if (CONFIG.enable_intent_probe && CONFIG.mode !== "passive") {
      try {
        const ActivityThread = Java.use("android.app.ActivityThread");
        const app = ActivityThread.currentApplication();
        const ctx = app.getApplicationContext();

        emit("intent_probe_ready", {
          package: ctx.getPackageName(),
        });
      } catch (_) {}
    }
  });

  // =====================================================
  // NATIVE LAYER
  // =====================================================
  if (CONFIG.enable_native_hooks) {
    try {
      const openPtr = Module.findExportByName(null, "open");
      if (openPtr) {
        Interceptor.attach(openPtr, {
          onEnter(args) {
            if (CONFIG.throttle_native && STATE.events > 3000) return;
            emit("native_open", {
              path: args[0].readCString(),
            });
          },
        });
      }
    } catch (_) {}

    try {
      const sslWrite = Module.findExportByName("libssl.so", "SSL_write");
      if (sslWrite) {
        Interceptor.attach(sslWrite, {
          onEnter(args) {
            emit("native_ssl_write", {});
          },
        });
      }
    } catch (_) {}
  }

  // =====================================================
  // MEMORY PATTERN SCAN (PASSIVE)
  // =====================================================
  try {
    Process.enumerateModulesSync().forEach(function (m) {
      Memory.scan(m.base, m.size, "6170695f6b6579", {
        onMatch: function (addr) {
          emit("memory_pattern_possible_api_key", {
            module: m.name,
            address: addr.toString(),
          });
        },
        onComplete: function () {},
      });
    });
  } catch (_) {}

  // =====================================================
  // SUMMARY
  // =====================================================
  setTimeout(function () {
    emit("scan_summary", {
      modules_triggered: Object.keys(STATE.modules),
      total_events: STATE.events,
      mode: CONFIG.mode,
      profile: "high_visibility_research",
    });
  }, 6000);
})();
