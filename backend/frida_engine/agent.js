/*
 * NapScan Frida Engine - Single Core Agent (DEV LOG VERBOSE)
 * Frida 16+ / QuickJS / Android 11+
 */

(function () {
  "use strict";

  // =========================================================================
  // 1. CONFIGURATION (DEV MODE)
  // =========================================================================
  const Config = {
    core: {
      marker_start: "[[NAPSCAN_JSON_START]]",
      marker_end: "[[NAPSCAN_JSON_END]]",
    },
    modules: {
      context: { enabled: true },
      detection: {
        ssl_pinning: { enabled: true },
        root: { enabled: true },
        anti_debug: { enabled: true },
        crypto: { enabled: true },
        storage: { enabled: true },
        webview: { enabled: true },
      },
    },
  };

  // =========================================================================
  // 2. CORE
  // =========================================================================
  const Boot = {
    init() {
      if (globalThis.NAPSCAN) return;

      globalThis.NAPSCAN = {
        startTime: new Date().toISOString(),
        config: Config,
        state: {
          modulesLoaded: new Set(),
          errors: [],
        },
      };

      Object.freeze(globalThis.NAPSCAN.config);
    },
  };

  const Emitter = {
    emit(event, data) {
      try {
        const payload = {
          timestamp: new Date().toISOString(),
          event,
          data: data || {},
        };
        console.log(
          Config.core.marker_start +
            JSON.stringify(payload) +
            Config.core.marker_end,
        );
      } catch (e) {
        console.log('{"event":"emit_error","error":"' + e.toString() + '"}');
      }
    },
    error(err, ctx) {
      this.emit("internal_error", {
        message: err.toString(),
        context: ctx,
      });
    },
  };

  // =========================================================================
  // 3. LOADER
  // =========================================================================
  const registry = new Map();

  const Loader = {
    register(name, category, fn) {
      registry.set(name, { category, fn });
    },

    load(name, fn) {
      if (globalThis.NAPSCAN.state.modulesLoaded.has(name)) return;

      Emitter.emit("module_loading", { name });
      fn();
      globalThis.NAPSCAN.state.modulesLoaded.add(name);
      Emitter.emit("module_loaded", { name });
    },

    loadAll() {
      registry.forEach((m, name) => {
        const enabled =
          Config.modules[m.category] &&
          Config.modules[m.category][name] &&
          Config.modules[m.category][name].enabled !== false;

        Emitter.emit("module_decision", {
          module: name,
          category: m.category,
          enabled,
        });

        if (enabled) this.load(name, m.fn);
      });
    },
  };

  // =========================================================================
  // 4. SAFE HELPERS
  // =========================================================================
  const Safe = {
    java(name, cb) {
      if (!Java.available) return;
      Java.perform(() => {
        try {
          cb(Java.use(name));
        } catch (_) {
          Emitter.emit("class_not_found", { class: name });
        }
      });
    },

    hook(cls, method, impl) {
      try {
        const overloads = cls[method]?.overloads;
        if (!overloads) return;

        overloads.forEach((o) => {
          o.implementation = function () {
            Emitter.emit("hook_hit", {
              class: cls.$className,
              method,
            });
            return impl.apply(this, arguments);
          };
        });

        Emitter.emit("hook_installed", {
          class: cls.$className,
          method,
          overloads: overloads.length,
        });
      } catch (e) {
        Emitter.error(e, cls.$className + "." + method);
      }
    },
  };

  // =========================================================================
  // 5. MODULES
  // =========================================================================

  // CONTEXT
  Loader.register("context", "context", function () {
    Safe.java("android.app.Application", (App) => {
      Safe.hook(App, "attach", function (ctx) {
        this.attach(ctx);
        Emitter.emit("context_attached", {
          package: ctx.getPackageName(),
        });
      });
    });
  });

  // SSL PINNING
  Loader.register("ssl_pinning", "detection", function () {
    Safe.java("com.android.org.conscrypt.TrustManagerImpl", (T) => {
      Safe.hook(T, "checkServerTrusted", function () {
        Emitter.emit("ssl_pinning_detected", {
          class: T.$className,
        });
        return this.checkServerTrusted.apply(this, arguments);
      });
    });

    Safe.java("okhttp3.CertificatePinner", (C) => {
      Safe.hook(C, "check", function (host) {
        Emitter.emit("ssl_pinning_detected", {
          class: C.$className,
          host,
        });
        return this.check.apply(this, arguments);
      });
    });
  });

  // ANTI DEBUG
  Loader.register("anti_debug", "detection", function () {
    Safe.java("android.os.Debug", (D) => {
      Safe.hook(D, "isDebuggerConnected", function () {
        Emitter.emit("anti_debug_detected", {
          api: "isDebuggerConnected",
        });
        return this.isDebuggerConnected();
      });
    });
  });

  // ROOT
  Loader.register("root", "detection", function () {
    Safe.java("java.lang.Runtime", (R) => {
      Safe.hook(R, "exec", function (cmd) {
        Emitter.emit("root_check", {
          command: cmd.toString(),
        });
        return this.exec(cmd);
      });
    });
  });

  // CRYPTO
  Loader.register("crypto", "detection", function () {
    Safe.java("javax.crypto.Cipher", (C) => {
      Safe.hook(C, "getInstance", function (algo) {
        Emitter.emit("crypto_usage", { algorithm: algo });
        return this.getInstance(algo);
      });
    });
  });

  // STORAGE
  Loader.register("storage", "detection", function () {
    Safe.java("android.database.sqlite.SQLiteDatabase", (DB) => {
      Safe.hook(DB, "openDatabase", function (path) {
        Emitter.emit("storage_access", { path });
        return this.openDatabase.apply(this, arguments);
      });
    });
  });

  // WEBVIEW
  Loader.register("webview", "detection", function () {
    Safe.java("android.webkit.WebView", (W) => {
      Safe.hook(W, "loadUrl", function (url) {
        Emitter.emit("webview_load", { url });
        return this.loadUrl(url);
      });
    });
  });

  // =========================================================================
  // 6. BOOT
  // =========================================================================
  Boot.init();

  Emitter.emit("engine_start", {
    version: "dev",
  });

  // HEARTBEAT
  setInterval(() => {
    Emitter.emit("engine_heartbeat", {
      uptime_ms: Date.now() - new Date(globalThis.NAPSCAN.startTime).getTime(),
      loaded_modules: Array.from(globalThis.NAPSCAN.state.modulesLoaded),
    });
  }, 3000);

  function main() {
    Emitter.emit("java_runtime_ready", {});
    Loader.loadAll();
    Emitter.emit("engine_ready", {
      modules: Array.from(globalThis.NAPSCAN.state.modulesLoaded),
    });
  }

  Java.available ? Java.perform(main) : main();
})();
