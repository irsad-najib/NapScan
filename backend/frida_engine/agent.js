/*
 * NapScan Frida Agent
 * Mode: Passive + Soft Active (Guaranteed Report)
 * Frida 16+ | Android 10+
 * No brute force, no fake input, no state manipulation
 */

(function () {
  "use strict";

  // =========================================================================
  // CORE MARKER
  // =========================================================================
  const MARKER_START = "[[NAPSCAN_JSON_START]]";
  const MARKER_END = "[[NAPSCAN_JSON_END]]";

  function emit(event, data) {
    console.log(
      MARKER_START +
        JSON.stringify({
          timestamp: new Date().toISOString(),
          event,
          data: data || {},
        }) +
        MARKER_END,
    );
  }

  // =========================================================================
  // ENGINE BOOT (PASTI KELUAR)
  // =========================================================================
  emit("engine_start", {
    frida_version: Frida.version || "unknown",
    java_available: Java.available,
    pid: Process.id,
    arch: Process.arch,
  });

  // =========================================================================
  // ENVIRONMENT SNAPSHOT (PASTI KELUAR)
  // =========================================================================
  let env = {
    platform: Process.platform,
    pointer_size: Process.pointerSize,
    module_count: 0,
  };

  try {
    env.module_count = Process.enumerateModulesSync().length;
  } catch (_) {}

  emit("environment_snapshot", env);

  if (!Java.available) {
    emit("scan_summary", {
      success: true,
      reason: "java_not_available",
      confidence: "low",
    });
    return;
  }

  // =========================================================================
  // JAVA RUNTIME
  // =========================================================================
  Java.perform(function () {
    emit("java_runtime_ready", {});

    // =========================================================================
    // APPLICATION ATTACH (PASSIVE – PASTI)
    // =========================================================================
    try {
      const App = Java.use("android.app.Application");
      const origAttach = App.attach.overload("android.content.Context");

      origAttach.implementation = function (ctx) {
        emit("application_attached", {
          package_name: ctx.getPackageName(),
          class_loader: ctx.getClassLoader().toString(),
        });
        return origAttach.call(this, ctx);
      };
    } catch (e) {
      emit("hook_error", {
        target: "Application.attach",
        error: e.toString(),
      });
    }

    // =========================================================================
    // ACTIVITY LIFECYCLE (PASSIVE – MIN 1x)
    // =========================================================================
    try {
      const Activity = Java.use("android.app.Activity");
      const origResume = Activity.onResume.overload();

      origResume.implementation = function () {
        if (!globalThis.__NAPSCAN_ACTIVITY_RECORDED) {
          globalThis.__NAPSCAN_ACTIVITY_RECORDED = true;
          emit("first_activity_resume", {
            activity: this.getClass().getName(),
          });
        }
        return origResume.call(this);
      };
    } catch (e) {
      emit("hook_error", {
        target: "Activity.onResume",
        error: e.toString(),
      });
    }

    // =========================================================================
    // PASSIVE CAPABILITY DETECTION (NO INVOKE)
    // =========================================================================
    const capabilities = {};

    function detect(name, key) {
      try {
        Java.use(name);
        capabilities[key] = true;
      } catch (_) {
        capabilities[key] = false;
      }
    }

    detect("okhttp3.OkHttpClient", "okhttp");
    detect("android.webkit.WebView", "webview");
    detect("javax.crypto.Cipher", "crypto");
    detect("com.android.org.conscrypt.TrustManagerImpl", "conscrypt");
    detect("android.os.Debug", "anti_debug_api");

    emit("capability_snapshot", capabilities);

    // =========================================================================
    // AGGRESSIVE BUT SAFE OBSERVATION (BOOT-TIME HOOKS)
    // =========================================================================

    // ---- APPLICATION.onCreate (PASTI KEPAKAI)
    try {
      const App = Java.use("android.app.Application");
      const origCreate = App.onCreate;

      origCreate.implementation = function () {
        emit("application_on_create", {});
        return origCreate.call(this);
      };
    } catch (_) {}

    // ---- OKHTTP CLIENT BUILDER (PASTI DIPANGGIL)
    if (capabilities.okhttp) {
      try {
        const Builder = Java.use("okhttp3.OkHttpClient$Builder");
        const origBuild = Builder.build;

        origBuild.implementation = function () {
          if (!globalThis.__NAPSCAN_OKHTTP_BUILD) {
            globalThis.__NAPSCAN_OKHTTP_BUILD = true;
            emit("okhttp_client_initialized", {});
          }
          return origBuild.call(this);
        };
      } catch (_) {}
    }

    // ---- SSL CONTEXT INIT (TLS SETUP)
    try {
      const SSLContext = Java.use("javax.net.ssl.SSLContext");
      const origInit = SSLContext.init;

      origInit.implementation = function () {
        if (!globalThis.__NAPSCAN_SSL_INIT) {
          globalThis.__NAPSCAN_SSL_INIT = true;
          emit("ssl_context_initialized", {});
        }
        return origInit.apply(this, arguments);
      };
    } catch (_) {}

    // ---- CRYPTO INIT (LEBIH SERING KENA DARI getInstance)
    if (capabilities.crypto) {
      try {
        const Cipher = Java.use("javax.crypto.Cipher");
        const origInit = Cipher.init.overload("int", "java.security.Key");

        origInit.implementation = function (mode, key) {
          if (!globalThis.__NAPSCAN_CIPHER_INIT) {
            globalThis.__NAPSCAN_CIPHER_INIT = true;
            emit("crypto_cipher_initialized", {
              mode: mode,
            });
          }
          return origInit.call(this, mode, key);
        };
      } catch (_) {}
    }

    // ---- CLASSLOADER OBSERVATION (THROTTLED & SAFE)
    try {
      const CL = Java.use("java.lang.ClassLoader");
      const origLoad = CL.loadClass.overload("java.lang.String");

      origLoad.implementation = function (name) {
        if (
          !globalThis.__NAPSCAN_CLASS_OBSERVED &&
          (name.includes("okhttp") ||
            name.includes("crypto") ||
            name.includes("conscrypt"))
        ) {
          globalThis.__NAPSCAN_CLASS_OBSERVED = true;
          emit("security_related_class_loaded", {
            class_name: name,
          });
        }
        return origLoad.call(this, name);
      };
    } catch (_) {}

    // =========================================================================
    // SOFT-ACTIVE OBSERVATION (FIRST HIT ONLY)
    // =========================================================================

    // ---- CRYPTO
    if (capabilities.crypto) {
      try {
        const Cipher = Java.use("javax.crypto.Cipher");
        const origGet = Cipher.getInstance.overload("java.lang.String");

        origGet.implementation = function (algo) {
          if (!globalThis.__NAPSCAN_CRYPTO_HIT) {
            globalThis.__NAPSCAN_CRYPTO_HIT = true;
            emit("crypto_first_use", { algorithm: algo });
          }
          return origGet.call(this, algo);
        };
      } catch (_) {}
    }

    // ---- WEBVIEW
    if (capabilities.webview) {
      try {
        const WebView = Java.use("android.webkit.WebView");
        const origLoad = WebView.loadUrl.overload("java.lang.String");

        origLoad.implementation = function (url) {
          if (!globalThis.__NAPSCAN_WEBVIEW_HIT) {
            globalThis.__NAPSCAN_WEBVIEW_HIT = true;
            emit("webview_first_load", { url });
          }
          return origLoad.call(this, url);
        };
      } catch (_) {}
    }

    // ---- SSL PINNING OBSERVATION (NO BYPASS)
    if (capabilities.conscrypt) {
      try {
        const TM = Java.use("com.android.org.conscrypt.TrustManagerImpl");
        const origCheck = TM.checkServerTrusted;

        origCheck.implementation = function () {
          if (!globalThis.__NAPSCAN_SSL_HIT) {
            globalThis.__NAPSCAN_SSL_HIT = true;
            emit("ssl_trust_manager_used", {
              class: TM.$className,
            });
          }
          return origCheck.apply(this, arguments);
        };
      } catch (_) {}
    }

    // ---- ANTI DEBUG OBSERVATION
    if (capabilities.anti_debug_api) {
      try {
        const Debug = Java.use("android.os.Debug");
        const origDbg = Debug.isDebuggerConnected;

        origDbg.implementation = function () {
          emit("anti_debug_checked", {
            api: "isDebuggerConnected",
          });
          return origDbg.call(this);
        };
      } catch (_) {}
    }
  });

  // =========================================================================
  // FINAL GUARANTEED SUMMARY (PASTI KELUAR)
  // =========================================================================
  setTimeout(function () {
    emit("scan_summary", {
      success: true,
      mode: "passive_plus_soft_active",
      bruteforce: false,
      interaction_required: false,
      confidence: "high",
    });
  }, 3000);
})();
