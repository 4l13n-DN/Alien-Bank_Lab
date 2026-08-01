// antifrida_off.js — Desactiva detección anti-Frida / anti-debug. MASVS-RESILIENCE.
Java.perform(function () {
    try { var Debug = Java.use("android.os.Debug");
          Debug.isDebuggerConnected.implementation = function () { return false; }; } catch (e) {}
    // Si la app tiene su propia clase de detección con isFridaPresent()
    ["com.taller.bancoalien.security.FridaDetection"].forEach(function (cn) {
        try { var C = Java.use(cn);
              C.isFridaPresent.implementation = function () { console.log("[antifrida] " + cn + ".isFridaPresent -> false"); return false; }; } catch (e) {}
    });
    console.log("[antifrida] hooks instalados.");
});
