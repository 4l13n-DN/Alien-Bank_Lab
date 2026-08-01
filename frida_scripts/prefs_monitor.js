// prefs_monitor.js — Muestra qué guarda la app en SharedPreferences en runtime. MASVS-STORAGE.
Java.perform(function () {
    try {
        var Ed = Java.use("android.app.SharedPreferencesImpl$EditorImpl");
        Ed.putString.implementation = function (k, v) {
            console.log("[prefs] put " + k + " = " + v); return this.putString(k, v);
        };
    } catch (e) { console.log("[prefs] " + e); }
    console.log("[prefs] monitor instalado.");
});
