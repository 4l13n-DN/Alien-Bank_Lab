// flagsecure_off.js — Quita FLAG_SECURE para permitir capturas de pantalla. MASVS-PLATFORM.
Java.perform(function () {
    try {
        var Window = Java.use("android.view.Window");
        Window.setFlags.overload('int', 'int').implementation = function (f, m) {
            var SECURE = 0x2000; f = f & ~SECURE; m = m & ~SECURE;
            console.log("[flagsecure] FLAG_SECURE removido -> capturas permitidas");
            return this.setFlags(f, m);
        };
    } catch (e) { console.log("[flagsecure] " + e); }
    console.log("[flagsecure] hook instalado.");
});
