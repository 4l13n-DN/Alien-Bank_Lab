// clipboard_monitor.js — Detecta datos copiados al portapapeles. MASVS-STORAGE/PRIVACY.
Java.perform(function () {
    try {
        var CM = Java.use("android.content.ClipboardManager");
        CM.setPrimaryClip.implementation = function (c) {
            try { console.log("[clip] setPrimaryClip: " + c.getItemAt(0).getText()); } catch (e) {}
            return this.setPrimaryClip(c);
        };
    } catch (e) {}
    console.log("[clip] monitor de portapapeles instalado.");
});
