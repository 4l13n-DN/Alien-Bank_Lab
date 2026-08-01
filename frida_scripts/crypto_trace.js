// crypto_trace.js — Traza uso de criptografía (Cipher) para ver claves/datos. MASVS-CRYPTO.
Java.perform(function () {
    try {
        var Cipher = Java.use("javax.crypto.Cipher");
        Cipher.doFinal.overload('[B').implementation = function (data) {
            try { console.log("[crypto] Cipher(" + this.getAlgorithm() + ").doFinal len=" + (data ? data.length : 0)); } catch (e) {}
            return this.doFinal(data);
        };
        var SKS = Java.use("javax.crypto.spec.SecretKeySpec");
        SKS.$init.overload('[B', 'java.lang.String').implementation = function (k, a) {
            try { console.log("[crypto] SecretKeySpec alg=" + a + " keyHex=" + bytesToHex(k)); } catch (e) {}
            return this.$init(k, a);
        };
    } catch (e) {}
    function bytesToHex(b) { var s = ""; for (var i = 0; i < b.length; i++) { var x = (b[i] & 0xff).toString(16); s += (x.length == 1 ? "0" : "") + x; } return s; }
    console.log("[crypto] trazando Cipher/SecretKeySpec...");
});
