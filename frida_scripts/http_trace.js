// http_trace.js — Traza URLs HTTP(S) en runtime SIN proxy. MASVS-NETWORK.
Java.perform(function () {
    try {
        var URL = Java.use("java.net.URL");
        URL.openConnection.overload().implementation = function () {
            console.log("[http] " + this.toString()); return this.openConnection();
        };
    } catch (e) {}
    try {
        var RB = Java.use("okhttp3.Request$Builder");
        RB.url.overload('java.lang.String').implementation = function (u) {
            console.log("[http] OkHttp " + u); return this.url(u);
        };
    } catch (e) {}
    console.log("[http] trazando URLs.");
});
