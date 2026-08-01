// ssl_unpin.js — Bypass de SSL/certificate pinning (varios frameworks). MASVS-NETWORK.
Java.perform(function () {
    // OkHttp3
    try {
        var CP = Java.use("okhttp3.CertificatePinner");
        CP.check.overload('java.lang.String', 'java.util.List').implementation = function (h, p) {
            console.log("[ssl] OkHttp CertificatePinner bypass: " + h);
        };
        console.log("[ssl] OkHttp CertificatePinner hooked");
    } catch (e) {}
    // TrustManager por defecto (X509TrustManagerExtensions / SSLContext)
    try {
        var TM = Java.registerClass({
            name: "com.dynadb.TrustAll",
            implements: [Java.use("javax.net.ssl.X509TrustManager")],
            methods: {
                checkClientTrusted: function () {}, checkServerTrusted: function () {},
                getAcceptedIssuers: function () { return []; }
            }
        });
        var SSLContext = Java.use("javax.net.ssl.SSLContext");
        SSLContext.init.overload('[Ljavax.net.ssl.KeyManager;', '[Ljavax.net.ssl.TrustManager;', 'java.security.SecureRandom')
            .implementation = function (km, tm, sr) {
                console.log("[ssl] SSLContext.init -> TrustManager permisivo");
                this.init(km, [TM.$new()], sr);
            };
    } catch (e) {}
    console.log("[ssl] hooks instalados.");
});
