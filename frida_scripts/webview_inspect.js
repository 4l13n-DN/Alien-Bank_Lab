// webview_inspect.js — Observa WebView: URLs cargadas y puentes JS. MASVS-PLATFORM/CODE.
Java.perform(function () {
    try {
        var WV = Java.use("android.webkit.WebView");
        WV.loadUrl.overload('java.lang.String').implementation = function (u) {
            console.log("[webview] loadUrl: " + u); return this.loadUrl(u);
        };
        WV.addJavascriptInterface.implementation = function (o, n) {
            console.log("[webview] addJavascriptInterface: " + n + "  (posible puente JS peligroso)");
            return this.addJavascriptInterface(o, n);
        };
    } catch (e) { console.log("[webview] " + e); }
    console.log("[webview] hooks instalados.");
});
