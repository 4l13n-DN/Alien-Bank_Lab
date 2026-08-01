// http_reader.js — Lee el CUERPO de las respuestas HTTP/HTTPS de OkHttp en runtime.
// MASVS-NETWORK. Revela los flags de red (F10 cleartext, F11 pinned) SIN proxy: leemos
// DENTRO de la app, después de que OkHttp valida el certificado, así que el pinning no
// estorba. Buen punto didáctico: con un hook en el dispositivo, el pinning no te salva.
//
// IMPORTANTE: enganchamos con un pequeño retraso (setTimeout) para NO competir con el
// bypass de root en el arranque. Así, en un mismo spawn (root_bypass + http_reader), el
// bypass gana la carrera y abre la app; el lector entra ~1.5 s después, mucho antes de
// que llegues al Dashboard (que es cuando se disparan las peticiones).
setTimeout(function () {
    Java.perform(function () {
        // URLs (contexto): qué pide la app
        try {
            var RB = Java.use("okhttp3.Request$Builder");
            RB.url.overload('java.lang.String').implementation = function (u) {
                console.log("[net] --> " + u);
                return this.url(u);
            };
        } catch (e) {}

        // Cuerpo de la respuesta: aquí viaja el flag
        try {
            var Body = Java.use("okhttp3.ResponseBody");
            Body.string.implementation = function () {
                var s = this.string();          // una sola lectura; devolvemos el mismo valor
                try {
                    console.log("[net] <-- body: " + s);
                    var m = /ALIEN\{[^}]+\}/.exec(s);
                    if (m) console.log("[net] *** FLAG: " + m[0]);
                } catch (e) {}
                return s;
            };
            console.log("[net] lector de red listo. Inicia sesión y entra al Dashboard para disparar las peticiones.");
        } catch (e) {
            console.log("[net] no pude hookear okhttp3.ResponseBody (¿la app usa OkHttp?): " + e);
        }
    });
}, 1500);
