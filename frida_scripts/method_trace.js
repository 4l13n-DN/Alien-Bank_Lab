// method_trace.js — Traza TODOS los métodos de una clase. Edita CLASE abajo. Didáctico.
var CLASE = "com.taller.bancoalien.ui.LoginActivity";
Java.perform(function () {
    try {
        var C = Java.use(CLASE);
        var ms = C.class.getDeclaredMethods();
        ms.forEach(function (m) {
            var name = m.getName();
            try {
                C[name].overloads.forEach(function (ov) {
                    ov.implementation = function () {
                        console.log("[trace] " + CLASE + "." + name + "(" + Array.prototype.join.call(arguments, ", ") + ")");
                        return ov.apply(this, arguments);
                    };
                });
            } catch (e) {}
        });
        console.log("[trace] hooked " + ms.length + " metodos de " + CLASE);
    } catch (e) { console.log("[trace] error: " + e); }
});
