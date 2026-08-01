// root_bypass.js — Bypass de deteccion de root (nativo + Java). MASVS-RESILIENCE.
// Diagnostico + multiples estrategias para ocultar /system/bin/su.

// ---------- CANARY (confirma que el script corre) ----------
console.log("[root] >>> script cargado, arch=" + Process.arch + " pid=" + Process.id);
// send() SIEMPRE llega a la GUI (via on('message')); es el canary a prueba de todo.
try { send("[root] canary: script vivo, arch=" + Process.arch + " pid=" + Process.id); } catch (e) {}

// ---------- Resolver libc (puede llamarse libc.so o otra cosa en algunos Nox) ----------
function findInLibc(sym) {
    // frida 17 ELIMINO el estatico Module.findExportByName(mod, sym). Usamos la API nueva
    // (findGlobalExportByName) y caemos a metodos de instancia. Compatible frida 16/17/<=15.
    try {
        if (typeof Module.findGlobalExportByName === "function") {
            var g = Module.findGlobalExportByName(sym);
            if (g) return g;
        }
    } catch (e) {}
    var mods = Process.enumerateModules();
    // 1) preferir libc*
    for (var i = 0; i < mods.length; i++) {
        if (mods[i].name.toLowerCase().indexOf("libc") >= 0) {
            try { var a = mods[i].findExportByName(sym); if (a) return a; } catch (e) {}
        }
    }
    // 2) cualquier modulo (instancia)
    for (var j = 0; j < mods.length; j++) {
        try { var b = mods[j].findExportByName(sym); if (b) return b; } catch (e) {}
    }
    // 3) legacy frida <=15 (estatico)
    try {
        if (typeof Module.findExportByName === "function") {
            var c = Module.findExportByName(null, sym);
            if (c) return c;
        }
    } catch (e) {}
    return null;
}

// ---------- 1) HOOKS NATIVOS ----------
(function () {
    var needles = ["su", "magisk", "superuser", "busybox", "xposed",
                   "/sbin/su", "/system/bin/su", "/system/xbin/su", "/vendor/bin/su"];
    var needleMatch = function (path) {
        if (!path) return false;
        var p = ("" + path).toLowerCase();
        for (var i = 0; i < needles.length; i++) {
            if (p.indexOf(needles[i]) >= 0) return true;
        }
        // comando "which su"
        if (p === "which su" || p.indexOf("which su") >= 0) return true;
        return false;
    };

    var hooked = 0;

    // access()
    try {
        var access = findInLibc("access");
        if (access) {
            Interceptor.attach(access, {
                onEnter: function (args) {
                    try { this.path = args[0].readUtf8String(); } catch(e) { this.path = "?"; }
                    this.block = needleMatch(this.path);
                },
                onLeave: function (retval) {
                    if (this.block) {
                        console.log("[root] access('" + this.path + "') -> -1");
                        retval.replace(-1);
                    }
                }
            });
            hooked++; console.log("[root] hook OK: access()");
        } else { console.log("[root] NO encontre access()"); }
    } catch (e) { console.log("[root] access hook error: " + e); }

    // faccessat
    try {
        var faccessat = findInLibc("faccessat");
        if (faccessat) {
            Interceptor.attach(faccessat, {
                onEnter: function (args) {
                    try { this.path = args[1].readUtf8String(); } catch(e) { this.path = "?"; }
                    this.block = needleMatch(this.path);
                },
                onLeave: function (retval) {
                    if (this.block) {
                        console.log("[root] faccessat('" + this.path + "') -> -1");
                        retval.replace(-1);
                    }
                }
            });
            hooked++; console.log("[root] hook OK: faccessat()");
        } else { console.log("[root] NO encontre faccessat()"); }
    } catch (e) { console.log("[root] faccessat hook error: " + e); }

    // stat
    try {
        var stat = findInLibc("stat");
        if (stat) {
            Interceptor.attach(stat, {
                onEnter: function (args) {
                    try { this.path = args[0].readUtf8String(); } catch(e) { this.path = "?"; }
                    this.block = needleMatch(this.path);
                },
                onLeave: function (retval) {
                    if (this.block) {
                        console.log("[root] stat('" + this.path + "') -> -1");
                        retval.replace(-1);
                    }
                }
            });
            hooked++; console.log("[root] hook OK: stat()");
        } else { console.log("[root] NO encontre stat()"); }
    } catch (e) { console.log("[root] stat hook error: " + e); }

    // lstat
    try {
        var lstat = findInLibc("lstat");
        if (lstat) {
            Interceptor.attach(lstat, {
                onEnter: function (args) {
                    try { this.path = args[0].readUtf8String(); } catch(e) { this.path = "?"; }
                    this.block = needleMatch(this.path);
                },
                onLeave: function (retval) {
                    if (this.block) {
                        console.log("[root] lstat('" + this.path + "') -> -1");
                        retval.replace(-1);
                    }
                }
            });
            hooked++; console.log("[root] hook OK: lstat()");
        } else { console.log("[root] NO encontre lstat()"); }
    } catch (e) { console.log("[root] lstat hook error: " + e); }

    // popen
    try {
        var popen = findInLibc("popen");
        if (popen) {
            Interceptor.attach(popen, {
                onEnter: function (args) {
                    try { this.cmd = args[0].readUtf8String(); } catch(e) { this.cmd = "?"; }
                    this.block = needleMatch(this.cmd);
                },
                onLeave: function (retval) {
                    if (this.block) {
                        console.log("[root] popen('" + this.cmd + "') -> NULL");
                        retval.replace(ptr(0));
                    }
                }
            });
            hooked++; console.log("[root] hook OK: popen()");
        } else { console.log("[root] NO encontre popen()"); }
    } catch (e) { console.log("[root] popen hook error: " + e); }

    // openat (algunas apps leen /proc o /system/bin/su directamente)
    try {
        var openat = findInLibc("openat");
        if (openat) {
            Interceptor.attach(openat, {
                onEnter: function (args) {
                    try { this.path = args[1].readUtf8String(); } catch(e) { this.path = "?"; }
                    this.block = needleMatch(this.path);
                },
                onLeave: function (retval) {
                    if (this.block) {
                        console.log("[root] openat('" + this.path + "') -> -1");
                        retval.replace(-1);
                    }
                }
            });
            hooked++; console.log("[root] hook OK: openat()");
        }
    } catch (e) { console.log("[root] openat hook error: " + e); }

    console.log("[root] hooks nativos instalados: " + hooked);
})();

// ---------- 2) HOOKS JAVA ----------
function installJavaHooks() {
    var needles = ["su", "magisk", "superuser", "busybox", "xposed", "/sbin/su",
                   "/system/bin/su", "/system/xbin/su"];

    try {
        var File = Java.use("java.io.File");
        File.exists.implementation = function () {
            var p = ("" + this.getAbsolutePath()).toLowerCase();
            for (var i = 0; i < needles.length; i++) {
                if (p.indexOf(needles[i]) >= 0) {
                    console.log("[root] File.exists(" + p + ") -> false");
                    return false;
                }
            }
            return this.exists();
        };
        console.log("[root] hook OK: File.exists");
    } catch (e) { console.log("[root] File.exists hook: " + e); }

    try {
        var Rt = Java.use("java.lang.Runtime");
        Rt.exec.overload('java.lang.String').implementation = function (c) {
            if (c && ("" + c).toLowerCase().indexOf("su") >= 0) {
                console.log("[root] Runtime.exec bloqueado: " + c);
                throw Java.use("java.io.IOException").$new("blocked");
            }
            return this.exec(c);
        };
        Rt.exec.overload('[Ljava.lang.String;').implementation = function (c) {
            // FIX: 'c' es un String[] de Java; ("" + c) daba la REFERENCIA del objeto,
            // no el contenido, asi que "which su" nunca se detectaba. Unimos elementos.
            var joined = "";
            try { for (var i = 0; i < c.length; i++) joined += (c[i] ? c[i].toString() : "") + " "; } catch (e) {}
            if (joined.toLowerCase().indexOf("su") >= 0) {
                console.log("[root] Runtime.exec[] bloqueado: " + joined.trim());
                throw Java.use("java.io.IOException").$new("blocked");
            }
            return this.exec(c);
        };
        console.log("[root] hook OK: Runtime.exec");
    } catch (e) { console.log("[root] Runtime.exec hook: " + e); }

    try {
        var RB = Java.use("com.scottyab.rootbeer.RootBeer");
        RB.isRooted.implementation = function () {
            console.log("[root] RootBeer.isRooted -> false"); return false;
        };
        console.log("[root] hook OK: RootBeer");
    } catch (e) { /* RootBeer no presente */ }

    // PackageManager: algunas apps buscan apps de root instaladas
    try {
        var PM = Java.use("android.app.ApplicationPackageManager");
        PM.getInstalledPackages.overload('int').implementation = function (flags) {
            var pkgs = this.getInstalledPackages(flags);
            var filtered = Java.use("java.util.ArrayList").$new();
            var hide = ["magisk", "supersu", "superuser", "chainfire", "topjohnwu",
                        "koushikdutta", "noshufou"];
            for (var i = 0; i < pkgs.size(); i++) {
                var info = pkgs.get(i);
                var name = info.packageName.value;
                var lname = (name || "").toLowerCase();
                var skip = false;
                for (var j = 0; j < hide.length; j++) {
                    if (lname.indexOf(hide[j]) >= 0) { skip = true; break; }
                }
                if (!skip) filtered.add(info);
            }
            console.log("[root] PackageManager.getInstalledPackages filtrado: " +
                        pkgs.size() + " -> " + filtered.size());
            return filtered;
        };
        console.log("[root] hook OK: PackageManager");
    } catch (e) { console.log("[root] PackageManager hook: " + e); }

    // ---------- 2.5) HOOK DIRECTO A DETECTORES CONOCIDOS DE LABORATORIO ----------
    // La deteccion corre en LoginActivity.onCreate() apenas arranca. Con Java.use forzamos
    // la carga de la clase AHORA (durante el spawn, antes del resume) y reemplazamos el
    // metodo de decision -> gana la carrera SIEMPRE. Es lo mas fiable para la demo.
    var LAB_DETECTORS = [
        ["com.taller.bancoalien.security.RootDetection",  "isDeviceRooted"],
        ["com.taller.bancoalien.security.FridaDetection", "isFridaPresent"]
    ];
    LAB_DETECTORS.forEach(function (pair) {
        try {
            var K = Java.use(pair[0]);
            K[pair[1]].overloads.forEach(function (ov) {
                ov.implementation = function () {
                    console.log("[root] " + pair[0] + "." + pair[1] + "() -> false (hook directo)");
                    return false;
                };
            });
            console.log("[root] hook OK (lab): " + pair[0] + "." + pair[1] + "()");
        } catch (e) { /* la app no tiene esa clase: normal en apps que no son Banco Alien */ }
    });

    // ---------- 3) BARRIDO DE DETECTORES PROPIOS DE LA APP ----------
    // Un bypass generico no vence un control a medida (ej. Banco Alien:
    // com.taller.bancoalien.security.RootDetection.isDeviceRooted()). Aqui buscamos
    // clases del propio APK cuyo nombre delate deteccion y forzamos a false sus
    // metodos booleanos sin argumentos (isRooted/isEmulator/isFridaPresent/...).
    sweepCustomDetectors();
    console.log("[root] hooks Java instalados.");
}

var _sweptOnce = {};
function sweepCustomDetectors() {
    var patt = /(root|jailbreak|emulator|frida|tamper|debug|hook|magisk|xposed|integrity|detect|secure|security)/i;
    var skip = /^(android\.|androidx\.|java\.|javax\.|kotlin\.|kotlinx\.|com\.google\.|dalvik\.|libcore\.|sun\.|org\.json)/;
    var count = 0;
    var classes;
    try { classes = Java.enumerateLoadedClassesSync(); }
    catch (e) { console.log("[root] no pude enumerar clases: " + e); return; }
    classes.forEach(function (cn) {
        if (skip.test(cn) || !patt.test(cn)) return;
        if (_sweptOnce[cn]) return;
        try {
            var K = Java.use(cn);
            var methods = K.class.getDeclaredMethods();
            for (var i = 0; i < methods.length; i++) {
                var m = methods[i];
                if (m.getReturnType().getName() !== "boolean") continue;
                var name = m.getName();
                try {
                    K[name].overloads.forEach(function (ov) {
                        if (ov.argumentTypes.length !== 0) return;   // solo métodos sin args
                        ov.implementation = function () {
                            console.log("[root] " + cn + "." + name + "() -> false (detector propio)");
                            return false;
                        };
                        count++;
                    });
                } catch (e2) {}
            }
            _sweptOnce[cn] = true;
        } catch (e) {}
    });
    // Solo reportamos cuando realmente neutralizamos algo (los re-barridos de respaldo
    // suelen dar 0 y ensuciaban la consola).
    if (count > 0) {
        console.log("[root] barrido de detectores propios: " + count + " metodo(s) neutralizado(s).");
    }
}

function tryInstall(attempts) {
    if (typeof Java === "undefined" || Java === null) {
        if (attempts <= 0) {
            console.log("[root] 'Java' no disponible tras reintentos (app nativa?).");
            return;
        }
        setTimeout(function () { tryInstall(attempts - 1); }, 200);
        return;
    }
    try {
        Java.perform(installJavaHooks);
        // Re-barrido: captura clases de deteccion que cargan despues del arranque.
        [400, 1000, 2000, 3500].forEach(function (ms) {
            setTimeout(function () { try { Java.perform(sweepCustomDetectors); } catch (e) {} }, ms);
        });
    } catch (e) {
        if (attempts <= 0) {
            console.log("[root] Java.perform fallo: " + e);
            return;
        }
        setTimeout(function () { tryInstall(attempts - 1); }, 200);
    }
}

tryInstall(25);  // ~5s max esperando a la VM