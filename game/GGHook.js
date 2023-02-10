Java.performNow(function () {
    Java.enumerateLoadedClasses({
        onMatch: function (name, handle) {
            if (name.startsWith("android.ext.Script$")) {
                if (name == "android.ext.Script$isVisible" || name == "android.ext.Script$ApiFunction"
                    || name == "android.ext.Script$BusyApiFunction" || name == "android.ext.Script$DebugFunctio"
                    || name.endsWith("$clearResults"))
                    return;
                var klass = Java.use(name);
                console.log(JSON.stringify(klass));
                if ("android.ext.Script$ApiFunction" == klass.$super.$className || "android.ext.Script$BusyApiFunction" == klass.$super.$className) {
                    for (var _i = 0, _a = klass.$ownMembers; _i < _a.length; _i++) {
                        var m = _a[_i];
                        if (m == "a" && typeof klass[m] == "function") {
                            try {
                                Java.use(name).a.overload().implementation = function () {
                                    console.log(this.a());
                                    return this.a();
                                };
                            }
                            catch (e) {
                                console.log(e);
                                console.log(name);
                            }
                        }
                        if (m == "d" && typeof klass[m] == "function") {
                            try {
                                Java.use(name).d.implementation = function (a) {
                                    if (name.endsWith("searchNumber")) {
                                        console.log("a1 string :", a.r(1));
                                    }
                                    console.log(name, ":", a);
                                    return this.d(a);
                                };
                            }
                            catch (e) {
                                console.log(e);
                                console.log(name);
                            }
                        }
                        if (m == "b" && typeof klass[m] == "function") {
                            try {
                                Java.use(name).b.implementation = function (a) {
                                    console.log(name, ":", a);
                                    return this.b(a);
                                };
                            }
                            catch (e) {
                                console.log(e);
                                console.log(name);
                            }
                        }
                    }
                }
            }
        },
        onComplete: function () {
        }
    });
});
console.log("end");