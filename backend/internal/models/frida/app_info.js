Java.perform(function () {
    var ActivityThread = Java.use('android.app.ActivityThread');

    function waitForApplication() {
        var app = ActivityThread.currentApplication();
        if (app !== null) {
            onApplicationReady(app);
        } else {
            setTimeout(waitForApplication, 100);
        }
    }

    function onApplicationReady(app) {
        var context = app.getApplicationContext();
        var pm = context.getPackageManager();
        var pkg = context.getPackageName();

        console.log(JSON.stringify({
            event: "app.info",
            package: pkg,
            process: ActivityThread.currentProcessName(),
            version: pm.getPackageInfo(pkg, 0).versionName.value,
            targetSdk: context.getApplicationInfo().targetSdkVersion.value
        }));

        // Activities
        var PackageManager = Java.use('android.content.pm.PackageManager');
        var info = pm.getPackageInfo(pkg, PackageManager.GET_ACTIVITIES.value);

        if (info.activities.value) {
            info.activities.value.forEach(function (a) {
                console.log(JSON.stringify({
                    event: "activity",
                    name: a.name.value
                }));
            });
        }
    }

    waitForApplication();
});
