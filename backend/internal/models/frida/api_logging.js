Java.perform(function() {
    try {
        var Retrofit = Java.use("retrofit2.Retrofit");
        Retrofit.create.implementation = function (service) {
            console.log("[+] Retrofit service: " + service);
            console.log('Service: ' + service.toString());
            return this.create(service);
        };
    } catch (e) {
        console.log("[*] Retrofit not present");
    }

    try {
        var OkHttpClient = Java.use('okhttp3.OkHttpClient');
        OkHttpClient.newCall.implementation = function(request) {
        console.log('[+] OkHttpClient.newCall() intercepted');
        console.log('URL: ' + request.url().toString());
        console.log('Method: ' + request.method());
        console.log('Headers: ' + request.headers().toString());
        return this.newCall(request);
    };    
    } catch (e) {
        console.log("[*] OkHttpClient not present");
    }

    try {
        var HttpURLConnection = Java.use('java.net.HttpURLConnection');
        HttpURLConnection.connect.implementation = function() {
            console.log('[+] HttpURLConnection.connect() called');
            console.log('URL: ' + this.getURL().toString());
            console.log('Method: ' + this.getRequestMethod());
            this.connect();
        };
    } catch (e) {
        console.log("[*] HTTP URL not present");
    }

});