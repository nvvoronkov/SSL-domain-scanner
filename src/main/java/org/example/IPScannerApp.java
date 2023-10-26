package org.example;

import io.javalin.Javalin;
import io.javalin.http.Context;

public class IPScannerApp {

    public static void main(String[] args) {
        Javalin app = Javalin.create().start(7000);

        app.get("/", IPScannerApp::getHomepage);
        app.post("/startScan", IPScannerApp::startScan);

        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            app.stop();
        }));
    }

    private static void getHomepage(Context ctx) {
        ctx.result("Welcome to IP Scanner App");
    }

    private static void startScan(Context ctx) {
        String ipRange = ctx.formParam("ipRange");
        int numThreads = Integer.parseInt(ctx.formParam("numThreads"));

        // Implement IP scanning logic here
        // Use Apache Http Client for making requests to IP addresses

        // Save found domains to a text file

        ctx.result("Scanning started for IP range: " + ipRange);
    }
}
