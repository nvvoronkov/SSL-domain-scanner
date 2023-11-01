package org.example;

import io.javalin.Javalin;
import io.javalin.http.Context;
import io.javalin.http.HttpStatus;
import io.javalin.http.staticfiles.Location;
import io.javalin.rendering.JavalinRenderer;

import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.util.List;
import java.util.Objects;

import static io.javalin.rendering.template.TemplateUtil.model;

public class IPScannerApp {

    public static void main(String[] args) {
        Javalin app = Javalin.create(config -> {
                    config.addStaticFiles("/static", Location.CLASSPATH);
                    JavalinRenderer.register(JavalinThymeleaf.INSTANCE);
                })
                .get("/", ctx -> {
                    try {
                        ctx.render("/templates/home.html", model("ip", "", "threadNum", 1));
                    } catch (Exception e) {
                        ctx.redirect("/", HttpStatus.forStatus(400));
                    }
                })
                .start(8080);
        app.post("/scan", ctx -> {
            try {
                String IP = ctx.formParam("ip");
                int threadNum = Integer.parseInt(ctx.formParam("threadNum"));
                String fileName = File.createTempFile("IPAddresses_Domains_", ".txt").getName();
                List<String> result = IPScannerManager.scan(IP, threadNum, fileName);
                ctx.render("/templates/home.html", model(
                        "ip", IP
                        , "threadNum", threadNum
                        , "filename", fileName
                        , "addresses", result.isEmpty() ? "empty" : result)
                );
            } catch (Exception e) {
                ctx.redirect("/", HttpStatus.forStatus(400));
            }
        });

        app.get("/download/{filename}", ctx -> {
            try {
                File localFile = new File(ctx.pathParam("filename"));
                InputStream inputStream = new BufferedInputStream(new FileInputStream(localFile));
                ctx.header("Content-Disposition", "attachment; filename=\"" + localFile.getName() + "\"");
                ctx.header("Content-Length", String.valueOf(localFile.length()));
                ctx.result(inputStream);
            } catch (Exception e) {
                ctx.redirect("/", HttpStatus.forStatus(400));
            }
        });

        app.error(400, "html", ctx -> {
            ctx.result("BAD REQUEST!");
        });
    }

    private static void getHomepage(Context ctx) {
        ctx.result("Welcome to IP Scanner App");
    }

    private static void startScan(Context ctx) {
        String ipRange = ctx.formParam("ipRange");
        int numThreads = Integer.parseInt(Objects.requireNonNull(ctx.formParam("numThreads")));



        // Implement IP scanning logic here
        // Use Apache Http Client for making requests to IP addresses

        // Save found domains to a text file

        ctx.result("Scanning started for IP range: " + ipRange);
    }
}
