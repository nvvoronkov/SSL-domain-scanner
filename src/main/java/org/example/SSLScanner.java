package org.example;

import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;

import java.io.*;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.List;

public class SSLScanner {
    public static void scanIP(String ipAddress) {
        try {
            CloseableHttpClient httpClient = HttpClients.createDefault();
            HttpGet httpGet = new HttpGet("https://" + ipAddress);

            try (CloseableHttpResponse response = httpClient.execute(httpGet)) {
                // Extract SSL certificate
                X509Certificate certificate = extractSSLCertificate(response);

                // Extract domain names from the certificate
                Collection<List<String>> subjectAltNames = certificate.getSubjectAlternativeNames();
                for (List<String> san : subjectAltNames) {
                    for (String name : san) {
                        System.out.println("Domain Name: " + name);
                        // Save the domain names to a file
                        saveDomainToFile(ipAddress, name);
                    }
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static X509Certificate extractSSLCertificate(CloseableHttpResponse response) throws IOException, CertificateParsingException {
        InputStream is = response.getEntity().getContent();
        PEMParser pemParser = new PEMParser(new InputStreamReader(is));

        X509CertificateHolder certHolder = (X509CertificateHolder) pemParser.readObject();

        return new JcaPEMKeyConverter().setProvider("BC").getCertificate(certHolder);
    }

    private static void saveDomainToFile(String ipAddress, String domain) {
        try (FileWriter writer = new FileWriter("domains.txt", true);
             BufferedWriter bufferedWriter = new BufferedWriter(writer)) {
            bufferedWriter.write("IP Address: " + ipAddress + ", Domain: " + domain);
            bufferedWriter.newLine();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public static void main(String[] args) {
        IPScannerApp.main(args);
//        String ipAddress = "example.com"; // Replace with the actual IP address you want to scan
//        scanIP(ipAddress);
    }
}
