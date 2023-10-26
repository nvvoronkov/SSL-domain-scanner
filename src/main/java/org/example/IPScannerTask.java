package org.example;

import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;

import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.List;

public class IPScannerTask implements Runnable {
    private final String[] ipAddresses;

    public IPScannerTask(String[] ipAddresses) {
        this.ipAddresses = ipAddresses;
    }

    @Override
    public void run() {
        for (String ipAddress : ipAddresses) {
            scanIP(ipAddress);
        }
    }

    private void scanIP(String ipAddress) {
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
                        System.out.println("IP Address: " + ipAddress + ", Domain Name: " + name);
                        // Save the domain names to a file
                        saveDomainToFile(ipAddress, name);
                    }
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private X509Certificate extractSSLCertificate(CloseableHttpResponse response) throws IOException {
        InputStream is = response.getEntity().getContent();
        PEMParser pemParser = new PEMParser(new InputStreamReader(is));

        X509CertificateHolder certHolder = (X509CertificateHolder) pemParser.readObject();

        return new JcaPEMKeyConverter().setProvider("BC").getCertificate(certHolder);
    }

    private void saveDomainToFile(String ipAddress, String domain) {
        // Реализуйте сохранение доменных имен в файл
    }
}
