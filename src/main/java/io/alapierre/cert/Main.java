package io.alapierre.cert;

import javax.net.ssl.*;
import java.io.FileInputStream;
import java.io.InputStream;
import java.net.URL;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.List;
import java.util.Map;

/**
 * @author Adrian Lapierre {@literal al@alapierre.io}
 * Copyrights by original author 27.05.2025
 */
public class Main {

    public static void main(String[] args) {
        if (args.length != 1) {
            System.err.println("Użycie: ssl-diag <https-url>");
            return;
        }

        String urlString = args[0];
        if (!urlString.startsWith("https://")) {
            System.err.println("Obsługiwane są tylko adresy HTTPS.");
            return;
        }

        printTrustStoreInfo();
        showLoadedTrustStore();
        System.out.println();

        try {
            URL url = new URL(urlString);
            HttpsURLConnection conn = (HttpsURLConnection) url.openConnection();

            // Custom TrustManager to debug the certificate chain
            conn.setSSLSocketFactory(createDebugSslContext().getSocketFactory());

            conn.setConnectTimeout(5000);
            conn.setReadTimeout(5000);
            conn.setRequestMethod("GET");

            try (InputStream is = conn.getInputStream()) {
                System.out.println("\n✅ Połączenie udane: " + conn.getResponseCode() + " " + conn.getResponseMessage() + "\n");

                printServerCertificates(conn);

                System.out.println("\n📦 Nagłówki HTTP:");
                for (Map.Entry<String, List<String>> entry : conn.getHeaderFields().entrySet()) {
                    System.out.printf(" - %s: %s%n", entry.getKey(), String.join(", ", entry.getValue()));
                }

            }
        } catch (SSLHandshakeException e) {
            System.err.println("❌ Błąd SSL: " + e.getMessage());
            e.printStackTrace();
        } catch (Exception e) {
            System.err.println("❌ Błąd połączenia: " + e.getMessage());
            e.printStackTrace();
        }
    }

    private static void printTrustStoreInfo() {
        System.out.println("Informacje o trustStore:");
        System.out.println(" - javax.net.ssl.trustStore: " + System.getProperty("javax.net.ssl.trustStore"));
        System.out.println(" - javax.net.ssl.trustStorePassword: " + System.getProperty("javax.net.ssl.trustStorePassword"));
        System.out.println(" - javax.net.ssl.keyStore: " + System.getProperty("javax.net.ssl.keyStore"));
        System.out.println(" - javax.net.ssl.keyStorePassword: " + System.getProperty("javax.net.ssl.keyStorePassword"));
    }

    private static SSLContext createDebugSslContext() throws Exception {
        TrustManager[] trustAllCerts = new TrustManager[]{
                new X509TrustManager() {
                    private final X509TrustManager defaultTm = getDefaultTrustManager();

                    public void checkClientTrusted(X509Certificate[] chain, String authType) {
                        // not needed
                    }

                    public void checkServerTrusted(X509Certificate[] chain, String authType) {
                        System.out.println("Sprawdzanie certyfikatów serwera:");
                        for (X509Certificate cert : chain) {
                            System.out.println(" - " + cert.getSubjectX500Principal());
                        }
                        try {
                            defaultTm.checkServerTrusted(chain, authType);
                        } catch (CertificateException e) {
                            throw new RuntimeException(e);
                        }
                    }

                    public X509Certificate[] getAcceptedIssuers() {
                        return defaultTm.getAcceptedIssuers();
                    }

                    private X509TrustManager getDefaultTrustManager() {
                        try {
                            TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
                            tmf.init((KeyStore) null);
                            return Arrays.stream(tmf.getTrustManagers())
                                    .filter(tm -> tm instanceof X509TrustManager)
                                    .map(tm -> (X509TrustManager) tm)
                                    .findFirst()
                                    .orElseThrow();
                        } catch (Exception e) {
                            throw new RuntimeException(e);
                        }
                    }
                }
        };

        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(null, trustAllCerts, null);
        return sslContext;
    }

    private static void printServerCertificates(HttpsURLConnection conn) {
        try {
            System.out.println("🔐 Informacje o certyfikacie serwera:");
            Certificate[] certs = conn.getServerCertificates();

            for (int i = 0; i < certs.length; i++) {
                System.out.println(" - Cert " + (i + 1) + ":");

                if (certs[i] instanceof X509Certificate cert) {
                    System.out.println("     Subject: " + cert.getSubjectDN());
                    System.out.println("     Issuer:  " + cert.getIssuerDN());
                    System.out.println("     Serial:  " + cert.getSerialNumber());
                    System.out.println("     Valid from: " + cert.getNotBefore());
                    System.out.println("     Valid until: " + cert.getNotAfter());
                    System.out.println("     Signature algorithm: " + cert.getSigAlgName());
                } else {
                    System.out.println("     [Nieznany typ certyfikatu: " + certs[i].getType() + "]");
                }
            }
        } catch (SSLPeerUnverifiedException e) {
            System.err.println("❗ Serwer nie dostarczył certyfikatów (SSLPeerUnverifiedException): " + e.getMessage());
        } catch (Exception e) {
            System.err.println("❗ Błąd podczas pobierania certyfikatów: " + e.getMessage());
        }
    }

    public static void showLoadedTrustStore() {

        try {
            String trustStorePath = System.getProperty("javax.net.ssl.trustStore");
            String trustStorePassword = System.getProperty("javax.net.ssl.trustStorePassword", "changeit");
            String trustStoreType = System.getProperty("javax.net.ssl.trustStoreType", "JKS");

            if (trustStorePath == null) {
                String javaHome = System.getProperty("java.home");
                trustStorePath = javaHome + "/lib/security/cacerts";
                System.out.println("⚠️ Brak ustawionej właściwości javax.net.ssl.trustStore – używany domyślny plik:");
            }

            System.out.println("🔐 Ścieżka trustStore: " + trustStorePath);
            System.out.println("🔐 Typ trustStore: " + trustStoreType);

            KeyStore ks = KeyStore.getInstance(trustStoreType);
            ks.load(new FileInputStream(trustStorePath), trustStorePassword.toCharArray());

            System.out.println("\n📋 Zawartość trustStore:");
            Enumeration<String> aliases = ks.aliases();
            while (aliases.hasMoreElements()) {
                String alias = aliases.nextElement();
                System.out.println(" - " + alias);
            }

        } catch (Exception ex) {
            ex.printStackTrace();
        }
    }
}
