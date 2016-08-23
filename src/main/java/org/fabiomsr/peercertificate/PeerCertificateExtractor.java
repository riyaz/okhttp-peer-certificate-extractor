package org.fabiomsr.peercertificate;

import javax.net.ssl.HttpsURLConnection;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.net.MalformedURLException;
import java.net.URISyntaxException;
import java.net.URL;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Base64;

/**
 * Created by fabiomsr on 3/7/16.
 */
public class PeerCertificateExtractor {



    public static void main(String[] args) throws IOException, URISyntaxException, NoSuchAlgorithmException {
        URL[] url = {
                new URL("https://github.com"),
        };

        for (URL anUrl : url) {
            System.out.println(anUrl.toString());
            String sha = extract(anUrl);
            System.out.println(sha);
            System.out.println();
        }

    }

    public static String extract(URL url) throws IOException, NoSuchAlgorithmException {
        HttpsURLConnection urlConnection = (HttpsURLConnection) url.openConnection();
        urlConnection.connect();
        Certificate certificate = urlConnection.getServerCertificates()[0];

        byte[] publicKeyEncoded = certificate.getPublicKey().getEncoded();
        MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
        byte[] publicKeySha256 = messageDigest.digest(publicKeyEncoded);
        byte[] publicKeyShaBase64 = Base64.getEncoder().encode(publicKeySha256);

//        String encoded = new BigInteger(1, publicKeyEncoded).toString(16);
//        System.out.println(url.toString());
        String out = "sha256/" + new String(publicKeyShaBase64);
//        System.out.println(out);
//        System.out.println(encoded);
//        System.out.println("\n");
        return out;
    }

    /**
     * Get peer certificate(Public key to sha256 to base64)
     *
     * @param certificate Crt or der or pem file with a valid certificate
     * @return
     */

    public static String extract(File certificate) {

        FileInputStream inputStream = null;

        try {
            inputStream = new FileInputStream(certificate);
            X509Certificate x509Certificate = (X509Certificate) CertificateFactory.getInstance("X509")
                    .generateCertificate(inputStream);

            byte[] publicKeyEncoded = x509Certificate.getPublicKey().getEncoded();
            MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
            byte[] publicKeySha256 = messageDigest.digest(publicKeyEncoded);
            byte[] publicKeyShaBase64 = Base64.getEncoder().encode(publicKeySha256);

            return "sha256/" + new String(publicKeyShaBase64);
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            try {
                if (inputStream != null) {
                    inputStream.close();
                }
            } catch (IOException e) {
                e.printStackTrace();
            }
        }

        return "";
    }

}
