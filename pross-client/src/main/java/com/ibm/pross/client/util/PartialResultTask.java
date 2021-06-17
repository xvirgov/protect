package com.ibm.pross.client.util;

import com.ibm.pross.common.util.crypto.kyber.KyberPublicParameters;
import com.ibm.pross.common.util.crypto.rsa.threshold.proactive.ProactiveRsaPublicParameters;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.*;
import java.net.URL;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.atomic.AtomicInteger;

import javax.net.ssl.HttpsURLConnection;

public abstract class PartialResultTask implements Runnable {

    // Creator class
    private final BaseClient baseClient;

    // Remote server info
    private final int remoteServerId;
    private final String requestUrl;
    // State management
    private final CountDownLatch latch;
    private final AtomicInteger failureCounter;
    private final int maximumFailures;
    private String requestBody = null;
    private String requestType = "GET";

    public PartialResultTask(final BaseClient baseClient, final int remoteServerId, final String requestUrl, final String requestBody, final String requestType,
                             final List<Object> verifiedResults, final CountDownLatch latch, final AtomicInteger failureCounter, final int maximumFailures) {

        this.requestBody = requestBody;
        this.baseClient = baseClient;
        // Remote server info
        this.remoteServerId = remoteServerId;
        this.requestUrl = requestUrl;
        this.requestType = requestType;

        // State management
        this.latch = latch;
        this.failureCounter = failureCounter;
        this.maximumFailures = maximumFailures;
    }

    public PartialResultTask(final BaseClient baseClient, final int remoteServerId, final String requestUrl, final String requestBody, final String requestType,
                             final CountDownLatch latch, final AtomicInteger failureCounter, final int maximumFailures) {

        this.requestBody = requestBody;
        this.baseClient = baseClient;
        // Remote server info
        this.remoteServerId = remoteServerId;
        this.requestUrl = requestUrl;
        this.requestType = requestType;

        // State management
        this.latch = latch;
        this.failureCounter = failureCounter;
        this.maximumFailures = maximumFailures;
    }

    public PartialResultTask(final BaseClient baseClient, final int remoteServerId, final String requestUrl, final List<Object> verifiedResults,
                             final CountDownLatch latch, final AtomicInteger failureCounter, final int maximumFailures) {

        this.baseClient = baseClient;
        // Remote server info
        this.remoteServerId = remoteServerId;
        this.requestUrl = requestUrl;

        // State management
        this.latch = latch;
        this.failureCounter = failureCounter;
        this.maximumFailures = maximumFailures;
    }

    public PartialResultTask(final BaseClient baseClient, final int remoteServerId, final String requestUrl,
                             final CountDownLatch latch, final AtomicInteger failureCounter, final int maximumFailures) {

        this.baseClient = baseClient;
        // Remote server info
        this.remoteServerId = remoteServerId;
        this.requestUrl = requestUrl;

        // State management
        this.latch = latch;
        this.failureCounter = failureCounter;
        this.maximumFailures = maximumFailures;
    }



    /**
     * For retrieving rsa public parameters
     *
     * @param baseClient
     * @param remoteServerId
     * @param requestUrl
     * @param verifiedResultsCounter
     * @param latch
     * @param failureCounter
     * @param maximumFailures
     */
    public PartialResultTask(final BaseClient baseClient, final int remoteServerId, final String requestUrl, final Map<RsaPublicParameters, Integer> verifiedResultsCounter,
                             final CountDownLatch latch, final AtomicInteger failureCounter, final int maximumFailures) {

        this.baseClient = baseClient;
        // Remote server info
        this.remoteServerId = remoteServerId;
        this.requestUrl = requestUrl;

        // State management
        this.latch = latch;
        this.failureCounter = failureCounter;
        this.maximumFailures = maximumFailures;
    }

    public PartialResultTask(final BaseClient baseClient, final int remoteServerId, final String requestUrl, final Map<ProactiveRsaPublicParameters, Integer> verifiedResultsCounter,
                             final CountDownLatch latch, final AtomicInteger failureCounter, final int maximumFailures, long epoch) {

        this.baseClient = baseClient;
        // Remote server info
        this.remoteServerId = remoteServerId;
        this.requestUrl = requestUrl;

        // State management
        this.latch = latch;
        this.failureCounter = failureCounter;
        this.maximumFailures = maximumFailures;
    }


    public PartialResultTask(final BaseClient baseClient, final int remoteServerId, final String requestUrl, final Map<KyberPublicParameters, Integer> verifiedResultsCounter,
                             final CountDownLatch latch, final AtomicInteger failureCounter, final int maximumFailures, long epoch, boolean tmp) {

        this.baseClient = baseClient;
        // Remote server info
        this.remoteServerId = remoteServerId;
        this.requestUrl = requestUrl;

        // State management
        this.latch = latch;
        this.failureCounter = failureCounter;
        this.maximumFailures = maximumFailures;
    }

    @Override
    public void run() {

        try {
            // Create HTTPS connection to the remote server
//			System.out.println(this.requestUrl);

            final URL url = new URL(this.requestUrl);
            final HttpsURLConnection httpsConnection = (HttpsURLConnection) url.openConnection();
            httpsConnection.setDoOutput(true);
            httpsConnection.setDoInput(true);
            this.baseClient.configureHttps(httpsConnection, remoteServerId);

            // Configure timeouts and method
            httpsConnection.setRequestMethod(requestType);
            httpsConnection.setConnectTimeout(10_000);
            httpsConnection.setReadTimeout(10_000);


            httpsConnection.connect();

            // Verify server identity is what we expect
            final Certificate[] certs = httpsConnection.getServerCertificates();
            final X509Certificate peerCertificate = (X509Certificate) certs[0];
            final PublicKey peerPublicKey = peerCertificate.getPublicKey();

            // Attempt to link the public key in the certificate to a known entity's key
            final Integer serverId = this.baseClient.serverKeys.getEntityIndex(peerPublicKey);
            if (serverId != remoteServerId) {
                System.err.println("Invalid server!!!: was " + serverId + ", expected: " + remoteServerId);
                throw new CertificateException("Invalid peer certificate");
            }

            // Write data back
            if (this.requestBody != null && this.requestType.equals("POST")) {
                try (final OutputStream outputStream = httpsConnection.getOutputStream();
                     final OutputStreamWriter outputStreamWriter = new OutputStreamWriter(outputStream)) {
//                    System.out.println("POSTING: " + this.requestBody);
                    outputStreamWriter.write(this.requestBody);
                }
            }

            // Read data from it
            try (final InputStream inputStream = httpsConnection.getInputStream();
                 final InputStreamReader inputStreamReader = new InputStreamReader(inputStream);
                 final BufferedReader bufferedReader = new BufferedReader(inputStreamReader);) {

                final String inputLine = bufferedReader.readLine();

                // Parse and process
                this.parseJsonResult(inputLine);

            }


        } catch (Exception e) {
            // Increment failure counter
            final int numFailures = this.failureCounter.incrementAndGet();

            // Check if there have been too many failures to succeed
            if (numFailures == (maximumFailures + 1)) { // n - k + 1
                while (latch.getCount() > 0) {
                    latch.countDown();
                }
            }
            System.err.println(e);
            System.err.println("Exception from server #" + remoteServerId + ": " + e);
        }
    }

    protected abstract void parseJsonResult(final String jsonString) throws Exception;
}