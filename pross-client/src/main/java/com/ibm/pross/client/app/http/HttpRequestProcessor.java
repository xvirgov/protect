package com.ibm.pross.client.app.http;

import com.ibm.pross.client.app.http.handlers.*;
import com.ibm.pross.client.app.permissions.AccessEnforcement;
import com.ibm.pross.common.config.CommonConfiguration;
import com.ibm.pross.common.config.KeyLoader;
import com.ibm.pross.common.config.ServerConfiguration;
import com.sun.net.httpserver.HttpsConfigurator;
import com.sun.net.httpserver.HttpsParameters;
import com.sun.net.httpserver.HttpsServer;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.TrustManagerFactory;
import java.io.File;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.net.InetSocketAddress;
import java.net.URLDecoder;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.LinkedHashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

@SuppressWarnings("restriction")
public class HttpRequestProcessor {

    public static int SHUTDOWN_DELAY_SECONDS = 5;
    public static int NUM_PROCESSING_THREADS = 15;

    private final HttpsServer server;

    public HttpRequestProcessor(final int appIndex, final ServerConfiguration serverConfig,
                                final AccessEnforcement accessEnforcement,
                                final List<X509Certificate> caCerts, final X509Certificate hostCert, final PrivateKey privateKey,
                                final KeyLoader clientKeys, final KeyLoader serverKeys, final X509Certificate caCertHost, BigInteger publicModulus, final File baseDirectory)
            throws IOException, NoSuchAlgorithmException, KeyManagementException, KeyStoreException,
            UnrecoverableKeyException, CertificateException {

        final int httpListenPort = CommonConfiguration.BASE_HTTP_PORT;
        this.server = HttpsServer.create(new InetSocketAddress(httpListenPort), 0);

        setupTls(hostCert, privateKey, caCertHost);

        System.out.println("HTTPS server listening on port: " + httpListenPort);

        addHandlers(appIndex, serverConfig, accessEnforcement, clientKeys, serverKeys, caCerts, publicModulus, baseDirectory);

        System.out.println("Ready to process requests.");

        // this.server.setExecutor(Executors.newFixedThreadPool(NUM_PROCESSING_THREADS));
    }

    public void addHandlers(final int appIndex, final ServerConfiguration serverConfig,
                            final AccessEnforcement accessEnforcement,
                            final KeyLoader clientKeys, final KeyLoader serverKeys, final List<X509Certificate> caCerts,
                            final BigInteger publicModulus, final File baseDirectory) {

        // Returns basic information about this server: (quorum information, other servers)
        this.server.createContext("/", new RootHandler(appIndex, serverConfig));
        //Public modulus is used during the signing/storing as a part of the public parameter
        this.server.createContext("/sign", new SignHandler(clientKeys, accessEnforcement, serverConfig, caCerts, serverKeys, publicModulus, baseDirectory));
        this.server.createContext("/store", new StoreHandler(clientKeys, accessEnforcement, serverConfig, caCerts, serverKeys, publicModulus, baseDirectory));
        this.server.createContext("/delete", new DeleteHandler(clientKeys, accessEnforcement, serverConfig, caCerts, serverKeys, baseDirectory));
        this.server.createContext("/disable", new DisableHandler(clientKeys, accessEnforcement, serverConfig, caCerts, serverKeys, baseDirectory));
        this.server.createContext("/enable", new EnableHandler(clientKeys, accessEnforcement, serverConfig, caCerts, serverKeys, baseDirectory));
/*
        /*
        // Used to debug authentication and access control problems
        this.server.createContext("/id", new IdHandler(clientKeys, accessEnforcement));

        // Define request handlers for the supported client operations
        this.server.createContext("/generate", new GenerateHandler(clientKeys, accessEnforcement));
        this.server.createContext("/info", new InfoHandler(clientKeys, accessEnforcement, serverConfig));

        // Handlers for reading or storing shares
        this.server.createContext("/read", new ReadHandler(clientKeys, accessEnforcement, serverConfig));
        this.server.createContext("/store", new StoreHandler(clientKeys, accessEnforcement, shareholders));

        // Handlers for deleting or recovering shares
        this.server.createContext("/delete", new DeleteHandler(clientKeys, accessEnforcement, shareholders));
        this.server.createContext("/recover", new RecoverHandler(clientKeys, accessEnforcement, serverConfig, shareholders, caCerts, serverKeys, hostCert, privateKey));

        // Handlers for enabling and disabling shares
        this.server.createContext("/enable", new EnableHandler(clientKeys, accessEnforcement, shareholders));
        this.server.createContext("/disable", new DisableHandler(clientKeys, accessEnforcement, shareholders));

        // Handlers for using the shares to perform functions
        this.server.createContext("/exponentiate", new ExponentiateHandler(clientKeys, accessEnforcement, shareholders));


        // Define server to server requests
        this.server.createContext("/partial", new PartialHandler(serverKeys, shareholders));
        */
    }

    public void setupTls(final X509Certificate hostCert, final PrivateKey hostKey,
                         X509Certificate caCertHost) throws NoSuchAlgorithmException, KeyManagementException, KeyStoreException,
            CertificateException, IOException, UnrecoverableKeyException {

        // Configure SSL context
        final SSLContext sslContext = SSLContext.getInstance(CommonConfiguration.TLS_VERSION);

        // Create in-memory key store
        final KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
        final char[] password = "password".toCharArray();
        keyStore.load(null, password);

        // Add the CA certificates
        //int caIndex = 1;
        //for (final X509Certificate caCert : caCerts) {
        //    keyStore.setCertificateEntry("ca-" + caIndex, caCert);
         //   caIndex++;
        //}

        // Add certificate and private key for the server
        //keyStore.setCertificateEntry("Siemens_EC.pem", caCertHost);
        keyStore.setCertificateEntry("ca-cert", caCertHost);

        keyStore.setKeyEntry("host", hostKey, password, new X509Certificate[] { hostCert, caCertHost });

        // Make Key Manager Factory
        final KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
        kmf.init(keyStore, password);

        // setup the trust manager factory
        final TrustManagerFactory tmf = TrustManagerFactory.getInstance("SunX509");
        tmf.init(keyStore);

        sslContext.init(kmf.getKeyManagers(), tmf.getTrustManagers(), new SecureRandom());

        this.server.setHttpsConfigurator(new HttpsConfigurator(sslContext) {
            public void configure(final HttpsParameters params) {
                try {
                    // Configure context
                    final SSLEngine engine = sslContext.createSSLEngine();
                    params.setWantClientAuth(true);
                    params.setNeedClientAuth(false);
                    params.setCipherSuites(engine.getEnabledCipherSuites());
                    //System.out.println(engine.getEnabledCipherSuites());
                } catch (Exception ex) {
                    throw new RuntimeException("Failed to create HTTPS server");
                }
            }
        });
    }

    public void start() {
        this.server.start();
    }

    public void stop() {
        this.server.stop(SHUTDOWN_DELAY_SECONDS);
    }

    /**
     * From:
     * https://stackoverflow.com/questions/13592236/parse-a-uri-string-into-name-value-collection
     *
     * @param url
     * @return
     * @throws UnsupportedEncodingException
     */
    public static Map<String, List<String>> parseQueryString(final String queryString)
            throws UnsupportedEncodingException {

        final Map<String, List<String>> queryPairs = new LinkedHashMap<String, List<String>>();
        final String[] pairs = queryString.split("&");
        for (String pair : pairs) {
            final int idx = pair.indexOf("=");
            final String key = idx > 0 ? URLDecoder.decode(pair.substring(0, idx), "UTF-8") : pair;
            if (!queryPairs.containsKey(key)) {
                queryPairs.put(key, new LinkedList<String>());
            }
            final String value = idx > 0 && pair.length() > idx + 1
                    ? URLDecoder.decode(pair.substring(idx + 1), "UTF-8")
                    : null;
            queryPairs.get(key).add(value);
        }
        return queryPairs;
    }

    public static String getParameterValue(Map<String, List<String>> params, final String parameterName) {
        final List<String> parameterValues = params.get(parameterName);
        if ((parameterValues == null) || (parameterValues.size() != 1) || (parameterValues.get(0) == null)) {
            return null;
        } else {
            return parameterValues.get(0);
        }
    }



}