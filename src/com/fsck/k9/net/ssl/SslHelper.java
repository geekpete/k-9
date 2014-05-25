
package com.fsck.k9.net.ssl;

import java.io.IOException;
import java.net.Socket;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import android.annotation.SuppressLint;
import android.os.Build;
import com.fsck.k9.mail.MessagingException;
import com.fsck.k9.security.KeyChainKeyManager;

/**
 * Helper class to create SSL/TLS sockets
 */
public class SslHelper {
    // this indicates we should "harvest" some connection information from
    // inside the TLS handshake, then abort the handshake with a custom
    // exception
    private static ThreadLocal<Boolean> interactiveClientCertificateAliasSelectionRequired = new ThreadLocal<Boolean>() {
        @Override
        protected Boolean initialValue() {
            return Boolean.FALSE;
        }

    };

    public static void setInteractiveClientCertificateAliasSelectionRequired(boolean die) {
        interactiveClientCertificateAliasSelectionRequired.set(die);
    }

    /**
     * KeyChain API available on Android >= 4.0
     * 
     * @return
     */
    public static boolean isClientCertificateSupportAvailable() {
        return (Build.VERSION.SDK_INT >= Build.VERSION_CODES.ICE_CREAM_SANDWICH);
    }

    @SuppressLint("TrulyRandom")
    private static SSLContext createSslContext(String host, int port,
            String clientCertificateAlias) throws NoSuchAlgorithmException, KeyManagementException,
            MessagingException {
        if (!isClientCertificateSupportAvailable()
                &&
                (interactiveClientCertificateAliasSelectionRequired.get() || clientCertificateAlias != null)) {
            throw new MessagingException(
                    "Client certificate support is only availble on Android >= 4.0", true);
        }

        KeyManager[] keyManagers = null;
        if (interactiveClientCertificateAliasSelectionRequired.get()) {
            keyManagers = new KeyManager[] {
                    new KeyChainKeyManager()
            };
        } else if (clientCertificateAlias != null) {
            keyManagers = new KeyManager[] {
                    new KeyChainKeyManager(clientCertificateAlias)
            };
        }

        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(keyManagers,
                new TrustManager[] {
                    TrustManagerFactory.get(
                            host, port)
                },
                new SecureRandom());

        return sslContext;
    }

    public static Socket createSslSocket(String host, int port, String clientCertificateAlias)
            throws NoSuchAlgorithmException, KeyManagementException, IOException,
            MessagingException {
        SSLContext sslContext = createSslContext(host, port, clientCertificateAlias);
        return TrustedSocketFactory.createSocket(sslContext);
    }

    public static Socket createStartTlsSocket(Socket socket, String host, int port, boolean secure,
            String clientCertificateAlias) throws NoSuchAlgorithmException,
            KeyManagementException, IOException, MessagingException {
        SSLContext sslContext = createSslContext(host, port, clientCertificateAlias);
        boolean autoClose = true;
        return TrustedSocketFactory.createSocket(sslContext, socket, host, port, autoClose);
    }
}
