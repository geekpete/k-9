
package com.fsck.k9.mail;

/**
 * This exception is thrown when, during an ssl handshake, a client certificate
 * is requested but the user didn't provide one
 * 
 * @author Konrad Gadzinowski
 */
public class ClientCertificateRequiredException extends RuntimeException {
    public static final long serialVersionUID = -1;

    public ClientCertificateRequiredException(Exception e) {
        super("Client certificate wasn't set, but is required to authenticate", e);
    }

}
