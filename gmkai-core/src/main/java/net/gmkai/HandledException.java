package net.gmkai;

import javax.net.ssl.SSLException;

public class HandledException extends SSLException {


    HandledException(AlertException alertException) {
        super(alertException.getMessage(), alertException);
    }
}
