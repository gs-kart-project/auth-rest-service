package com.gskart.user.utils;

import java.io.IOException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

public interface IGskartKeystore {
    RSAPublicKey readPublicKey() throws CertificateException, KeyStoreException, IOException, NoSuchAlgorithmException;
    RSAPrivateKey readPrivateKey() throws CertificateException, KeyStoreException, IOException, NoSuchAlgorithmException, UnrecoverableKeyException;
}
