package com.gskart.user.utils;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.Resource;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

@Component
public class GskartKeystore implements IGskartKeystore {
    @Value("${gskart.jwt.keystore.path}")
    private String keystoreFilePath;

    @Value("${gskart.jwt.keystore.password}")
    private String keystorePassword;

    @Value("${gskart.jwt.keystore.keyPairAlias}")
    private String keyPairAlias;

    private KeyStore rsaKeyStore;

    private KeyStore readKeystore() throws KeyStoreException, IOException, CertificateException, NoSuchAlgorithmException {
        if(rsaKeyStore == null) {
            rsaKeyStore = KeyStore.getInstance("JKS");
            Resource keystoreFileResource = new ClassPathResource(keystoreFilePath);
            rsaKeyStore.load(keystoreFileResource.getInputStream(), keystorePassword.toCharArray());
        }
        return rsaKeyStore;
    }

    public RSAPublicKey readPublicKey() throws CertificateException, KeyStoreException, IOException, NoSuchAlgorithmException {
        KeyStore rsaKeyStore = readKeystore();
        Certificate certificate = rsaKeyStore.getCertificate(keyPairAlias);
        RSAPublicKey publicKey = (RSAPublicKey) certificate.getPublicKey();
        return publicKey;
    }

    public RSAPrivateKey readPrivateKey() throws CertificateException, KeyStoreException, IOException, NoSuchAlgorithmException, UnrecoverableKeyException {
        KeyStore rsaKeyStore = readKeystore();
        RSAPrivateKey privateKey = (RSAPrivateKey) rsaKeyStore.getKey(keyPairAlias, keystorePassword.toCharArray());
        return privateKey;
    }
}
