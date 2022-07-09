package com.majid.jwt_article.impl;

import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.springframework.stereotype.Component;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.Date;

@Slf4j
@Component
class InMemoryKeys { // not to be used in production
    public static final PrivateKey PRIVATE_KEY;
    public static final PublicKey PUBLIC_KEY;
    public static final X509Certificate SELF_SIGNED_CERT;
    public static final Base64.Encoder ENCODER = Base64.getEncoder();
    public static final Base64.Decoder DECODER = Base64.getDecoder();

    static {
        try {
            Security.addProvider(new BouncyCastleProvider());

            KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
            kpg.initialize(2048);
            KeyPair keyPair = kpg.generateKeyPair();

            PRIVATE_KEY = keyPair.getPrivate();
            PUBLIC_KEY = keyPair.getPublic();
            SELF_SIGNED_CERT = createCertificate();

            print(SELF_SIGNED_CERT);

        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private static X509Certificate createCertificate() throws OperatorCreationException, CertificateException {
        X500Name dnName = new X500Name("cn=articles.majid.com,o=null,l=berlin,c=de");
        BigInteger certSerialNumber = BigInteger.valueOf(System.currentTimeMillis());
        ContentSigner contentSigner = new JcaContentSignerBuilder("SHA256WithRSA")
                .build(InMemoryKeys.PRIVATE_KEY);
        Instant startDate = Instant.now();
        Instant endDate = startDate.plus(1, ChronoUnit.DAYS);
        JcaX509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
                dnName, certSerialNumber, Date.from(startDate), Date.from(endDate), dnName,
                InMemoryKeys.PUBLIC_KEY);
        Certificate certificate = new JcaX509CertificateConverter()
                .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                .getCertificate(certBuilder.build(contentSigner));
        return (X509Certificate) certificate;
    }

    private static void print(X509Certificate cert) throws CertificateEncodingException {
        log.info("self-signed cert {} ", new String(ENCODER.encode(cert.getEncoded()), StandardCharsets.US_ASCII));
    }

}
