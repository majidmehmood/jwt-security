package com.majid.jwt_article.impl;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import lombok.RequiredArgsConstructor;
import org.bouncycastle.jcajce.provider.asymmetric.x509.CertificateFactory;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Date;
import java.util.UUID;

@Service
@RequiredArgsConstructor
class TokenService {
    private final ObjectMapper objectMapper;

    public Principal verifyCert(String cert) {
        if (cert == null) {
            return null;
        }

        cert = cert
                .replace("-----BEGIN CERTIFICATE-----", "")
                .replace("-----END CERTIFICATE-----", "")
                .replaceAll("\\s", "");

        try (ByteArrayInputStream bytes = new ByteArrayInputStream(InMemoryKeys.DECODER.decode(cert.getBytes(StandardCharsets.US_ASCII)))) {
            Security.addProvider(new BouncyCastleProvider());
            CertificateFactory factory = new CertificateFactory();
            X509Certificate certificate = (X509Certificate) factory.engineGenerateCertificate(bytes);
            certificate.verify(InMemoryKeys.PUBLIC_KEY);
            return Principal.builder().user(certificate.getIssuerDN().getName()).build();
        } catch (Exception e) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "client-cert is invalid:" + cert);
        }

    }

    public Token createTokenFor(Principal principal) {
        if (principal == null) {
            return null;
        }

        try {
            LocalDateTime currentTime = LocalDateTime.now();
            Date issueTime = Date.from(currentTime.atZone(ZoneId.systemDefault()).toInstant());
            Date expiryTime = Date.from(currentTime.plusMinutes(10).atZone(ZoneId.systemDefault()).toInstant());
            String id = UUID.randomUUID().toString();
            String principalAsJson = objectMapper.writeValueAsString(principal);
            String token = Jwts.builder()
                    .setIssuer(TokenAPI.class.getName())
                    .setId(id)
                    .setSubject(principalAsJson)
                    .setIssuedAt(issueTime)
                    .setExpiration(expiryTime)
                    .signWith(SignatureAlgorithm.RS256, InMemoryKeys.PRIVATE_KEY)
                    .compact();

            return Token.builder().jwt(token).build();

        } catch (Exception e) {
            throw new RuntimeException(e);
        }

    }

    public Principal verifyToken(Token token) {
        try {
            Object jwtToken = Jwts.parser()
                    .setSigningKey(InMemoryKeys.PUBLIC_KEY)
                    .parse(token.getJwt()).getBody();
            if (jwtToken instanceof Claims) {
                Claims c =  ((Claims) jwtToken);
                Principal principal = objectMapper.readValue(c.getSubject(), Principal.class);
                return principal;
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        throw new ResponseStatusException(HttpStatus.FORBIDDEN, "jwt token is invalid:" + token);
    }





}
