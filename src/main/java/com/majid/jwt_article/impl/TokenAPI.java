package com.majid.jwt_article.impl;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.nio.charset.StandardCharsets;


@RestController
@RequestMapping("/some/access-controller")
@RequiredArgsConstructor
@Slf4j
class TokenAPI {
    private final TokenService tokenService;
    private static final String BEARER = "Bearer ";
    private static final String X_AUTHORIZATION_HEADERNAME = "X-Authorization";

    @PostMapping(consumes = MediaType.APPLICATION_JSON_UTF8_VALUE, produces = MediaType.APPLICATION_JSON_UTF8_VALUE)
    public Token token(@RequestHeader(X_AUTHORIZATION_HEADERNAME) String clientCert) {
        if (clientCert.startsWith(BEARER)) {
            clientCert = clientCert.substring(clientCert.toLowerCase().indexOf(BEARER) + BEARER.length());
        }
        Principal principal = tokenService.verifyCert(clientCert);
        return tokenService.createTokenFor(principal);
    }


}
