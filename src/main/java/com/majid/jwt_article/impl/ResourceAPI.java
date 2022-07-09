package com.majid.jwt_article.impl;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.*;

import static org.springframework.http.MediaType.APPLICATION_JSON_VALUE;

@RestController
@RequestMapping("/some/resource-controller")
@RequiredArgsConstructor
@Slf4j
class ResourceAPI {
    private final TokenService tokenService;

    @GetMapping(path = "protected-resource", produces = {APPLICATION_JSON_VALUE})
    @PostMapping(consumes = MediaType.APPLICATION_JSON_UTF8_VALUE, produces = MediaType.APPLICATION_JSON_UTF8_VALUE)
    public String someProtectedMethod(@RequestBody  Token token) {
        Principal principal = tokenService.verifyToken(token);
        log.info("Found principal {} ", principal);
        return "resource has been access successfully by " + principal;
    }
}
