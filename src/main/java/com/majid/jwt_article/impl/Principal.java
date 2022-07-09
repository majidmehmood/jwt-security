package com.majid.jwt_article.impl;

import lombok.Builder;
import lombok.ToString;
import lombok.Value;
import lombok.extern.jackson.Jacksonized;

@Builder
@Jacksonized
@Value
@ToString
class Principal {
    String user;
}
