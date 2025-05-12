package com.honnect.server.infra.security;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "security.token")
public record JwtTokenProperties(
        String secretKey,
        Long expirationTime
) {
}
