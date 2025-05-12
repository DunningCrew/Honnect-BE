package com.honnect.server.infra.security;

import lombok.Getter;
import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
@Getter
public class UserPrincipal {

    private final Long id;
    private final String username;
}
