package com.honnect.server.ui.auth.request;

public record RegisterRequest(
        String username,
        String password
) {
}
