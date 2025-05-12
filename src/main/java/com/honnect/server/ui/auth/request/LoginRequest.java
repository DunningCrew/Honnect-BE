package com.honnect.server.ui.auth.request;

public record LoginRequest(
        String username,
        String password
) {
}
