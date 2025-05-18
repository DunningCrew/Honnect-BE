package com.honnect.server.infra.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {
    private final JwtTokenProvider tokenProvider;
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        try {
            // 요청에서 JWT 토큰 추출
            String jwt = getJwtFromRequest(request);

            // JWT 유효성 검사 및 사용자 식별자 추출
            if (jwt != null && tokenProvider.validateToken(jwt)) {
                String userId = tokenProvider.getUserIdFromJWT(jwt);

                // UserPrincipal 객체 생성
                UserPrincipal userPrincipal = new UserPrincipal(userId, null);

                // SecurityContext에 인증 정보 설정
                UsernamePasswordAuthenticationToken authentication =
                        new UsernamePasswordAuthenticationToken(userPrincipal, null, Collections.emptyList());
                authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

                SecurityContextHolder.getContext().setAuthentication(authentication);
            }
        } catch (Exception ex) {
            // 인증 실패 시 로그 출력
            logger.error("Failed to set user authentication in security context", ex);
        }

        // 다음 필터로 요청 전달
        filterChain.doFilter(request, response);
    }
    private String getJwtFromRequest(HttpServletRequest request) {  //쿠키에서 jwt추출 메서드

       Cookie[] cookie = request.getCookies();
        for (Cookie cookie1 : cookie) {
           String a= cookie1.getName();

        if( a.equals("access-token")){
            return cookie1.getValue();
        }

    }

        return null;
    }
}
