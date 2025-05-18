package com.honnect.server.application.auth;

import com.honnect.server.domain.Member;
import com.honnect.server.domain.MemberRepository;
import com.honnect.server.infra.security.JwtTokenProvider;
import com.honnect.server.infra.security.UserPrincipal;
import io.jsonwebtoken.Jwts;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
public class AuthService {

    private final MemberRepository memberRepository;
    private final JwtTokenProvider tokenProvider;

    @Transactional
    public void register(String username, String password) {
        if (memberRepository.existsByUsername(username)) {
            throw new IllegalArgumentException("이미 존재하는 사용자 이름입니다.");
        }

        Member member = new Member(username, password);
        memberRepository.save(member);
    }

    public String login(String username, String password) {
        Member member = memberRepository.findByUsername(username)
                .orElseThrow(() -> new IllegalArgumentException("존재하지 않는 사용자입니다."));

        if (!member.getPassword().equals(password)) {
            throw new IllegalArgumentException("비밀번호가 일치하지 않습니다.");
        }

        UserPrincipal principal = new UserPrincipal(member.getId(), member.getUsername());
        return tokenProvider.generateToken(principal);
    }

}
