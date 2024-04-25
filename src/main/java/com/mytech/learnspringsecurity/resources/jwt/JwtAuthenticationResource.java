package com.mytech.learnspringsecurity.resources.jwt;

import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.PostMapping;

//@RestController
public class JwtAuthenticationResource {

    private final JwtTokenService tokenService;


    public JwtAuthenticationResource(JwtTokenService tokenService) {
        this.tokenService = tokenService;
    }

    @PostMapping("${jwt.get.token.uri}")
    public JwtTokenResponse generateToken(Authentication authentication) {

//       var authenticationToken = new UsernamePasswordAuthenticationToken(jwtTokenRequest.username(), jwtTokenRequest.password());
//
//       var authentication = authenticationManager.authenticate(authenticationToken);


        var token = tokenService.generateToken(authentication);

        return new JwtTokenResponse(token);
    }
}
