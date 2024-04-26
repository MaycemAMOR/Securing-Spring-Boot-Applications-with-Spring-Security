# Securing-Spring-Boot-Applications-with-Spring-Security

## Setting Up JWT Auth with Spring Security and Spring Boot : 

### Getting Started With JWT Security Configuration: 

![alt text](<Getting Started With JWT Security Configuration.PNG>)


#### JWT Authentication Using Spring Boot's OAuth2 Resorce Server: 

1: Create Key Pair: We will use java.security.keyPairGenerator.
                    We can use openssl as well

2: Create RSA Key object using Key Pair:  we will use com.nimbus.jose.jwk.RSAKey

3: Create JWKSource(JSON Web Key source) : Create JWKSet (a new json web key set) with the RSA key.
                                           Create JWKSourse using the JWKSet.

4: Use RSA Public Key for Secoding: We will use NimbusJwtDecoder.WithPublicKey(rsaKey().toRSAPublicKey()).build() .

5: Use JWKSource for Encoding: we will return new NimbusJwtEncoder(jwkSource());.


## Setting Up JWT Resource with Spring Security and Spring Boot :

### Understanding high Level JWT Flow 

![alt text](<Understanding high Level JWT Flow .PNG>)


1: Create a JWT 
    - Needs Encoding : 1: User credentials.
                       2: User data (payload).
                       3: RSA key pair
    - we will create a JWT Resource for creating Jwt.

2: Send JWT as part of request header:
    - Autorization Header
    - Bearer Token
    - Authorization : Bearer ${JWT_TOKEN}

3: JWT is verified:
    - Needs Decoding.
    - RSA key pair (Public Key).


## Understanding Spring Security Authentication: 

![alt text](<Understanding Spring Security Authentication.PNG>)

### Authentication is done as part of the Spring Security Filter Chain :

1: AuthentificationManger- Responsible for authentication:
    Can interact with Multiple Authentication Providers.

2: AuthenticationProvider- Perform specific authentication type : JwtAuthenticationProvider- JWT Authentication

3: UserDetailsService- Core interface to load user data

How is authentication result stored ? 
    ==> SecurityContextHolder > SecurityContext > Authentication > GrantedAuthority
            - Authentication - (After authentication) Holds user (Principal) details.
            - GrantedAuthority - An Authority granted to principal(roles, scopes,...),



## Exploring Spring Security Authorization

![alt text](<Exploring Spring Security Authorization.PNG>)
### 1: Global Security: authorize HttpRequests: 
    -requestMatchers("/users").hasRole("USER")
        * HasRole, hasAuthority, hasAnyAurhority, isAuthenticated ....

### 2: Method Security(@EnableMethodSecurity): 
    -@Pre and @Post Annotations:
        @PreAuthorize("hasRole('USER')and #username==authentication.name") : at TodoResource (controller) 
        @PostAuthorize("returnObject.username=='MayTech'") : at TodoResource (controller) 
    
    -JSR-250 annotations:
        @EnableMethodSecurity(jsr250Enabled=true) : at BasicAuthSecurityConfiguration (configuration)
        @RolesAllowed({"ADMIN","USER"}) :  at TodoResource  (controller) 
    
    -@Secured annotation: 
        @EnableMethodSecurity(securedEnabled=true) : at BasicAuthSecurityConfiguration (configuration)
        @Secured({"ROLE_ADMIN","ROLE_USER"}) :  at TodoResource  (controller)


## Author

#### Maycem AMOR 
#### Contact: MaycemAmor@gmail.com 
