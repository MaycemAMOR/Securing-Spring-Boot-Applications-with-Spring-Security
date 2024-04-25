package com.mytech.learnspringsecurity.resources.basic;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseBuilder;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseType;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.jdbc.JdbcDaoImpl;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

import javax.sql.DataSource;

@Configuration//j'ai commenté cette ligne précedament pour que je puisse utilisé la configuration de jwt
@EnableMethodSecurity(jsr250Enabled = true, securedEnabled = true)
/*****pour activer les differentes methode tq @PreAuthorized @postAuthorized il y a pas d'option a ajouter  @EnableMethodSecurity****
 * **********************************************************************************************************************************
 ******mais si je veux bien les désactiver je dois ajouter l'option  prePostEnabled = false pour les deux pre et post.***************
 * **********************************************************************************************************************************
 *****l'option securedEnabled = true permet d'utliser l'annotation .... @Secured({"ROLE_ADMIN","ROLE_USER"}) ===> @secured test
 * les authorities et pas les roles comme @RolesAllowes ...**************************************************************************
 ****l'option jsr250Enabled = true permet d'utliser l'annotation .... @RolesAllowed({"ADMIN","USER"}) ...*************
 * ***********************************************************************************************************************************
 *****pou plus de details voir : https://www.baeldung.com/spring-security-method-security ********************************************
 * **********************************************************************************************************************************/
public class BasicAuthSecurityConfiguration {

    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests(
                auth -> {
                    auth
                            .requestMatchers("/users").hasRole("USER")
                            .requestMatchers("/admin/**").hasRole("ADMIN")
                            .anyRequest().authenticated();
                });
        http.sessionManagement(
                session ->
                        session.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
        );
        //http.formLogin(Customizer.withDefaults());
        http.httpBasic(Customizer.withDefaults());
        http.csrf(AbstractHttpConfigurer::disable);
        // donner l'acces au frame pour que la console h2 s'affiche correctement
        http.headers(headers ->
                headers.frameOptions(
                        HeadersConfigurer.FrameOptionsConfig::sameOrigin)
        );
        return http.build();
    }

    //    @Bean
//    public UserDetailsService userDetailsService() {
//        var user = User.withUsername("MayTech")
//                .password("{noop}password")
//                .authorities("read", "write")
//                .roles("USER")
//                .build();
//
//        var admin = User.withUsername("admin")
//                .password("{noop}password")
//                .authorities("read", "write")
//                .roles("ADMIN")
//                .build();
//
//        return new InMemoryUserDetailsManager(user, admin);
//    }
//
    @Bean
    public DataSource dataSource() {
        return new EmbeddedDatabaseBuilder()
                .setType(EmbeddedDatabaseType.H2)
                .addScript(JdbcDaoImpl.DEFAULT_USER_SCHEMA_DDL_LOCATION)
                .build();

    }


    @Bean
    public UserDetailsService userDetailsService(DataSource dataSource) {
        var user = User.withUsername("MayTech")
                //.password("{noop}password") // car on va utiliser un encodage la aprés la suivante
                .password("password")
                .passwordEncoder(str -> passwordEncoder().encode(str))
                .authorities("read", "write")
                .roles("USER")
                .build();

        var admin = User.withUsername("admin")
                //.password("{noop}password")
                .password("password")
                .passwordEncoder(str -> passwordEncoder().encode(str))
                .authorities("read", "write")
                .roles("ADMIN", "USER")
                .build();

        var jdbcUserDetailsManager = new JdbcUserDetailsManager(dataSource);
        jdbcUserDetailsManager.createUser(user);
        jdbcUserDetailsManager.createUser(admin);


        return jdbcUserDetailsManager;
    }

    @Bean
    public BCryptPasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

}
