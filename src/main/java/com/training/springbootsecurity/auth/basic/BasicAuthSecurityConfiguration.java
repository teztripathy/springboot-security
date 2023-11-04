package com.training.springbootsecurity.auth.basic;

import static org.springframework.security.config.Customizer.withDefaults;

import javax.sql.DataSource;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseBuilder;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseType;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.jdbc.JdbcDaoImpl;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@Profile("dev")
@EnableMethodSecurity(jsr250Enabled = true, securedEnabled = true) //these parameters are to enable the @RolesAlloed and @Secured attribute and add more redundancey security in the system @Secured is a old standard, and also we can use that.
public class BasicAuthSecurityConfiguration {
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity) throws Exception {
        httpSecurity.authorizeHttpRequests(auth -> {
            auth.anyRequest().authenticated();
        });

        httpSecurity.sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS));
        httpSecurity.formLogin(login -> login.disable());
        httpSecurity.httpBasic(withDefaults());
        httpSecurity.csrf(csrf -> csrf.disable()); //to access h2 database etc.
        httpSecurity.headers(headers -> headers.frameOptions(frameOptions -> frameOptions.sameOrigin())); //to fix the html frames in h2 database page.
        httpSecurity.logout(withDefaults());
        return httpSecurity.build();

    }

    // @Bean
    // public UserDetailsService userDetailsService() {
    // var user =
    // User.withUsername("tejeswar").password("{noop}dummy").roles("USER").build();
    // var admin =
    // User.withUsername("admin").password("{noop}dummy").roles("ADMIN").build();

    // return new InMemoryUserDetailsManager(user, admin);
    // }

    @Bean
    DataSource dataSource() {
        return new EmbeddedDatabaseBuilder()
                .setType(EmbeddedDatabaseType.H2)
                .addScript(JdbcDaoImpl.DEFAULT_USER_SCHEMA_DDL_LOCATION)
                .build();
    }

    @Bean
    UserDetailsService userDetailsService(DataSource dataSource) {
        // var user = User.withUsername("tejeswar").password("{noop}dummy").roles("USER").build();
        // var admin = User.withUsername("admin").password("{noop}dummy").roles("ADMIN").build();

        var user1 = User.withUsername("tejeswar")
                        .password("PaSS#123")
                        .passwordEncoder(pwd -> passwordEncoder().encode(pwd))
                        .roles("USER")
                        .build();
        
        var user2 = User.withUsername("archana")
                        .password("Pizza")
                        .passwordEncoder(pwd -> passwordEncoder().encode(pwd))
                        .roles("USER")
                        .build();

        var admin = User.withUsername("admin")
                        .password("dummy")
                        .passwordEncoder(pwd -> passwordEncoder().encode(pwd))
                        .roles("ADMIN")
                        .build();


        JdbcUserDetailsManager jdbcUserDetailsManager = new JdbcUserDetailsManager(dataSource);
        jdbcUserDetailsManager.createUser(user1);
        jdbcUserDetailsManager.createUser(user2);
        jdbcUserDetailsManager.createUser(admin);

        return jdbcUserDetailsManager;
    }

    @Bean
    BCryptPasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}
