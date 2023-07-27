package com.example.SpringSecurity.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Role;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCrypt;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.provisioning.UserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    public BCryptPasswordEncoder getPasswordEncoder(){
        return new BCryptPasswordEncoder();
    }

    @Bean
    public UserDetailsService userDetailsService(){
        UserDetails student = User.builder().username("Ayan")
                .password(getPasswordEncoder().encode("ayan123"))
                .roles("STUDENT")
                .build();

        UserDetails admin = User.builder().username("bindu")
                .password(getPasswordEncoder().encode("bindu123"))
                .roles("ADMIN")
                .build();

        return new InMemoryUserDetailsManager(student, admin);
    }
    @Bean
    public SecurityFilterChain getSecurityFilterChain(HttpSecurity httpSecurity) throws Exception {

         httpSecurity.csrf().disable()
                .authorizeRequests()
                .requestMatchers("/public/**")
                .permitAll()
                 .requestMatchers("/student/welcome")
                 .hasAnyRole("STUDENT", "ADMIN")
                 .requestMatchers("admin/**")
                 .hasRole("ADMIN")
                .anyRequest()
                .authenticated()
                .and()
                .formLogin();

         return httpSecurity.build();
    }
}
