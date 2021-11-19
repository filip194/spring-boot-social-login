package com.iot.demo.clients.sociallogin.security;

import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.oauth2.client.oidc.web.logout.OidcClientInitiatedLogoutSuccessHandler;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;

@EnableWebSecurity
public class WebSecurity extends WebSecurityConfigurerAdapter
{

    // Details of client registration repository will be red from application.properties file, and
    // based on the configured clients that we have, Spring framework will figure out the end_session_endpoint to use
    private final ClientRegistrationRepository clientRegistrationRepository;

    public WebSecurity(ClientRegistrationRepository clientRegistrationRepository)
    {
        this.clientRegistrationRepository = clientRegistrationRepository;
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception
    {
        http
                .authorizeRequests()
                .antMatchers("/").permitAll()
                .anyRequest().authenticated()
                .and()
                .oauth2Login()
                .and()
                .logout()
                // logoutSuccessUrl(...) should not be used together with logoutSuccessHandler
//                .logoutSuccessUrl("/")
                .logoutSuccessHandler(oidcLogoutSuccessHandler())
                // next 2 will be done automatically by Spring Boot Security
                .invalidateHttpSession(true)
                .clearAuthentication(true)
                .deleteCookies("JSESSIONID");
    }

    // NOTE: Works only for Okta (does not work for Keycloak, Facebook, Google...)
    private OidcClientInitiatedLogoutSuccessHandler oidcLogoutSuccessHandler()
    {
        final OidcClientInitiatedLogoutSuccessHandler successHandler =
                new OidcClientInitiatedLogoutSuccessHandler(clientRegistrationRepository);
        // We only need to tell Spring where user will be redirected after session logout
        successHandler.setPostLogoutRedirectUri("http://localhost:9090/");
        return successHandler;
    }
}

