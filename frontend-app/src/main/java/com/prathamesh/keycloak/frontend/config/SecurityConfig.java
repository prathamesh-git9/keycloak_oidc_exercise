package com.prathamesh.keycloak.frontend.config;

import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest;
import org.springframework.security.oauth2.client.oidc.web.logout.OidcClientInitiatedLogoutSuccessHandler;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;

@Configuration
public class SecurityConfig {

    private static final String ROLE_PREFIX = "ROLE_";

    @Value("${app.security.required-role}")
    private String requiredRole;

    @Bean
    LogoutSuccessHandler oidcLogoutSuccessHandler(ClientRegistrationRepository repo) {
        OidcClientInitiatedLogoutSuccessHandler handler
                = new OidcClientInitiatedLogoutSuccessHandler(repo);
        handler.setPostLogoutRedirectUri("{baseUrl}/logged-out");
        return handler;
    }

    @Bean
    SecurityFilterChain securityFilterChain(
            HttpSecurity http,
            OAuth2UserService<OidcUserRequest, OidcUser> keycloakOidcUserService, // Injected here
            LogoutSuccessHandler oidcLogoutSuccessHandler
    ) throws Exception {

        http
                .authorizeHttpRequests(auth -> auth
                .requestMatchers("/error", "/forbidden", "/logged-out", "/login**", "/oauth2/**").permitAll()
                .anyRequest().hasAuthority(ROLE_PREFIX + requiredRole)
                )
                .oauth2Login(oauth -> oauth
                .userInfoEndpoint(userInfo -> userInfo.oidcUserService(keycloakOidcUserService))
                .defaultSuccessUrl("/", true)
                )
                .oauth2Client(Customizer.withDefaults())
                .logout(logout -> logout
                .logoutRequestMatcher(request -> {
                    String method = request.getMethod();
                    String path = request.getRequestURI();
                    boolean matchesPath = path != null && path.endsWith("/logout");
                    boolean matchesMethod = "POST".equalsIgnoreCase(method) || "GET".equalsIgnoreCase(method);
                    return matchesPath && matchesMethod;
                })
                .logoutSuccessHandler(oidcLogoutSuccessHandler)
                .invalidateHttpSession(true)
                .clearAuthentication(true)
                .deleteCookies("JSESSIONID")
                )
                .exceptionHandling(ex -> ex.accessDeniedPage("/forbidden"));

        return http.build();
    }

    @SuppressWarnings("unchecked")
    private List<String> extractRolesFromClaims(Map<String, Object> claims) {
        // Try realm_access.roles
        Object realmAccess = claims.get("realm_access");
        if (realmAccess instanceof Map) {
            Map<String, Object> realmAccessMap = (Map<String, Object>) realmAccess;
            Object roles = realmAccessMap.get("roles");
            if (roles instanceof List) {
                return ((List<?>) roles).stream()
                        .map(Object::toString)
                        .collect(Collectors.toList());
            }
        }
        // Try direct roles claim
        Object roles = claims.get("roles");
        if (roles instanceof List) {
            return ((List<?>) roles).stream()
                    .map(Object::toString)
                    .collect(Collectors.toList());
        }
        return List.of();
    }
}
