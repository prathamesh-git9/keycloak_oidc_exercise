package com.prathamesh.keycloak.frontend.config;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Collection;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.web.SecurityFilterChain;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.context.annotation.Bean;


@Configuration
public class SecurityConfig {

    private static final String ROLE_PREFIX = "ROLE_";

    @Bean
    ObjectMapper objectMapper() {
        return new ObjectMapper();
    }

    @Bean
    SecurityFilterChain securityFilterChain(
            HttpSecurity http,
            OAuth2UserService<OidcUserRequest, OidcUser> oidcUserService
    ) throws Exception {

        http
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/error", "/login**", "/oauth2/**").permitAll()
                        .anyRequest().hasAuthority("ROLE_my-role")
                )
                .oauth2Login(oauth -> oauth
                        .userInfoEndpoint(userInfo -> userInfo.oidcUserService(oidcUserService))
                )
                .oauth2Client(Customizer.withDefaults());

        return http.build();
    }

    @Bean
    OAuth2UserService<OidcUserRequest, OidcUser> oidcUserService(ObjectMapper objectMapper) {
        OidcUserService delegate = new OidcUserService();

        return (userRequest) -> {
            OidcUser oidcUser = delegate.loadUser(userRequest);

            Map<String, Object> accessTokenClaims =
                    decodeJwtPayload(userRequest.getAccessToken().getTokenValue(), objectMapper);

            Set<GrantedAuthority> mapped = new HashSet<>(oidcUser.getAuthorities());
            mapped.addAll(extractRealmRoles(accessTokenClaims));
            mapped.addAll(extractClientRoles(accessTokenClaims, "frontend-app"));

            return new DefaultOidcUser(
                    mapped,
                    oidcUser.getIdToken(),
                    oidcUser.getUserInfo(),
                    "preferred_username"
            );
        };
    }

    private Map<String, Object> decodeJwtPayload(String jwt, ObjectMapper objectMapper) {
        try {
            String[] parts = jwt.split("\\.");
            if (parts.length < 2) {
                return Map.of();
            }
            byte[] decoded = Base64.getUrlDecoder().decode(parts[1]);
            String json = new String(decoded, StandardCharsets.UTF_8);
            return objectMapper.readValue(json, new TypeReference<Map<String, Object>>() {});
        } catch (Exception e) {
            return Map.of();
        }
    }

    private Set<GrantedAuthority> extractRealmRoles(Map<String, Object> claims) {
        Set<GrantedAuthority> roles = new HashSet<>();

        Object realmAccess = claims.get("realm_access");
        if (realmAccess instanceof Map<?, ?> ra) {
            Object roleList = ra.get("roles");
            if (roleList instanceof Collection<?> list) {
                for (Object r : list) {
                    if (r instanceof String roleName) {
                        roles.add(new SimpleGrantedAuthority(ROLE_PREFIX + roleName));
                    }
                }
            }
        }

        return roles;
    }

    private Set<GrantedAuthority> extractClientRoles(Map<String, Object> claims, String clientId) {
        Set<GrantedAuthority> roles = new HashSet<>();

        Object resourceAccess = claims.get("resource_access");
        if (resourceAccess instanceof Map<?, ?> res) {
            Object client = res.get(clientId);
            if (client instanceof Map<?, ?> clientMap) {
                Object roleList = clientMap.get("roles");
                if (roleList instanceof Collection<?> list) {
                    for (Object r : list) {
                        if (r instanceof String roleName) {
                            roles.add(new SimpleGrantedAuthority(ROLE_PREFIX + roleName));
                        }
                    }
                }
            }
        }

        return roles;
    }
}
