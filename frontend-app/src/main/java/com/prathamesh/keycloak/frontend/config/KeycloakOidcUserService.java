package com.prathamesh.keycloak.frontend.config;

import java.text.ParseException;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.stereotype.Service;

import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.JWTParser;

@Service
public class KeycloakOidcUserService implements OAuth2UserService<OidcUserRequest, OidcUser> {

    static {
        System.out.println("*** KeycloakOidcUserService CLASS LOADED ***");
        System.out.flush();
    }

    public KeycloakOidcUserService() {
        System.out.println("*** KeycloakOidcUserService CONSTRUCTOR CALLED ***");
        System.out.flush();
    }

    private final OidcUserService delegate = new OidcUserService();

    @Override
    public OidcUser loadUser(OidcUserRequest userRequest) throws OAuth2AuthenticationException {
        System.out.println("*** KeycloakOidcUserService.loadUser() CALLED ***");
        System.out.flush();

        OidcUser oidcUser = delegate.loadUser(userRequest);
        Map<String, Object> accessTokenClaims = extractAccessTokenClaims(userRequest);

        // Debug: Print token claims to see what's available
        System.out.println("=== Token Claims Debug ===");
        System.out.flush();
        oidcUser.getClaims().forEach((key, value)
                -> System.out.println("Claim: " + key + " = " + value)
        );
        System.out.println("=== End Token Claims ===");

        // Extract roles from Keycloak token and convert to Spring Security authorities
        Collection<GrantedAuthority> authorities = extractAuthorities(oidcUser, accessTokenClaims);

        System.out.println("=== Extracted Authorities ===");
        authorities.forEach(auth -> System.out.println("Authority: " + auth.getAuthority()));
        System.out.println("=== End Authorities ===");

        // Return a new OidcUser with the extracted authorities
        return new DefaultOidcUser(authorities, oidcUser.getIdToken(), oidcUser.getUserInfo());
    }

    private Collection<GrantedAuthority> extractAuthorities(OidcUser oidcUser, Map<String, Object> accessTokenClaims) {
        Map<String, Object> idTokenClaims = oidcUser.getClaims();

        // Collect roles from both ID token and access token to handle Keycloak defaults
        List<String> roles = Stream.of(idTokenClaims, accessTokenClaims)
                .filter(Objects::nonNull)
                .flatMap(claims -> Stream.of(
                extractRolesFromRealmAccess(claims),
                extractRolesFromDirectClaim(claims, "roles"),
                extractRolesFromResourceAccess(claims))
                .flatMap(List::stream))
                .distinct()
                .collect(Collectors.toList());

        // Convert roles to Spring Security authorities with ROLE_ prefix
        return roles.stream()
                .map(role -> new SimpleGrantedAuthority("ROLE_" + role))
                .collect(Collectors.toList());
    }

    @SuppressWarnings("unchecked")
    private List<String> extractRolesFromRealmAccess(Map<String, Object> claims) {
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
        return List.of();
    }

    @SuppressWarnings("unchecked")
    private List<String> extractRolesFromDirectClaim(Map<String, Object> claims, String claimName) {
        Object claimValue = claims.get(claimName);
        if (claimValue instanceof List) {
            return ((List<?>) claimValue).stream()
                    .map(Object::toString)
                    .collect(Collectors.toList());
        }
        return List.of();
    }

    @SuppressWarnings("unchecked")
    private List<String> extractRolesFromResourceAccess(Map<String, Object> claims) {
        Object resourceAccess = claims.get("resource_access");
        if (resourceAccess instanceof Map) {
            Map<String, Object> resourceAccessMap = (Map<String, Object>) resourceAccess;
            // Check each resource for roles
            return resourceAccessMap.values().stream()
                    .filter(Map.class::isInstance)
                    .map(m -> (Map<String, Object>) m)
                    .filter(m -> m.containsKey("roles"))
                    .map(m -> m.get("roles"))
                    .filter(List.class::isInstance)
                    .map(l -> (List<?>) l)
                    .flatMap(List::stream)
                    .map(Object::toString)
                    .collect(Collectors.toList());
        }
        return List.of();
    }

    private Map<String, Object> extractAccessTokenClaims(OidcUserRequest userRequest) {
        String tokenValue = userRequest.getAccessToken().getTokenValue();
        try {
            JWT jwt = JWTParser.parse(tokenValue);
            JWTClaimsSet claimsSet = jwt.getJWTClaimsSet();
            return claimsSet == null ? Map.of() : claimsSet.getClaims();
        } catch (ParseException ex) {
            throw new OAuth2AuthenticationException(
                    new OAuth2Error("invalid_token", "Unable to parse Keycloak access token", null),
                    ex);
        }
    }
}
