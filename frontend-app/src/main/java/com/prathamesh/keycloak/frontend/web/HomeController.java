package com.prathamesh.keycloak.frontend.web;

import java.util.List;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.annotation.RegisteredOAuth2AuthorizedClient;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

import com.prathamesh.keycloak.frontend.calendar.CalendarApi;
import com.prathamesh.keycloak.frontend.calendar.CalendarApi.CalendarEvent;

@Controller
public class HomeController {

    private final CalendarApi calendarApi;

    public HomeController(CalendarApi calendarApi) {
        this.calendarApi = calendarApi;
    }

    @GetMapping("/")
    public String index(Model model,
            @AuthenticationPrincipal OidcUser user,
            @RegisteredOAuth2AuthorizedClient("keycloak") OAuth2AuthorizedClient client) {

        // Prod note: The Token validation
        // In real prod check the token if its near its expiry before using the token
        //AuthorizedClientRepository handling it but still some explicit checks needed
        // prevent sending stale tokens to the downstream API
        Authentication a = SecurityContextHolder.getContext().getAuthentication();
        System.out.println("=== HomeController Debug ===");
        System.out.println("USER=" + a.getName());
        System.out.println("AUTH=" + a.getAuthorities());
        if (user != null && user.getIdToken() != null) {
            System.out.println("ID Token Claims:");
            user.getIdToken().getClaims().forEach((key, value)
                    -> System.out.println("  " + key + " = " + value)
            );
        }
        System.out.println("=== End Debug ===");

        String accessToken = client.getAccessToken().getTokenValue();

        // Prod note: Resilience
        // This remote call to 'calendarApi' is one failure point
        // In prod this should be wrapped in circuit breaker
        // if the calendar is down, we should get fallback
        // Rather then the exception crash the page
        List<CalendarEvent> events = calendarApi.getEvents(accessToken);

        model.addAttribute("username", user.getPreferredUsername());
        model.addAttribute("events", events);

        return "index";
    }
}
