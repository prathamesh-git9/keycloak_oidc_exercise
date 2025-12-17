package com.prathamesh.keycloak.frontend.web;

import java.util.List;

import com.prathamesh.keycloak.frontend.calendar.CalendarApi;
import com.prathamesh.keycloak.frontend.calendar.CalendarApi.CalendarEvent;

import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.annotation.RegisteredOAuth2AuthorizedClient;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

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

        String accessToken = client.getAccessToken().getTokenValue();
        List<CalendarEvent> events = calendarApi.getEvents(accessToken);

        model.addAttribute("username", user.getPreferredUsername());
        model.addAttribute("events", events);

        return "index";
    }
}
