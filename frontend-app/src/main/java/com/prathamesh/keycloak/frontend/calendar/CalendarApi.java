package com.prathamesh.keycloak.frontend.calendar;

import java.time.Instant;
import java.util.List;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.HttpHeaders;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestClient;

@Component
public class CalendarApi {

    private final RestClient restClient;

    public CalendarApi(@Value("${app.calendar.base-url}") String baseUrl) {
        this.restClient = RestClient.builder()
                .baseUrl(baseUrl)
                .build();
    }


    public List<CalendarEvent> getEvents(String accessToken) {
        return restClient.get()
                .uri("/api/calendar")
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + accessToken)
                .retrieve()
                .body(new ParameterizedTypeReference<>() {});
    }

    public record CalendarEvent(String title, Instant startsAt) {}
}
