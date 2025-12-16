package com.prathamesh.keycloak.calendar.api;

import java.time.OffsetDateTime;
import java.util.List;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class CalendarController {

    @GetMapping("/api/calendar")
    public List<CalendarEvent> getCalendar() {
        return List.of(
                new CalendarEvent("Standup", OffsetDateTime.now().plusMinutes(15)),
                new CalendarEvent("Interview prep", OffsetDateTime.now().plusHours(2))
        );
    }

    public record CalendarEvent(String title, OffsetDateTime startsAt) { }
}