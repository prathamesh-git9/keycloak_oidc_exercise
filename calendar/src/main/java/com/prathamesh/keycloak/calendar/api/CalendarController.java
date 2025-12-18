package com.prathamesh.keycloak.calendar.api;

import java.time.OffsetDateTime;
import java.util.List;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class CalendarController {

    // Prod note: Granular Security
    // Right now we just check if they are logged in.
    // In production we should use @PreAuthorize to check specific scopes like "read:calendar"
    // ensuring the token is actually meant for this specific operation.
    @GetMapping("/api/calendar")
    // Timeout check is needed and the defaults are infinite
    public List<CalendarEvent> getCalendar() {
        return List.of(
                new CalendarEvent("Standup", OffsetDateTime.now().plusMinutes(15)),
                new CalendarEvent("Interview prep", OffsetDateTime.now().plusHours(2))
        );
    }

    public record CalendarEvent(String title, OffsetDateTime startsAt) { }
}