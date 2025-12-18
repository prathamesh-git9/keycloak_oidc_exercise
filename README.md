Keycloak OIDC Exercise

This is my submission for the Keycloak OIDC take-home exercise.
It demonstrates a simple but production-oriented OpenID Connect integration using Spring Boot and Keycloak.
The goal was correctness, clarity, and clean security boundaries rather than feature overload.

Architecture Overview

The system is split into three clear parts:

1. frontend-app
   A Spring Boot MVC application that acts as an OAuth2 / OIDC client.
   It handles user login, enforces authorization rules, and calls the backend service using an access token.

2. calendar service
   A protected REST API that returns calendar events.
   It only accepts requests authenticated with a valid Keycloak access token.

3. Keycloak
   Acts as the Identity Provider and Authorization Server.
   It manages users, roles, login, and token issuance.

This separation mirrors a typical microservice setup where the frontend never trusts user input directly and all backend access is token based.

Implemented Requirements

All core requirements from the exercise are fully implemented.

- OIDC Login
  Users authenticate via Keycloak using the Authorization Code flow.

- Role-based Authorization
  Only users with the role "my-role" are authorized to access the frontend application.
  Users without this role are redirected to an access denied page.

- Token Propagation
  The frontend forwards the Keycloak access token when calling the calendar service.

- Token Validation
  The calendar service validates the token signature and issuer before returning data.

- End-to-end Flow
  Logged-in users with the correct role can see calendar events rendered in the UI.

Senior / Additional Improvements

I added a few specific improvements to make the application more robust and closer to what I would ship in production.

1. Role Externalization
   Instead of hardcoding "my-role" deep in the Java code, I extracted it to reference a property key (app.security.required-role). This allows the authorization policy to be changed via configuration without recompiling the application.

2. Audience Validation (Security)
   I noticed that standard Spring Security validation only checks the Issuer. I added a custom AudienceValidator to the Calendar API to strictly check the "aud" claim. This ensures that a token issued for another application cannot be reused to access this API.

3. Code Refactoring
   I extracted the complex Role Mapping logic into a separate service class (KeycloakOidcUserService). This keeps the SecurityConfig clean and focused solely on configuration.

Production Considerations

This is a demo application, so some trade-offs were made intentionally.
I added targeted "PROD NOTE" comments in the code (e.g., in HomeController and CalendarApi) where production improvements would be required.

If this were deployed to production, the next steps would be:

- Resilience Between Services
  I noted that the http call needs a Circuit Breaker. Currently, if the backend hangs, the frontend hangs.

- Secrets Management
  Load Keycloak URLs and credentials from environment variables or a secrets manager, rather than application.properties.

- Observability
  Add structured logging and request correlation across services.

How to Run the Application

Start Keycloak
  cd infra
  docker-compose up -d

Run the Calendar Service
  cd calendar
  ./mvnw spring-boot:run

Run the Frontend Application
  cd frontend-app
  ./mvnw spring-boot:run

Test the Flow
  Open: http://localhost:8080
  Log in as a user with "my-role" to see calendar events.
