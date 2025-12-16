# Keycloak OIDC Exercise

## Goal
Build two Java applications:
1. frontend-app: This logs users in via Keycloak OIDC and shows calendar the data.
2. calendar: An REST service that is protected by Keycloak access tokens.

## Acceptance checklist
1. frontend-app redirects to Keycloak for login and receives tokens.
2. frontend-app authorizes only users with role my-role.
3. frontend-app calls calendar with an access token.
4. calendar returns 401 for missing or invalid tokens.
5. calendar returns 200 for valid tokens.
6. frontend-app displays the calendar response.

## Notes
Setup and run steps will be added in later commits.
