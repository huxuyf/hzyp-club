# Backend API Test Cases

## 1. Authentication and Authorization

### 1.1 WeChat Login/Registration (`POST /api/auth/wx-login`)
- **TC1.1.1 (New User Registration):** 
  - Input: Valid `code`, `userInfo` (nickName, avatarUrl).
  - Expected: `200 OK`, returns `token`, `userId`, `isNewUser: true`, `profileCompletionRequired: true`. New user record created in `Users` table, `member` role assigned in `User_Roles`.
- **TC1.1.2 (Existing User Login - Profile Incomplete):**
  - Input: Valid `code` for an existing user whose profile (real_name, id_card_number, phone_number) is incomplete.
  - Expected: `200 OK`, returns `token`, `userId`, `isNewUser: false`, `profileCompletionRequired: true`.
- **TC1.1.3 (Existing User Login - Profile Complete):**
  - Input: Valid `code` for an existing user whose profile is complete.
  - Expected: `200 OK`, returns `token`, `userId`, `isNewUser: false`, `profileCompletionRequired: false`.
- **TC1.1.4 (Missing WeChat Code):**
  - Input: Missing `code`.
  - Expected: `400 Bad Request`, error message about missing code.
- **TC1.1.5 (New User - Missing UserInfo):**
  - Input: Valid `code` for a new user, but `userInfo` is missing or incomplete.
  - Expected: `400 Bad Request`, error message about missing user info.

### 1.2 Authentication Middleware
- **TC1.2.1 (Valid Token):** Access a protected endpoint with a valid `Bearer` token.
  - Expected: `200 OK` (or other success status depending on endpoint).
- **TC1.2.2 (Missing Token):** Access a protected endpoint without `Authorization` header.
  - Expected: `401 Unauthorized`, error message about missing token.
- **TC1.2.3 (Invalid Token Format):** Access a protected endpoint with an invalid token format (e.g., no `Bearer` prefix).
  - Expected: `401 Unauthorized`, error message about invalid token format.
- **TC1.2.4 (Invalid/Expired Token):** Access a protected endpoint with an invalid or expired token.
  - Expected: `401 Unauthorized`, error message about invalid/expired token.

### 1.3 Authorization Middleware (Role-based)
- **TC1.3.1 (Sufficient Permissions - Super Admin):** Super admin accesses an endpoint requiring `super_admin` role.
  - Expected: `200 OK` (or other success status).
- **TC1.3.2 (Sufficient Permissions - Team Admin):** Team admin accesses an endpoint requiring `team_admin` role.
  - Expected: `200 OK` (or other success status).
- **TC1.3.3 (Insufficient Permissions):** Member accesses an endpoint requiring `team_admin` or `super_admin` role.
  - Expected: `403 Forbidden`, error message about insufficient permissions.
- **TC1.3.4 (No Roles Found):** Authenticated user with no roles assigned (edge case, should not happen with default member role) tries to access a role-protected endpoint.
  - Expected: `403 Forbidden`, error message about no roles found.

## 2. User Management (`/api/users/*`)

### 2.1 Get Current User Info (`GET /api/users/me`)
- **TC2.1.1 (Get Own Info - Desensitized):** Authenticated user requests their info without `showFull=true`.
  - Expected: `200 OK`, returns desensitized user data (real_name, id_card_number, phone_number masked), `profileCompletionRequired` status, list of their teams.
- **TC2.1.2 (Get Own Info - Full):** Authenticated user requests their info with `showFull=true`.
  - Expected: `200 OK`, returns full user data (real_name, id_card_number, phone_number in clear), `profileCompletionRequired` status, list of their teams.
- **TC2.1.3 (User Not Found - Edge Case):** Authenticated user (valid token) but no corresponding record in DB (e.g., deleted manually).
  - Expected: `404 Not Found`.

### 2.2 Update Current User Info (`PUT /api/users/me`)
- **TC2.2.1 (Valid Update - Complete Profile):** Authenticated user updates their profile with all required fields (realName, idCardNumber, phoneNumber, gender) and valid teamIds.
  - Expected: `200 OK`, returns desensitized updated user data. Database reflects changes (encrypted for sensitive fields), User_Teams updated.
- **TC2.2.2 (Valid Update - Partial Profile Update):** Authenticated user updates only some optional fields (e.g., changes teams).
  - Expected: `200 OK`, returns desensitized updated user data.
- **TC2.2.3 (Missing Required Fields):** User attempts to update profile missing one or more of (realName, idCardNumber, phoneNumber, gender).
  - Expected: `400 Bad Request`, validation error message.
- **TC2.2.4 (Invalid Team IDs):** User provides non-existent team IDs.
  - Expected: Database operation might partially succeed for user data but fail for team assignments or handle gracefully depending on DB constraints (e.g., foreign key). Test for consistent behavior.

### 2.3 Get Preset Team List (`GET /api/teams`)
- **TC2.3.1 (Get Teams):** Any user (authenticated or anonymous) requests the team list.
  - Expected: `200 OK`, returns a list of all teams with `team_id` and `team_name` from the `Teams` table.
- **TC2.3.2 (No Teams Exist):** If `Teams` table is empty.
  - Expected: `200 OK`, returns an empty list.

## 3. Event Management (`/api/events/*`)

### 3.1 Create Event (`POST /api/events`)
- **TC3.1.1 (Valid Creation - Super Admin):** Super admin creates a valid event.
  - Expected: `200 OK`, returns the created event data. Event record in `Events` table.
- **TC3.1.2 (Valid Creation - Team Admin):** Team admin creates a valid event.
  - Expected: `200 OK`, returns the created event data. `creator_id` is the team admin.
- **TC3.1.3 (Invalid Input - Missing Title):** Missing `title`.
  - Expected: `400 Bad Request`, validation error.
- **TC3.1.4 (Invalid Input - Start Time in Past):** `startTime` is in the past.
  - Expected: `400 Bad Request`, validation error.
- **TC3.1.5 (Invalid Input - End Time before Start Time):** `endTime` is before `startTime`.
  - Expected: `400 Bad Request`, validation error.
- **TC3.1.6 (Invalid Input - Max Participants Negative):** `maxParticipants` is negative.
  - Expected: `400 Bad Request`, validation error.
- **TC3.1.7 (Unauthorized - Member):** Member attempts to create an event.
  - Expected: `403 Forbidden`.

### 3.2 Modify Event (`PUT /api/events/:eventId`)
- **TC3.2.1 (Valid Modification - Creator):** Event creator (team admin) modifies their own event.
  - Expected: `200 OK`, returns updated event data.
- **TC3.2.2 (Valid Modification - Super Admin):** Super admin modifies an event created by another admin.
  - Expected: `200 OK`, returns updated event data.
- **TC3.2.3 (Unauthorized - Different Team Admin):** Team admin attempts to modify an event created by another team admin (not super admin).
  - Expected: `403 Forbidden`.
- **TC3.2.4 (Event Not Found):** Attempt to modify a non-existent `eventId`.
  - Expected: `404 Not Found`.
- **TC3.2.5 (No Updateable Fields):** Request body is empty or contains no fields to update.
  - Expected: `400 Bad Request`.

### 3.3 Delete Event (`DELETE /api/events/:eventId`)
- **TC3.3.1 (Valid Deletion - Creator):** Event creator deletes their own event.
  - Expected: `200 OK`, success message. Event and related registrations (CASCADE) removed from DB.
- **TC3.3.2 (Valid Deletion - Super Admin):** Super admin deletes an event.
  - Expected: `200 OK`, success message.
- **TC3.3.3 (Unauthorized - Different Team Admin):** Team admin attempts to delete an event not created by them.
  - Expected: `403 Forbidden`.
- **TC3.3.4 (Event Not Found):** Attempt to delete a non-existent `eventId`.
  - Expected: `404 Not Found`.

### 3.4 Get Event List (`GET /api/events`)
- **TC3.4.1 (Anonymous User):** Anonymous user requests event list.
  - Expected: `200 OK`, returns only `public` and `published`/`ongoing` events, with `registered_count`.
- **TC3.4.2 (Authenticated Member):** Logged-in member requests event list.
  - Expected: `200 OK`, returns `public` and `registered_users_only` events that are `published`/`ongoing`, with `registered_count`.
- **TC3.4.3 (No Events Match Criteria):** No events meet visibility/status criteria.
  - Expected: `200 OK`, returns empty list.

### 3.5 Get Event Details (`GET /api/events/:eventId`)
- **TC3.5.1 (Public Event - Anonymous):** Anonymous user requests details of a `public` event.
  - Expected: `200 OK`, returns full event details, including `registered_count`.
- **TC3.5.2 (Registered Users Only Event - Authenticated):** Authenticated user requests details of a `registered_users_only` event.
  - Expected: `200 OK`, returns full event details.
- **TC3.5.3 (Registered Users Only Event - Anonymous):** Anonymous user requests details of a `registered_users_only` event.
  - Expected: `401 Unauthorized` (or `403 Forbidden` depending on implementation if redirect to login is desired behavior, API should be clear).
- **TC3.5.4 (Event Not Found):** Request details for a non-existent `eventId`.
  - Expected: `404 Not Found`.
- **TC3.5.5 (Team Members Only Event - To Be Implemented):** Test cases for `team_members_only` visibility once fully implemented.

## 4. Registration Management (`/api/events/:eventId/register`, `/api/registrations/:registrationId`)

### 4.1 Register for Event (`POST /api/events/:eventId/register`)
- **TC4.1.1 (Valid Registration):** Authenticated user registers for an open, available event.
  - Expected: `200 OK`, returns registration details. New record in `Registrations` table.
- **TC4.1.2 (Event Not Found):** Attempt to register for a non-existent `eventId`.
  - Expected: `404 Not Found`.
- **TC4.1.3 (Registration Closed - Before Start):** Registration time has not started.
  - Expected: `400 Bad Request`, error message.
- **TC4.1.4 (Registration Closed - After End):** Registration time has ended.
  - Expected: `400 Bad Request`, error message.
- **TC4.1.5 (Event Full):** Event `max_participants` reached.
  - Expected: `409 Conflict`, error message.
- **TC4.1.6 (Already Registered):** User attempts to register again for the same event.
  - Expected: `409 Conflict`, error message.
- **TC4.1.7 (Unauthenticated User):** Unauthenticated user attempts to register.
  - Expected: `401 Unauthorized`.

### 4.2 Cancel Registration (`DELETE /api/registrations/:registrationId`)
- **TC4.2.1 (Valid Cancellation - Own Registration):** Authenticated user cancels their own registration.
  - Expected: `200 OK`, success message. Registration record removed from DB.
- **TC4.2.2 (Registration Not Found):** Attempt to cancel a non-existent `registrationId`.
  - Expected: `404 Not Found`.
- **TC4.2.3 (Unauthorized - Cancel Others):** User attempts to cancel another user's registration.
  - Expected: `403 Forbidden`.
- **TC4.2.4 (Unauthenticated User):** Unauthenticated user attempts to cancel.
  - Expected: `401 Unauthorized`.

### 4.3 Get Event Registrants (`GET /api/events/:eventId/registrants`)
- **TC4.3.1 (Valid Request - Event Creator):** Event creator requests list of registrants for their event.
  - Expected: `200 OK`, returns list of desensitized user info (wx_nickname, real_name (masked), phone_number (masked), gender, registration_time).
- **TC4.3.2 (Valid Request - Super Admin):** Super admin requests list of registrants for any event.
  - Expected: `200 OK`, returns list of desensitized user info.
- **TC4.3.3 (Unauthorized - Member):** Member attempts to get registrants list.
  - Expected: `403 Forbidden`.
- **TC4.3.4 (Unauthorized - Different Team Admin):** Team admin attempts to get registrants for an event not created by them (and not super admin).
  - Expected: `403 Forbidden`.
- **TC4.3.5 (Event Not Found):** Request registrants for a non-existent `eventId`.
  - Expected: `404 Not Found`.
- **TC4.3.6 (No Registrants):** Event has no registrants.
  - Expected: `200 OK`, returns empty list.

## 5. Admin Functions (`/api/admin/*`)

### 5.1 Assign Team Admin Role (`POST /api/admin/users/:targetUserId/assign-team-admin`)
- **TC5.1.1 (Valid Assignment - Super Admin):** Super admin assigns `team_admin` role to a user for a specific team.
  - Expected: `200 OK`, success message. `User_Roles` table updated with `role_id` for `team_admin` and `assigned_team_id`.
- **TC5.1.2 (Target User Not Found):** `targetUserId` does not exist.
  - Expected: `404 Not Found`.
- **TC5.1.3 (Team Not Found):** `teamId` does not exist.
  - Expected: `404 Not Found`.
- **TC5.1.4 (Unauthorized - Team Admin):** Team admin attempts to use this endpoint.
  - Expected: `403 Forbidden`.
- **TC5.1.5 (Missing targetUserId or teamId):** Request is missing required parameters.
  - Expected: `400 Bad Request`.
- **TC5.1.6 (User Already Team Admin for a Team - Reassignment):** Super admin assigns a user (who is already team_admin for team A) to be team_admin for team B. (Behavior depends on design: overwrite or error. Current code overwrites).
  - Expected: `200 OK`, user is now team_admin for team B. Old assignment removed/updated.

### 5.2 Team Admin Views Users in Their Team (`GET /api/admin/team-users`)
- **TC5.2.1 (Valid Request - Team Admin):** Team admin requests users in their assigned team(s).
  - Expected: `200 OK`, returns list of users belonging to their `assigned_team_id`(s). User info is desensitized for team admin view (nickname, surname, gender, team).
- **TC5.2.2 (Team Admin Not Assigned to Any Team):** A user with `team_admin` role but no `assigned_team_id` (edge case).
  - Expected: `403 Forbidden` (or `200 OK` with empty list, depending on strictness. Code returns 403).
- **TC5.2.3 (Unauthorized - Super Admin):** Super admin attempts to use this specific endpoint (they have other ways to see users).
  - Expected: `403 Forbidden` (as endpoint is specifically for `team_admin` role context).
- **TC5.2.4 (Unauthorized - Member):** Member attempts to use this endpoint.
  - Expected: `403 Forbidden`.
- **TC5.2.5 (No Users in Team):** Assigned team has no users (other than potentially the admin themselves, if they are also a member of that team).
  - Expected: `200 OK`, returns empty list or list containing only admin if applicable.

## 6. Data Security & Integrity

- **TC6.1 (Sensitive Data Encryption):** Verify that `real_name`, `id_card_number`, `phone_number` are stored encrypted in the `Users` table after registration/update.
- **TC6.2 (Sensitive Data Desensitization):** Verify that API responses for user info (e.g., `/api/users/me`, `/api/events/:eventId/registrants`) correctly desensitize sensitive fields unless `showFull=true` is used by an authorized user for their own data.
- **TC6.3 (JWT Security):** Basic check that JWTs are required and validated for protected endpoints. (Actual JWT cryptographic strength is out of scope for functional tests but crucial for security reviews).
- **TC6.4 (Input Validation):** General check across multiple endpoints that invalid inputs (e.g., wrong data types, out-of-range values, excessively long strings) are handled gracefully with `400 Bad Request` and informative error messages.
- **TC6.5 (SQL Injection Prevention):** Conceptual check that parameterized queries (prepared statements) are used for all database interactions. (Requires code review, not black-box testable easily).

## 7. Concurrency and Edge Cases (Conceptual)

- **TC7.1 (Concurrent Registrations for Limited Event):** Simulate multiple users trying to register for an event with limited spots simultaneously, ensuring `max_participants` is not exceeded.
- **TC7.2 (Update Conflicts):** Simulate concurrent updates to the same event or user profile to check for race conditions (depends on DB transaction isolation levels and application logic).

This list provides a good starting point. Specific implementation details might necessitate additional test cases.
