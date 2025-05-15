import { Router, error, json } from 'itty-router';

// Helper function to generate a simple JWT (not for production without proper libraries)
async function generateJWT(payload, secret) {
  const header = {
    alg: 'HS256',
    typ: 'JWT'
  };
  const encodedHeader = btoa(JSON.stringify(header)).replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
  const encodedPayload = btoa(JSON.stringify(payload)).replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
  const signatureInput = `${encodedHeader}.${encodedPayload}`;
  
  const key = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );
  const signature = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(signatureInput));
  const encodedSignature = btoa(String.fromCharCode(...new Uint8Array(signature))).replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
  
  return `${encodedHeader}.${encodedPayload}.${encodedSignature}`;
}

// Helper function to verify JWT (basic placeholder)
async function verifyJWT(token, secret) {
  try {
    const [encodedHeader, encodedPayload, signature] = token.split('.');
    if (!encodedHeader || !encodedPayload || !signature) {
      return null;
    }
    const signatureInput = `${encodedHeader}.${encodedPayload}`;
    const key = await crypto.subtle.importKey(
      'raw',
      new TextEncoder().encode(secret),
      { name: 'HMAC', hash: 'SHA-256' },
      false,
      ['verify']
    );
    const expectedSignatureData = Uint8Array.from(atob(signature.replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0));
    const isValid = await crypto.subtle.verify('HMAC', key, expectedSignatureData, new TextEncoder().encode(signatureInput));
    
    if (!isValid) {
      return null;
    }
    return JSON.parse(atob(encodedPayload.replace(/-/g, '+').replace(/_/g, '/')));
  } catch (e) {
    console.error('JWT verification error:', e);
    return null;
  }
}

// Helper function for UUID generation
function uuidv4() {
  return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function(c) {
    var r = Math.random() * 16 | 0, v = c == 'x' ? r : (r & 0x3 | 0x8);
    return v.toString(16);
  });
}

// Encryption function (placeholder - implement actual AES-GCM)
async function encryptData(data, keyString) {
  if (data === null || typeof data === 'undefined') return null;
  return `encrypted_${String(data)}`; // Placeholder
}

// Decryption function (placeholder - implement actual AES-GCM)
async function decryptData(encryptedData, keyString) {
  if (encryptedData === null || typeof encryptedData === 'undefined' || !String(encryptedData).startsWith('encrypted_')) return encryptedData;
  return String(encryptedData).substring(10); // Placeholder
}


// Desensitization function
function desensitizeUser(user, showFull = false) {
  if (!user) return null;
  const desensitized = { ...user };
  const realNameRaw = user.real_name;
  const idCardRaw = user.id_card_number;
  const phoneRaw = user.phone_number;

  if (showFull) {
    desensitized.real_name = decryptData(realNameRaw, null);
    desensitized.id_card_number = decryptData(idCardRaw, null);
    desensitized.phone_number = decryptData(phoneRaw, null);
  } else {
    if (realNameRaw) {
      const nameParts = String(decryptData(realNameRaw, null));
      if (nameParts.length > 1) {
          desensitized.real_name = nameParts[0] + '*'.repeat(nameParts.length - 1);
      } else {
          desensitized.real_name = nameParts;
      }
    }
    if (idCardRaw) {
      const id = String(decryptData(idCardRaw, null));
      if (id.length > 10) {
          desensitized.id_card_number = id.substring(0, 6) + '*'.repeat(id.length - 10) + id.substring(id.length - 4);
      } else {
          desensitized.id_card_number = id;
      }
    }
    if (phoneRaw) {
      const phone = String(decryptData(phoneRaw, null));
      if (phone.length === 11) {
          desensitized.phone_number = phone.substring(0, 3) + '****' + phone.substring(7);
      } else {
          desensitized.phone_number = phone;
      }
    }
  }
  // For team admin view, only show nickname, surname (from real_name), gender, team
  if (user.forTeamAdminView) {
    const nameForTeamAdmin = decryptData(realNameRaw, null);
    desensitized.surname = nameForTeamAdmin ? nameForTeamAdmin[0] : '';
    delete desensitized.real_name;
    delete desensitized.id_card_number;
    delete desensitized.phone_number;
    delete desensitized.wx_avatar_url; // As per doc
    delete desensitized.created_at;
    delete desensitized.updated_at;
    delete desensitized.wx_openid;
  }

  return desensitized;
}


const router = Router();

// Auth Middleware
const authenticate = async (request, env) => {
  const authHeader = request.headers.get('Authorization');
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return error(401, { success: false, error: { code: 'UNAUTHORIZED', message: 'Missing or invalid token.' } });
  }
  const token = authHeader.substring(7);
  const JWT_SECRET = env.JWT_SECRET || 'your-super-secret-and-long-jwt-key-for-dev-only-replace-in-prod';
  const payload = await verifyJWT(token, JWT_SECRET);
  if (!payload || !payload.userId) {
    return error(401, { success: false, error: { code: 'UNAUTHORIZED', message: 'Invalid or expired token.' } });
  }
  request.user = { userId: payload.userId }; 
};

// Authorization Middleware (Role-based)
const authorize = (roles) => async (request, env) => {
  if (!request.user || !request.user.userId) {
    return error(401, { success: false, error: { code: 'UNAUTHORIZED', message: 'Authentication required.' } });
  }
  const userRolesQuery = await env.DB.prepare(
    'SELECT R.role_name, UR.assigned_team_id FROM Roles R JOIN User_Roles UR ON R.role_id = UR.role_id WHERE UR.user_id = ?'
  ).bind(request.user.userId).all();

  if (!userRolesQuery || !userRolesQuery.results || userRolesQuery.results.length === 0) {
    return error(403, { success: false, error: { code: 'FORBIDDEN', message: 'No roles found for user.' } });
  }
  const userRoleDetails = userRolesQuery.results.map(r => ({ name: r.role_name, assigned_team_id: r.assigned_team_id }));
  const hasPermission = roles.some(role => userRoleDetails.some(urd => urd.name === role));

  if (!hasPermission) {
    return error(403, { success: false, error: { code: 'FORBIDDEN', message: 'Insufficient permissions.' } });
  }
  request.user.roles = userRoleDetails; 
};


// POST /api/auth/wx-login (WeChat Quick Register/Login)
router.post('/api/auth/wx-login', async (request, env) => {
  try {
    const body = await request.json();
    const { code, userInfo } = body;
    if (!code) {
      return error(400, { success: false, error: { code: 'INVALID_INPUT', message: 'Missing WeChat auth code.' } });
    }
    const JWT_SECRET = env.JWT_SECRET || 'your-super-secret-and-long-jwt-key-for-dev-only-replace-in-prod';
    const wx_openid = `simulated_openid_for_${code}`;
    let userId;
    let isNewUser = false;
    let profileCompletionRequired = true;
    let userRecord = await env.DB.prepare('SELECT user_id, real_name, id_card_number, phone_number FROM Users WHERE wx_openid = ?').bind(wx_openid).first();
    if (userRecord) {
      userId = userRecord.user_id;
      if (userRecord.real_name && userRecord.id_card_number && userRecord.phone_number) {
         profileCompletionRequired = false;
      }
    } else {
      if (!userInfo || !userInfo.nickName || !userInfo.avatarUrl) {
        return error(400, { success: false, error: { code: 'USER_INFO_REQUIRED', message: 'User info (nickName, avatarUrl) required for new user.' } });
      }
      userId = uuidv4();
      isNewUser = true;
      profileCompletionRequired = true;
      await env.DB.prepare(
        'INSERT INTO Users (user_id, wx_openid, wx_nickname, wx_avatar_url, created_at, updated_at) VALUES (?, ?, ?, ?, datetime(\'now\'), datetime(\'now\'))'
      ).bind(userId, wx_openid, userInfo.nickName, userInfo.avatarUrl).run();
      const memberRole = await env.DB.prepare('SELECT role_id FROM Roles WHERE role_name = ?').bind('member').first();
      if (memberRole) {
        await env.DB.prepare('INSERT INTO User_Roles (user_id, role_id) VALUES (?, ?)').bind(userId, memberRole.role_id).run();
      }
    }
    const token = await generateJWT({ userId: userId, openid: wx_openid }, JWT_SECRET);
    return json({
      success: true,
      data: {
        token,
        userId,
        isNewUser,
        profileCompletionRequired
      }
    });
  } catch (e) {
    console.error('wx-login error:', e.stack);
    return error(500, { success: false, error: { code: 'INTERNAL_SERVER_ERROR', message: e.message } });
  }
});

// GET /api/teams - Get preset team list
router.get('/api/teams', async (request, env) => {
  try {
    const { results } = await env.DB.prepare('SELECT team_id, team_name FROM Teams').all();
    return json({ success: true, data: results || [] });
  } catch (e) {
    console.error('get teams error:', e.stack);
    return error(500, { success: false, error: { code: 'INTERNAL_SERVER_ERROR', message: e.message } });
  }
});

// GET /api/users/me - Get current user information
router.get('/api/users/me', authenticate, async (request, env) => {
  try {
    const userId = request.user.userId;
    const showFullParam = new URL(request.url).searchParams.get('showFull');
    const showFull = showFullParam === 'true';
    const user = await env.DB.prepare(
      'SELECT user_id, wx_openid, wx_avatar_url, wx_nickname, real_name, id_card_number, phone_number, gender, created_at, updated_at FROM Users WHERE user_id = ?'
    ).bind(userId).first();
    if (!user) {
      return error(404, { success: false, error: { code: 'USER_NOT_FOUND', message: 'User not found.' } });
    }
    const userTeams = await env.DB.prepare(
      'SELECT T.team_id, T.team_name FROM Teams T JOIN User_Teams UT ON T.team_id = UT.team_id WHERE UT.user_id = ?'
    ).bind(userId).all();
    const responseUser = desensitizeUser(user, showFull);
    responseUser.teams = userTeams.results || [];
    responseUser.profileCompletionRequired = !(user.real_name && user.id_card_number && user.phone_number);
    delete responseUser.wx_openid;
    if (!showFull) {
        // When not showing full, the desensitizeUser function already replaced these with desensitized versions
    } 
    return json({ success: true, data: responseUser });
  } catch (e) {
    console.error('get user me error:', e.stack);
    return error(500, { success: false, error: { code: 'INTERNAL_SERVER_ERROR', message: e.message } });
  }
});


// PUT /api/users/me - Update current user information
router.put('/api/users/me', authenticate, async (request, env) => {
  try {
    const userId = request.user.userId;
    const body = await request.json();
    const { realName, idCardNumber, phoneNumber, gender, teamIds } = body;
    const ENCRYPTION_KEY = env.ENCRYPTION_KEY_SECRET || 'your-super-secret-encryption-key-for-dev-only-replace-in-prod';
    if (!realName || !idCardNumber || !phoneNumber || !gender) {
      return error(400, { success: false, error: { code: 'VALIDATION_ERROR', message: 'Real name, ID card number, phone number, and gender are required.' } });
    }
    const encryptedRealName = await encryptData(realName, ENCRYPTION_KEY);
    const encryptedIdCardNumber = await encryptData(idCardNumber, ENCRYPTION_KEY);
    const encryptedPhoneNumber = await encryptData(phoneNumber, ENCRYPTION_KEY);
    await env.DB.prepare(
      'UPDATE Users SET real_name = ?, id_card_number = ?, phone_number = ?, gender = ?, updated_at = datetime(\'now\') WHERE user_id = ?'
    ).bind(encryptedRealName, encryptedIdCardNumber, encryptedPhoneNumber, gender, userId).run();
    await env.DB.prepare('DELETE FROM User_Teams WHERE user_id = ?').bind(userId).run();
    if (teamIds && Array.isArray(teamIds) && teamIds.length > 0) {
      const insertTeamStmt = env.DB.prepare('INSERT INTO User_Teams (user_id, team_id) VALUES (?, ?)');
      const batch = teamIds.map(teamId => insertTeamStmt.bind(userId, teamId));
      await env.DB.batch(batch);
    }
    const updatedUserRaw = await env.DB.prepare('SELECT user_id, wx_nickname, wx_avatar_url, real_name, id_card_number, phone_number, gender FROM Users WHERE user_id = ?').bind(userId).first();
    const updatedUserTeams = await env.DB.prepare('SELECT T.team_id, T.team_name FROM Teams T JOIN User_Teams UT ON T.team_id = UT.team_id WHERE UT.user_id = ?').bind(userId).all();
    const responseUser = desensitizeUser(updatedUserRaw, false);
    responseUser.teams = updatedUserTeams.results || [];
    responseUser.profileCompletionRequired = !(updatedUserRaw.real_name && updatedUserRaw.id_card_number && updatedUserRaw.phone_number);
    delete responseUser.wx_openid;
    return json({ success: true, data: responseUser });
  } catch (e) {
    console.error('update user error:', e.stack);
    return error(500, { success: false, error: { code: 'INTERNAL_SERVER_ERROR', message: e.message } });
  }
});

// POST /api/events - Create new event (Admin only)
router.post('/api/events', authenticate, authorize(['super_admin', 'team_admin']), async (request, env) => {
  try {
    const creatorId = request.user.userId;
    const body = await request.json(); 
    const {
      title,
      startTime, endTime,
      registrationStartTime, registrationEndTime,
      locationText, locationCoordinates,
      maxParticipants,
      content,
      visibility = 'public',
      isPaidEvent = false 
    } = body;

    if (!title || title.length > 60) {
      return error(400, { success: false, error: { code: 'VALIDATION_ERROR', message: 'Title is required and max 60 chars.' } });
    }
    if (!startTime || !endTime || !registrationStartTime || !registrationEndTime) {
      return error(400, { success: false, error: { code: 'VALIDATION_ERROR', message: 'All time fields are required.' } });
    }
    const now = new Date();
    const eventStartTime = new Date(startTime);
    if (eventStartTime <= now) {
      return error(400, { success: false, error: { code: 'VALIDATION_ERROR', message: 'Event start time must be in the future.' } });
    }
    if (new Date(endTime) < eventStartTime) {
      return error(400, { success: false, error: { code: 'VALIDATION_ERROR', message: 'Event end time must be after start time.' } });
    }
    if (!locationText) {
      return error(400, { success: false, error: { code: 'VALIDATION_ERROR', message: 'Location text is required.' } });
    }
    if (!content) {
      return error(400, { success: false, error: { code: 'VALIDATION_ERROR', message: 'Event content is required.' } });
    }
    if (maxParticipants !== null && (typeof maxParticipants !== 'number' || maxParticipants < 0)) {
        return error(400, { success: false, error: { code: 'VALIDATION_ERROR', message: 'Max participants must be a non-negative number or null.' }});
    }

    const coverImageUrl = 'https://example.com/placeholder_cover.jpg'; 
    const eventId = uuidv4();
    const insertEventStmt = env.DB.prepare(
      'INSERT INTO Events (event_id, title, cover_image_url, start_time, end_time, registration_start_time, registration_end_time, location_text, location_coordinates, max_participants, content, visibility, creator_id, is_paid_event, status, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime(\'now\'), datetime(\'now\'))'
    );
    await insertEventStmt.bind(
      eventId, title, coverImageUrl, startTime, endTime, 
      registrationStartTime, registrationEndTime, locationText, locationCoordinates,
      maxParticipants === null ? null : Number(maxParticipants),
      content, visibility, creatorId, isPaidEvent ? 1 : 0, 'published'
    ).run();

    const newEvent = await env.DB.prepare('SELECT * FROM Events WHERE event_id = ?').bind(eventId).first();
    return json({ success: true, data: newEvent });

  } catch (e) {
    console.error('create event error:', e.stack);
    if (e.message && e.message.includes('D1_ERROR')) { 
        return error(500, { success: false, error: { code: 'DATABASE_ERROR', message: 'Failed to create event in database.' } });
    }
    return error(500, { success: false, error: { code: 'INTERNAL_SERVER_ERROR', message: e.message } });
  }
});

// PUT /api/events/:eventId - Modify existing event (Admin only)
router.put('/api/events/:eventId', authenticate, authorize(['super_admin', 'team_admin']), async (request, env) => {
  try {
    const { eventId } = request.params;
    const userId = request.user.userId;

    const existingEvent = await env.DB.prepare('SELECT creator_id FROM Events WHERE event_id = ?').bind(eventId).first();
    if (!existingEvent) {
      return error(404, { success: false, error: { code: 'NOT_FOUND', message: 'Event not found.' } });
    }

    const isSuperAdmin = request.user.roles.some(role => role.name === 'super_admin');
    if (existingEvent.creator_id !== userId && !isSuperAdmin) {
        return error(403, { success: false, error: { code: 'FORBIDDEN', message: 'You do not have permission to modify this event.' } });
    }

    const body = await request.json();
    const { 
        title, startTime, endTime, registrationStartTime, registrationEndTime, 
        locationText, locationCoordinates, maxParticipants, content, visibility 
    } = body;

    const updates = [];
    const bindings = [];
    if (title !== undefined) { updates.push('title = ?'); bindings.push(title); }
    if (startTime !== undefined) { updates.push('start_time = ?'); bindings.push(startTime); }
    if (endTime !== undefined) { updates.push('end_time = ?'); bindings.push(endTime); }
    if (registrationStartTime !== undefined) { updates.push('registration_start_time = ?'); bindings.push(registrationStartTime); }
    if (registrationEndTime !== undefined) { updates.push('registration_end_time = ?'); bindings.push(registrationEndTime); }
    if (locationText !== undefined) { updates.push('location_text = ?'); bindings.push(locationText); }
    if (locationCoordinates !== undefined) { updates.push('location_coordinates = ?'); bindings.push(locationCoordinates); }
    if (maxParticipants !== undefined) { updates.push('max_participants = ?'); bindings.push(maxParticipants === null ? null : Number(maxParticipants)); }
    if (content !== undefined) { updates.push('content = ?'); bindings.push(content); }
    if (visibility !== undefined) { updates.push('visibility = ?'); bindings.push(visibility); }

    if (updates.length === 0) {
      return error(400, { success: false, error: { code: 'VALIDATION_ERROR', message: 'No updateable fields provided.' } });
    }

    updates.push('updated_at = datetime(\'now\')');
    bindings.push(eventId);

    const updateQuery = `UPDATE Events SET ${updates.join(', ')} WHERE event_id = ?`;
    await env.DB.prepare(updateQuery).bind(...bindings).run();

    const updatedEvent = await env.DB.prepare('SELECT * FROM Events WHERE event_id = ?').bind(eventId).first();
    return json({ success: true, data: updatedEvent });

  } catch (e) {
    console.error('update event error:', e.stack);
    return error(500, { success: false, error: { code: 'INTERNAL_SERVER_ERROR', message: e.message } });
  }
});

// DELETE /api/events/:eventId - Delete event (Admin only)
router.delete('/api/events/:eventId', authenticate, authorize(['super_admin', 'team_admin']), async (request, env) => {
  try {
    const { eventId } = request.params;
    const userId = request.user.userId;

    const existingEvent = await env.DB.prepare('SELECT creator_id FROM Events WHERE event_id = ?').bind(eventId).first();
    if (!existingEvent) {
      return error(404, { success: false, error: { code: 'NOT_FOUND', message: 'Event not found.' } });
    }

    const isSuperAdmin = request.user.roles.some(role => role.name === 'super_admin');
    if (existingEvent.creator_id !== userId && !isSuperAdmin) {
      return error(403, { success: false, error: { code: 'FORBIDDEN', message: 'You do not have permission to delete this event.' } });
    }

    await env.DB.prepare('DELETE FROM Events WHERE event_id = ?').bind(eventId).run();
    return json({ success: true, message: 'Event deleted successfully.' });

  } catch (e) {
    console.error('delete event error:', e.stack);
    return error(500, { success: false, error: { code: 'INTERNAL_SERVER_ERROR', message: e.message } });
  }
});

// GET /api/events - Get list of events (handles visibility)
router.get('/api/events', async (request, env) => {
  try {
    const url = new URL(request.url);
    let query = 'SELECT event_id, title, cover_image_url, start_time, end_time, location_text, max_participants, visibility, status, (SELECT COUNT(*) FROM Registrations WHERE event_id = E.event_id) as registered_count FROM Events E';
    const bindings = [];
    const conditions = [];
    
    let isAuthenticatedUser = false;
    try {
        const authHeader = request.headers.get('Authorization');
        if (authHeader && authHeader.startsWith('Bearer ')) {
            const token = authHeader.substring(7);
            const JWT_SECRET = env.JWT_SECRET || 'your-super-secret-and-long-jwt-key-for-dev-only-replace-in-prod';
            const payload = await verifyJWT(token, JWT_SECRET);
            if (payload && payload.userId) {
                isAuthenticatedUser = true;
            }
        }
    } catch (authError) { /* ignore, treat as anonymous */ }

    if (isAuthenticatedUser) {
        conditions.push('(visibility = ? OR visibility = ?)');
        bindings.push('public', 'registered_users_only');
    } else {
        conditions.push('visibility = ?');
        bindings.push('public');
    }
    
    conditions.push('(status = ? OR status = ?)');
    bindings.push('published', 'ongoing');

    if (conditions.length > 0) {
      query += ' WHERE ' + conditions.join(' AND ');
    }
    query += ' ORDER BY start_time ASC';

    const { results } = await env.DB.prepare(query).bind(...bindings).all();
    return json({ success: true, data: results || [] });

  } catch (e) {
    console.error('get events error:', e.stack);
    return error(500, { success: false, error: { code: 'INTERNAL_SERVER_ERROR', message: e.message } });
  }
});

// GET /api/events/:eventId - Get event details
router.get('/api/events/:eventId', async (request, env) => {
  try {
    const { eventId } = request.params;
    let event = await env.DB.prepare(
        'SELECT *, (SELECT COUNT(*) FROM Registrations WHERE event_id = E.event_id) as registered_count FROM Events E WHERE event_id = ?'
    ).bind(eventId).first();

    if (!event) {
      return error(404, { success: false, error: { code: 'NOT_FOUND', message: 'Event not found.' } });
    }

    let isAuthenticatedUser = false;
    try {
        const authHeader = request.headers.get('Authorization');
        if (authHeader && authHeader.startsWith('Bearer ')) {
            const token = authHeader.substring(7);
            const JWT_SECRET = env.JWT_SECRET || 'your-super-secret-and-long-jwt-key-for-dev-only-replace-in-prod';
            const payload = await verifyJWT(token, JWT_SECRET);
            if (payload && payload.userId) {
                isAuthenticatedUser = true;
            }
        }
    } catch (authError) { /* ignore */ }

    if (event.visibility === 'registered_users_only' && !isAuthenticatedUser) {
        return error(401, { success: false, error: { code: 'UNAUTHORIZED', message: 'You must be logged in to view this event.' } });
    }

    return json({ success: true, data: event });
  } catch (e) {
    console.error('get event detail error:', e.stack);
    return error(500, { success: false, error: { code: 'INTERNAL_SERVER_ERROR', message: e.message } });
  }
});

// POST /api/events/:eventId/register - Register for an event
router.post('/api/events/:eventId/register', authenticate, async (request, env) => {
  try {
    const { eventId } = request.params;
    const userId = request.user.userId;

    const event = await env.DB.prepare('SELECT event_id, max_participants, registration_start_time, registration_end_time, status FROM Events WHERE event_id = ?').bind(eventId).first();
    if (!event) {
      return error(404, { success: false, error: { code: 'EVENT_NOT_FOUND', message: 'Event not found.' } });
    }

    const now = new Date();
    if (now < new Date(event.registration_start_time) || now > new Date(event.registration_end_time)) {
      return error(400, { success: false, error: { code: 'REGISTRATION_CLOSED', message: 'Registration is not currently open for this event.' } });
    }
    if (event.status !== 'published' && event.status !== 'ongoing') {
        return error(400, { success: false, error: { code: 'EVENT_NOT_AVAILABLE', message: 'Event is not available for registration.' } });
    }

    const existingRegistration = await env.DB.prepare('SELECT registration_id FROM Registrations WHERE event_id = ? AND user_id = ?').bind(eventId, userId).first();
    if (existingRegistration) {
      return error(409, { success: false, error: { code: 'ALREADY_REGISTERED', message: 'You are already registered for this event.' } });
    }

    if (event.max_participants !== null) {
      const registeredCountResult = await env.DB.prepare('SELECT COUNT(*) as count FROM Registrations WHERE event_id = ?').bind(eventId).first();
      const registeredCount = registeredCountResult ? registeredCountResult.count : 0;
      if (registeredCount >= event.max_participants) {
        return error(409, { success: false, error: { code: 'EVENT_FULL', message: 'This event is full.' } });
      }
    }

    const registrationId = uuidv4();
    await env.DB.prepare(
      'INSERT INTO Registrations (registration_id, event_id, user_id, registration_time, status) VALUES (?, ?, ?, datetime(\'now\'), ?)'
    ).bind(registrationId, eventId, userId, 'confirmed').run();

    return json({ success: true, data: { registrationId, eventId, userId, status: 'confirmed' } });

  } catch (e) {
    console.error('register event error:', e.stack);
    if (e.message && e.message.includes('UNIQUE constraint failed: Registrations.event_id, Registrations.user_id')) {
        return error(409, { success: false, error: { code: 'ALREADY_REGISTERED', message: 'You are already registered for this event (concurrent request?).' } });
    }
    return error(500, { success: false, error: { code: 'INTERNAL_SERVER_ERROR', message: e.message } });
  }
});

// DELETE /api/registrations/:registrationId - Cancel a registration (user cancels their own)
router.delete('/api/registrations/:registrationId', authenticate, async (request, env) => {
    try {
        const { registrationId } = request.params;
        const userId = request.user.userId;

        const registration = await env.DB.prepare('SELECT user_id, event_id FROM Registrations WHERE registration_id = ?').bind(registrationId).first();

        if (!registration) {
            return error(404, { success: false, error: { code: 'REGISTRATION_NOT_FOUND', message: 'Registration not found.' } });
        }

        if (registration.user_id !== userId) {
            return error(403, { success: false, error: { code: 'FORBIDDEN', message: 'You can only cancel your own registration.' } });
        }
        
        await env.DB.prepare('DELETE FROM Registrations WHERE registration_id = ? AND user_id = ?')
            .bind(registrationId, userId)
            .run();

        return json({ success: true, message: 'Registration cancelled successfully.' });

    } catch (e) {
        console.error('cancel registration error:', e.stack);
        return error(500, { success: false, error: { code: 'INTERNAL_SERVER_ERROR', message: e.message } });
    }
});

// GET /api/events/:eventId/registrants - Get list of registrants for an event (Admin/Creator only)
router.get('/api/events/:eventId/registrants', authenticate, authorize(['super_admin', 'team_admin']), async (request, env) => {
  try {
    const { eventId } = request.params;
    const userId = request.user.userId;

    const event = await env.DB.prepare('SELECT creator_id FROM Events WHERE event_id = ?').bind(eventId).first();
    if (!event) {
      return error(404, { success: false, error: { code: 'EVENT_NOT_FOUND', message: 'Event not found.' } });
    }

    const isSuperAdmin = request.user.roles.some(role => role.name === 'super_admin');
    if (event.creator_id !== userId && !isSuperAdmin) {
      return error(403, { success: false, error: { code: 'FORBIDDEN', message: 'You do not have permission to view registrants for this event.' } });
    }

    const registrantsQuery = await env.DB.prepare(
      'SELECT U.user_id, U.wx_nickname, U.real_name, U.phone_number, U.gender, R.registration_time '
      + 'FROM Users U JOIN Registrations R ON U.user_id = R.user_id '
      + 'WHERE R.event_id = ? ORDER BY R.registration_time ASC'
    ).bind(eventId).all();

    const registrants = registrantsQuery.results ? registrantsQuery.results.map(u => desensitizeUser(u, false)) : [];

    return json({ success: true, data: registrants });

  } catch (e) {
    console.error('get event registrants error:', e.stack);
    return error(500, { success: false, error: { code: 'INTERNAL_SERVER_ERROR', message: e.message } });
  }
});

// POST /api/admin/users/:targetUserId/assign-team-admin - Super admin assigns team admin role
router.post('/api/admin/users/:targetUserId/assign-team-admin', authenticate, authorize(['super_admin']), async (request, env) => {
  try {
    const { targetUserId } = request.params;
    const { teamId } = await request.json();

    if (!targetUserId || !teamId) {
      return error(400, { success: false, error: { code: 'VALIDATION_ERROR', message: 'Target user ID and team ID are required.' } });
    }

    const targetUser = await env.DB.prepare('SELECT user_id FROM Users WHERE user_id = ?').bind(targetUserId).first();
    if (!targetUser) {
      return error(404, { success: false, error: { code: 'USER_NOT_FOUND', message: 'Target user not found.' } });
    }

    const team = await env.DB.prepare('SELECT team_id FROM Teams WHERE team_id = ?').bind(teamId).first();
    if (!team) {
      return error(404, { success: false, error: { code: 'TEAM_NOT_FOUND', message: 'Team not found.' } });
    }

    const teamAdminRole = await env.DB.prepare('SELECT role_id FROM Roles WHERE role_name = ?').bind('team_admin').first();
    if (!teamAdminRole) {
      return error(500, { success: false, error: { code: 'ROLE_NOT_FOUND', message: 'Team admin role not configured.' } });
    }

    // Remove existing team_admin role for this user if any, to prevent multiple team_admin roles for different teams (if that's the design)
    // Or, if a user can be admin of multiple teams, this logic would change.
    // Current schema User_Roles has (user_id, role_id) as PK, so one user can have one instance of team_admin role.
    // The assigned_team_id is on that User_Roles row.
    // To support multiple team admin roles, User_Roles PK would need to include assigned_team_id or be just an auto-increment ID.
    // For now, assuming one user can be team_admin of AT MOST ONE team via this specific role assignment.
    // If they are already team_admin for another team, this will effectively change their assignment.
    await env.DB.prepare('DELETE FROM User_Roles WHERE user_id = ? AND role_id = ?')
      .bind(targetUserId, teamAdminRole.role_id)
      .run();

    await env.DB.prepare('INSERT INTO User_Roles (user_id, role_id, assigned_team_id) VALUES (?, ?, ?)')
      .bind(targetUserId, teamAdminRole.role_id, teamId)
      .run();

    return json({ success: true, message: `User ${targetUserId} assigned as team admin for team ${teamId}.` });

  } catch (e) {
    console.error('assign team admin error:', e.stack);
    if (e.message && e.message.includes('UNIQUE constraint failed')) {
        return error(409, { success: false, error: { code: 'CONFLICT', message: 'User is already assigned this role for a team or another conflict occurred.' } });
    }
    return error(500, { success: false, error: { code: 'INTERNAL_SERVER_ERROR', message: e.message } });
  }
});

// GET /api/admin/team-users - Team admin views users in their assigned team(s)
router.get('/api/admin/team-users', authenticate, authorize(['team_admin']), async (request, env) => {
  try {
    const teamAdminUserId = request.user.userId;
    const adminRoles = request.user.roles.filter(role => role.name === 'team_admin' && role.assigned_team_id);
    
    if (!adminRoles || adminRoles.length === 0) {
        return error(403, { success: false, error: { code: 'FORBIDDEN', message: 'You are not assigned to manage any team.' }});
    }

    // For simplicity, if a team_admin is assigned to multiple teams (schema allows via multiple User_Roles entries if PK is different),
    // this will fetch users from all their assigned teams.
    // The requirement 
