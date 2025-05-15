-- Users Table
CREATE TABLE IF NOT EXISTS Users (
    user_id TEXT PRIMARY KEY,
    wx_openid TEXT UNIQUE,
    wx_avatar_url TEXT,
    wx_nickname TEXT,
    real_name TEXT, -- Encrypted
    id_card_number TEXT, -- Encrypted
    phone_number TEXT, -- Encrypted
    gender TEXT,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT DEFAULT CURRENT_TIMESTAMP
);

-- Teams Table
CREATE TABLE IF NOT EXISTS Teams (
    team_id TEXT PRIMARY KEY,
    team_name TEXT UNIQUE,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

-- User_Teams Junction Table
CREATE TABLE IF NOT EXISTS User_Teams (
    user_id TEXT,
    team_id TEXT,
    PRIMARY KEY (user_id, team_id),
    FOREIGN KEY (user_id) REFERENCES Users(user_id) ON DELETE CASCADE,
    FOREIGN KEY (team_id) REFERENCES Teams(team_id) ON DELETE CASCADE
);

-- Events Table
CREATE TABLE IF NOT EXISTS Events (
    event_id TEXT PRIMARY KEY,
    title TEXT NOT NULL CHECK(length(title) <= 60),
    cover_image_url TEXT,
    start_time TEXT NOT NULL,
    end_time TEXT NOT NULL,
    registration_start_time TEXT NOT NULL,
    registration_end_time TEXT NOT NULL,
    location_text TEXT,
    location_coordinates TEXT, -- "lng,lat"
    max_participants INTEGER, -- NULL for unlimited
    content TEXT, -- Rich text
    visibility TEXT DEFAULT 'public' CHECK(visibility IN ('public', 'registered_users_only', 'team_members_only')),
    creator_id TEXT, -- User_id of the creator
    is_paid_event INTEGER DEFAULT 0, -- 0 for false, 1 for true
    status TEXT DEFAULT 'draft' CHECK(status IN ('draft', 'published', 'ongoing', 'ended', 'cancelled')),
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (creator_id) REFERENCES Users(user_id) ON DELETE SET NULL
);

-- Registrations Table
CREATE TABLE IF NOT EXISTS Registrations (
    registration_id TEXT PRIMARY KEY,
    event_id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    registration_time TEXT DEFAULT CURRENT_TIMESTAMP,
    status TEXT DEFAULT 'confirmed' CHECK(status IN ('confirmed', 'cancelled', 'waitlisted')),
    UNIQUE (event_id, user_id),
    FOREIGN KEY (event_id) REFERENCES Events(event_id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES Users(user_id) ON DELETE CASCADE
);

-- Roles Table
CREATE TABLE IF NOT EXISTS Roles (
    role_id TEXT PRIMARY KEY,
    role_name TEXT UNIQUE CHECK(role_name IN ('super_admin', 'team_admin', 'member'))
);

-- User_Roles Junction Table
CREATE TABLE IF NOT EXISTS User_Roles (
    user_id TEXT,
    role_id TEXT,
    assigned_team_id TEXT, -- Nullable, FK to Teams.team_id, only for team_admin
    PRIMARY KEY (user_id, role_id),
    FOREIGN KEY (user_id) REFERENCES Users(user_id) ON DELETE CASCADE,
    FOREIGN KEY (role_id) REFERENCES Roles(role_id) ON DELETE CASCADE,
    FOREIGN KEY (assigned_team_id) REFERENCES Teams(team_id) ON DELETE SET NULL
);

-- Pre-populate Teams table
INSERT INTO Teams (team_id, team_name) VALUES
    (REPLACE(HEX(RANDOMBLOB(16)), '-', ''), '仁皇山分舵'),
    (REPLACE(HEX(RANDOMBLOB(16)), '-', ''), '城区分舵'),
    (REPLACE(HEX(RANDOMBLOB(16)), '-', ''), '西南分舵'),
    (REPLACE(HEX(RANDOMBLOB(16)), '-', ''), '城南分舵'),
    (REPLACE(HEX(RANDOMBLOB(16)), '-', ''), '西山漾分舵'),
    (REPLACE(HEX(RANDOMBLOB(16)), '-', ''), '南浔分舵'),
    (REPLACE(HEX(RANDOMBLOB(16)), '-', ''), '和平分舵'),
    (REPLACE(HEX(RANDOMBLOB(16)), '-', ''), '练市分舵'),
    (REPLACE(HEX(RANDOMBLOB(16)), '-', ''), '双林分舵')
ON CONFLICT(team_name) DO NOTHING;

-- Pre-populate Roles table
INSERT INTO Roles (role_id, role_name) VALUES
    (REPLACE(HEX(RANDOMBLOB(16)), '-', ''), 'super_admin'),
    (REPLACE(HEX(RANDOMBLOB(16)), '-', ''), 'team_admin'),
    (REPLACE(HEX(RANDOMBLOB(16)), '-', ''), 'member')
ON CONFLICT(role_name) DO NOTHING;


