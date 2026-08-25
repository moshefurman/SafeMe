-- ============================================================================
--  SafeMe · 0002 · טיפוסי enum
--
--  כל הערכים ב-snake_case ותואמים אחד לאחד למחרוזות שהסוכן שולח.
--  שינוי ערך כאן מחייב שינוי מקביל ב-SafeMe.Core/Models/Enums.cs.
-- ============================================================================

CREATE TYPE tenant_type      AS ENUM ('family', 'organization', 'individual');
CREATE TYPE tenant_status    AS ENUM ('active', 'suspended', 'closed');

CREATE TYPE user_role        AS ENUM ('platform_admin', 'support_operator',
                                      'tenant_owner', 'tenant_member');
CREATE TYPE user_status      AS ENUM ('active', 'disabled', 'invited');

CREATE TYPE install_profile  AS ENUM ('family_child', 'individual', 'organization');
CREATE TYPE enforcement_mode AS ENUM ('monitor', 'warn', 'enforce');
CREATE TYPE red_action       AS ENUM ('none', 'warn', 'lockout');

CREATE TYPE device_status    AS ENUM ('active', 'uninstalled', 'revoked');

-- תואם ל-SecurityStatus בסוכן
CREATE TYPE security_status  AS ENUM ('unknown', 'safe', 'low_filter',
                                      'unfiltered', 'blocked');

CREATE TYPE dead_man_state   AS ENUM ('healthy', 'late', 'missing',
                                      'offline', 'tampered');

CREATE TYPE trust_level      AS ENUM ('none', 'low', 'medium', 'high');

-- מחזור החיים של בקשת הסרה, כולל ביטול בחלון הצינון (7.5)
CREATE TYPE uninstall_status AS ENUM ('issued', 'confirmed', 'cancelled',
                                      'expired', 'denied');

CREATE TYPE alert_state      AS ENUM ('open', 'notified', 'resolved');

CREATE TYPE key_purpose      AS ENUM ('policy', 'uninstall', 'loosening');

CREATE TYPE actor_type       AS ENUM ('platform_user', 'tenant_user',
                                      'device', 'system');
