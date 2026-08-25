-- ============================================================================
--  SafeMe · 0007 · זריעת קטלוג ספקי הסינון
--
--  ארבעת הספקים הנתמכים: נטפרי, רימון, אתרוג, נתיב.
--
--  ⚠️  נתוני הזיהוי כאן הם שלד בלבד. טביעות האצבע של תעודות השורש,
--      טווחי ה-IP ומספרי ה-ASN חסרים — ראה פער מספר 8 באפיון.
--      עד שיאספו נתונים אמיתיים, זיהוי הספק יסתמך על תבניות rDNS בלבד
--      ולכן יגיע לכל היותר לרמת אמון בינונית (וקטור אחד).
--
--  איסוף הנתונים: להתקין סוכן על חיבור מסונן ידוע של כל ספק ולקרוא את
--  דוח הביקורת שהוא מחזיר. הסוכן כבר מדווח את כל השדות הנדרשים.
-- ============================================================================

INSERT INTO providers (key, display_name, trust_level, enabled, sort_order, detection)
VALUES
  ('netfree', 'נטפרי', 'high', true, 10, jsonb_build_object(
      'rootCa', jsonb_build_object(
        'thumbprints',     jsonb_build_array(),
        'subjectPatterns', jsonb_build_array('CN=NetFree*', 'O=NetFree*'),
        'required',        false
      ),
      'network', jsonb_build_object(
        'asns',               jsonb_build_array(),
        'cidrs',              jsonb_build_array(),
        'reverseDnsPatterns', jsonb_build_array('*.netfree.link', '*.netfree.co.il')
      ),
      'httpMarkers', jsonb_build_object(
        'headers',      jsonb_build_object(),
        'bodyContains', jsonb_build_array('netfree')
      ),
      'dataStatus', 'skeleton'
  )),

  ('rimon', 'רימון', 'high', true, 20, jsonb_build_object(
      'rootCa', jsonb_build_object(
        'thumbprints',     jsonb_build_array(),
        'subjectPatterns', jsonb_build_array('CN=Rimon*', 'O=Rimon*'),
        'required',        false
      ),
      'network', jsonb_build_object(
        'asns',               jsonb_build_array(),
        'cidrs',              jsonb_build_array(),
        'reverseDnsPatterns', jsonb_build_array('*.rimon.net.il', '*.rimonnet.co.il')
      ),
      'httpMarkers', jsonb_build_object(
        'headers',      jsonb_build_object(),
        'bodyContains', jsonb_build_array('rimon')
      ),
      'dataStatus', 'skeleton'
  )),

  ('etrog', 'אתרוג', 'high', true, 30, jsonb_build_object(
      'rootCa', jsonb_build_object(
        'thumbprints',     jsonb_build_array(),
        'subjectPatterns', jsonb_build_array('CN=Etrog*', 'O=Etrog*'),
        'required',        false
      ),
      'network', jsonb_build_object(
        'asns',               jsonb_build_array(),
        'cidrs',              jsonb_build_array(),
        'reverseDnsPatterns', jsonb_build_array('*.etrog.net.il')
      ),
      'httpMarkers', jsonb_build_object(
        'headers',      jsonb_build_object(),
        'bodyContains', jsonb_build_array('etrog')
      ),
      'dataStatus', 'skeleton'
  )),

  ('nativ', 'נתיב', 'high', true, 40, jsonb_build_object(
      'rootCa', jsonb_build_object(
        'thumbprints',     jsonb_build_array(),
        'subjectPatterns', jsonb_build_array('CN=Nativ*', 'O=Nativ*'),
        'required',        false
      ),
      'network', jsonb_build_object(
        'asns',               jsonb_build_array(),
        'cidrs',              jsonb_build_array(),
        'reverseDnsPatterns', jsonb_build_array('*.nativ.net.il')
      ),
      'httpMarkers', jsonb_build_object(
        'headers',      jsonb_build_object(),
        'bodyContains', jsonb_build_array('nativ')
      ),
      'dataStatus', 'skeleton'
  ))
ON CONFLICT (key) DO NOTHING;

-- ---------------------------------------------------------------- מפתח פיתוח
--
-- רשומת מפתח חתימה ריקה כדי שמפתחות זרים בטבלת policies יהיו תקפים
-- בסביבת פיתוח. בייצור הרשומה נוצרת מ-KMS עם kid אמיתי.

INSERT INTO signing_keys (kid, purpose, public_pem, kms_key_id)
VALUES ('dev-policy-0', 'policy', '-- מפתח פיתוח, אינו בשימוש בייצור --', 'dev')
ON CONFLICT (kid) DO NOTHING;
