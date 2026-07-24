-- SNR V3 — keep the rule body on the detection-rule index.
--
-- 016 stored only a hash of the rule body (enough to count distinct rules), so
-- the coverage view could list a rule but never show it. Analysts need to read
-- the actual rule, copy it, and export it from the coverage panel without
-- opening the originating incident.
--
-- Still DERIVED STATE: result_json remains the source of truth and
-- reindexSessionDetectionRules rebuilds these rows on every result write.
-- Backfilled from the latest result of every live session, exactly as 016 did.

ALTER TABLE detection_rule_observations ADD COLUMN IF NOT EXISTS rule_content TEXT NOT NULL DEFAULT '';

UPDATE detection_rule_observations d
SET rule_content = COALESCE(rule.value ->> 'rule_content', '')
FROM sessions s
JOIN (
  SELECT session_id, MAX(version) AS v FROM analysis_results GROUP BY session_id
) mv ON mv.session_id = s.id
JOIN analysis_results ar ON ar.session_id = s.id AND ar.version = mv.v,
  snr_json_array(ar.result_json, 'detection_rules') AS rule(value)
WHERE d.session_id = s.id
  AND d.rule_content = ''
  AND LOWER(rule.value ->> 'rule_type') = d.rule_type
  AND rule.value ->> 'rule_name' = d.rule_name
  AND encode(sha256(convert_to(regexp_replace(COALESCE(rule.value ->> 'rule_content', ''), '\s+', ' ', 'g'), 'UTF8')), 'hex') = d.rule_hash;
