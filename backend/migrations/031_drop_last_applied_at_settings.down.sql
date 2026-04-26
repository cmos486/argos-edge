-- v1.3.27 down: no-op.
--
-- The .up dropped two settings rows that the v1.3.27+ panel no
-- longer writes (mark-applied endpoints removed). Rolling back
-- to v1.3.26 leaves the keys absent until the operator clicks
-- "Mark as applied" again, at which point the row is recreated
-- on first PATCH. The .down therefore has nothing to restore.
SELECT 1;  -- migration runner expects at least one statement
