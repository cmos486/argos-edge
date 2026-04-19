DELETE FROM settings WHERE key IN (
    'appsec.mode',
    'appsec.last_mode_change_at',
    'appsec.last_mode_change_by'
);
