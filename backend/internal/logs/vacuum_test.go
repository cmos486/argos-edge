package logs

import (
	"context"
	"testing"
	"time"

	"github.com/cmos486/argos-edge/backend/internal/db"
)

func TestVacuumSlots(t *testing.T) {
	cases := []struct {
		now, last, next string
	}{
		{"2026-09-28T17:54:00Z", "2026-09-01T04:00:00Z", "2026-10-01T04:00:00Z"},
		{"2026-10-01T03:59:59Z", "2026-09-01T04:00:00Z", "2026-10-01T04:00:00Z"},
		{"2026-10-01T04:00:00Z", "2026-10-01T04:00:00Z", "2026-11-01T04:00:00Z"},
		{"2026-12-31T23:00:00Z", "2026-12-01T04:00:00Z", "2027-01-01T04:00:00Z"},
		{"2027-01-01T00:00:00Z", "2026-12-01T04:00:00Z", "2027-01-01T04:00:00Z"},
	}
	for _, c := range cases {
		now, _ := time.Parse(time.RFC3339, c.now)
		if got := lastVacuumSlot(now).Format(time.RFC3339); got != c.last {
			t.Errorf("lastVacuumSlot(%s) = %s, want %s", c.now, got, c.last)
		}
		if got := nextVacuumSlot(now).Format(time.RFC3339); got != c.next {
			t.Errorf("nextVacuumSlot(%s) = %s, want %s", c.now, got, c.next)
		}
	}
	now, _ := time.Parse(time.RFC3339, "2026-10-02T10:00:00Z")
	ran, _ := time.Parse(time.RFC3339, "2026-09-01T04:00:10Z")
	if !vacuumDue(now, ran) {
		t.Fatal("a run before the 2026-10-01 slot must be due on 2026-10-02")
	}
	ran, _ = time.Parse(time.RFC3339, "2026-10-01T04:00:10Z")
	if vacuumDue(now, ran) {
		t.Fatal("a run after the slot must not be due")
	}
	if vacuumDue(now, time.Time{}) {
		t.Fatal("no record is initialised, never due")
	}
}

// TestVacuumAtBoot: no record initialises the schedule without a
// run; a stale record runs the catch-up and records it; a fresh
// record does nothing.
func TestVacuumAtBoot(t *testing.T) {
	d := openRetentionTestDB(t)
	ctx := context.Background()
	now, _ := time.Parse(time.RFC3339, "2026-10-02T10:00:00Z")

	vacuumAtBoot(ctx, d, now)
	if got := db.GetSettingValue(ctx, d, SettingVacuumLastAt, ""); got != "2026-10-01T04:00:00Z" {
		t.Fatalf("first boot must record the last slot, got %q", got)
	}

	if err := db.UpsertSetting(ctx, d, SettingVacuumLastAt, "2026-09-01T04:00:05Z"); err != nil {
		t.Fatal(err)
	}
	before := time.Now().UTC().Add(-time.Second)
	vacuumAtBoot(ctx, d, now)
	got, err := time.Parse(time.RFC3339, db.GetSettingValue(ctx, d, SettingVacuumLastAt, ""))
	if err != nil || got.Before(before) {
		t.Fatalf("catch-up must run and record now, got %v %v", got, err)
	}

	if err := db.UpsertSetting(ctx, d, SettingVacuumLastAt, "2026-10-01T04:00:05Z"); err != nil {
		t.Fatal(err)
	}
	vacuumAtBoot(ctx, d, now)
	if got := db.GetSettingValue(ctx, d, SettingVacuumLastAt, ""); got != "2026-10-01T04:00:05Z" {
		t.Fatalf("fresh record must be left alone, got %q", got)
	}
}
