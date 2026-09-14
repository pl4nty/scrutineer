package web

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"scrutineer/internal/db"
)

func verifyWindowsFixture(t *testing.T, s *Server, status db.FindingLifecycle) db.Finding {
	t.Helper()
	repo := db.Repository{URL: "https://github.com/contoso/cli", Name: "cli"}
	s.DB.Create(&repo)
	scan := db.Scan{RepositoryID: repo.ID, Kind: "skill", Status: db.ScanDone, SkillName: "security-deep-dive"}
	s.DB.Create(&scan)
	f := db.Finding{ScanID: scan.ID, RepositoryID: repo.ID, FindingID: "F1",
		Title: "out-of-bounds read in the DXF reader", Severity: "High", Status: status}
	s.DB.Create(&f)
	return f
}

func installVerifyWindowsSkill(t *testing.T, s *Server) db.Skill {
	t.Helper()
	skill := db.Skill{Name: verifyWindowsSkillName, Description: "windows artifact verification",
		Body: "b", OutputFile: "report.json", OutputKind: "verify", Version: 1, Active: true, Source: "ui"}
	s.DB.Create(&skill)
	return skill
}

// The action needs both halves: the skill installed, and skills executing on
// this Windows host rather than in a Linux container. Offering it otherwise
// buys an agent run that can only report env-blocked.
func TestFindingShow_offersVerifyWindowsOnlyWhenInstalledAndOnAWindowsHost(t *testing.T) {
	s, done := newTestServer(t)
	defer done()

	f := verifyWindowsFixture(t, s, db.FindingNew)
	action := fmt.Sprintf(`hx-post="/findings/%d/verify-windows"`, f.ID)
	offered := func() bool {
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, localReq("GET", fmt.Sprintf("/findings/%d", f.ID)))
		if w.Code != http.StatusOK {
			t.Fatalf("status %d: %s", w.Code, w.Body)
		}
		return strings.Contains(w.Body.String(), action)
	}

	s.WindowsArtifactHost = true
	if offered() {
		t.Error("offered the Windows artifact check without the skill installed")
	}

	installVerifyWindowsSkill(t, s)
	if !offered() {
		t.Error("did not offer the Windows artifact check with the skill installed on a Windows host")
	}

	s.WindowsArtifactHost = false
	if offered() {
		t.Error("offered the Windows artifact check where skills do not run on a Windows host")
	}
}

// Re-verifying a finding that verify already graded is the point of the
// second action: an enriched finding still gets the artifact-backed check.
func TestFindingVerifyWindows_enqueuesOnAlreadyVerifiedFinding(t *testing.T) {
	s, done := newTestServer(t)
	defer done()

	f := verifyWindowsFixture(t, s, db.FindingEnriched)
	skill := installVerifyWindowsSkill(t, s)

	req := httptest.NewRequest("POST", fmt.Sprintf("/findings/%d/verify-windows", f.ID), nil)
	req.Host = testHost
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusSeeOther {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}

	var scan db.Scan
	if err := s.DB.Where("finding_id = ? AND skill_name = ?", f.ID, verifyWindowsSkillName).
		First(&scan).Error; err != nil {
		t.Fatalf("verify-windows scan not enqueued: %v", err)
	}
	if scan.SkillID == nil || *scan.SkillID != skill.ID {
		t.Errorf("scan skill = %v, want %d", scan.SkillID, skill.ID)
	}
	if scan.FindingID == nil || *scan.FindingID != f.ID {
		t.Errorf("scan finding = %v, want %d", scan.FindingID, f.ID)
	}
}

// A queued Windows check must not be enqueued twice, and it must not be
// confused with an open generic verify scan on the same finding.
func TestFindingVerifyWindows_skipsOpenScanButIgnoresVerify(t *testing.T) {
	s, done := newTestServer(t)
	defer done()

	f := verifyWindowsFixture(t, s, db.FindingNew)
	skill := installVerifyWindowsSkill(t, s)
	verify := db.Skill{Name: verifySkillName, Description: "v", Body: "b",
		OutputFile: "report.json", OutputKind: "verify", Version: 1, Active: true, Source: "ui"}
	s.DB.Create(&verify)
	s.DB.Create(&db.Scan{RepositoryID: f.RepositoryID, Kind: "skill", Status: db.ScanRunning,
		StatusPriority: db.StatusPriorityFor(db.ScanRunning), SkillName: verifySkillName,
		SkillID: new(verify.ID), FindingID: new(f.ID)})

	post := func() *httptest.ResponseRecorder {
		req := httptest.NewRequest("POST", fmt.Sprintf("/findings/%d/verify-windows", f.ID), nil)
		req.Host = testHost
		req.Header.Set("Sec-Fetch-Site", "same-origin")
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, req)
		return w
	}

	// An open verify scan is a different skill and must not block this one.
	if got := post().Code; got != http.StatusSeeOther {
		t.Fatalf("first enqueue status %d", got)
	}
	s.DB.Model(&db.Scan{}).
		Where("finding_id = ? AND skill_name = ?", f.ID, verifyWindowsSkillName).
		Update("status", db.ScanQueued)

	if got := post().Code; got != http.StatusSeeOther {
		t.Fatalf("second enqueue status %d", got)
	}
	var count int64
	s.DB.Model(&db.Scan{}).
		Where("finding_id = ? AND skill_id = ?", f.ID, skill.ID).
		Count(&count)
	if count != 1 {
		t.Errorf("verify-windows scans = %d, want 1", count)
	}
}
