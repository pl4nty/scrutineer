package worker

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"scrutineer/internal/db"
	"scrutineer/internal/db/dbtest"
	"scrutineer/internal/queue"
)

// contextCapturingRunner reads context.json out of the workspace at RunSkill
// time, before the worker tears the scan directory down.
type contextCapturingRunner struct {
	dir     string
	apiBase *string
}

func (r contextCapturingRunner) RunSkill(_ context.Context, sj SkillJob, _ func(Event)) (SkillResult, error) {
	data, err := os.ReadFile(filepath.Join(sj.WorkRoot, "context.json"))
	if err != nil {
		return SkillResult{}, err
	}
	var ctx struct {
		Scrutineer struct {
			APIBase string `json:"api_base"`
		} `json:"scrutineer"`
	}
	if err := json.Unmarshal(data, &ctx); err != nil {
		return SkillResult{}, err
	}
	*r.apiBase = ctx.Scrutineer.APIBase
	return SkillResult{}, nil
}

func (r contextCapturingRunner) SkillDir(workRoot, name string) string {
	return filepath.Join(workRoot, r.dir, name)
}

func (contextCapturingRunner) Backend() string { return "codex" }

func TestHostSplitRunner_routesByName(t *testing.T) {
	var hostBase, containerBase string
	r := HostSplitRunner{
		Container:  contextCapturingRunner{dir: "container", apiBase: &containerBase},
		Host:       contextCapturingRunner{dir: "host", apiBase: &hostBase},
		HostSkills: []string{"verify"},
	}
	if got := r.SkillDir("/w", "verify"); got != filepath.Join("/w", "host", "verify") {
		t.Errorf("host skill dir = %q", got)
	}
	if got := r.SkillDir("/w", "triage"); got != filepath.Join("/w", "container", "triage") {
		t.Errorf("container skill dir = %q", got)
	}
	if !r.runsOnHost("verify") || r.runsOnHost("triage") {
		t.Errorf("runsOnHost: verify=%v triage=%v", r.runsOnHost("verify"), r.runsOnHost("triage"))
	}
	if got := r.Backend(); got != "codex" {
		t.Errorf("Backend() = %q, want the container's", got)
	}
}

func TestRunnerImageName_unwrapsHostSplit(t *testing.T) {
	inner := ContainerRunner{Image: "runner:test", Runtime: ContainerRuntime{Bin: "podman"}}
	r := HostSplitRunner{Container: inner, Host: LocalClaude{}, HostSkills: []string{"verify"}}
	if got := RunnerImageName(r); got != "runner:test" {
		t.Errorf("RunnerImageName = %q, want runner:test", got)
	}
	if got := RuntimeOf(r).Bin; got != "podman" {
		t.Errorf("RuntimeOf.Bin = %q, want podman", got)
	}
}

// runHostSplitScan runs one posture-test scan through a split runner whose
// host list is hostSkills and returns the api_base each side saw.
func runHostSplitScan(t *testing.T, hostSkills []string) (hostBase, containerBase string) {
	t.Helper()
	gdb := dbtest.Open(t)
	repo := db.Repository{URL: "https://example.com/x", Name: "x"}
	gdb.Create(&repo)
	skill := db.Skill{Name: "posture-test", Description: "d", Body: "b", Version: 1, Active: true, Source: "ui"}
	gdb.Create(&skill)
	scan := db.Scan{RepositoryID: repo.ID, Kind: JobSkill, Status: db.ScanQueued, SkillID: &skill.ID, Model: "fake"}
	gdb.Create(&scan)
	w := &Worker{
		DB: gdb, Log: slog.New(slog.NewTextHandler(io.Discard, nil)),
		DataDir: t.TempDir(),
		APIBase: "http://host.docker.internal:8080/api",
		Runner: HostSplitRunner{
			Container:   contextCapturingRunner{dir: "container", apiBase: &containerBase},
			Host:        contextCapturingRunner{dir: "host", apiBase: &hostBase},
			HostSkills:  hostSkills,
			HostAPIBase: "http://127.0.0.1:8080/api",
		},
		PrepareRepoSrc: stubPrepareRepoSrc,
	}
	body, _ := json.Marshal(queue.Payload{ScanID: scan.ID})
	if err := w.wrap(w.doSkill)(context.Background(), body); err != nil {
		t.Fatalf("wrap: %v", err)
	}
	var got db.Scan
	gdb.First(&got, scan.ID)
	if got.Status != db.ScanDone {
		t.Fatalf("scan status = %q, want done (%s)", got.Status, got.Error)
	}
	return hostBase, containerBase
}

func TestWorker_hostSkillGetsLoopbackAPIBase(t *testing.T) {
	hostBase, containerBase := runHostSplitScan(t, []string{"posture-test"})
	if containerBase != "" {
		t.Errorf("container side ran a host skill (api_base %q)", containerBase)
	}
	if hostBase != "http://127.0.0.1:8080/api" {
		t.Errorf("host api_base = %q, want the loopback base", hostBase)
	}
}

func TestWorker_containerSkillKeepsContainerAPIBase(t *testing.T) {
	hostBase, containerBase := runHostSplitScan(t, []string{"verify"})
	if hostBase != "" {
		t.Errorf("host side ran a container skill (api_base %q)", hostBase)
	}
	if containerBase != "http://host.docker.internal:8080/api" {
		t.Errorf("container api_base = %q, want the container host endpoint", containerBase)
	}
}

// hostProfileStubRunner is a container side that names a host profile for the
// repository and records the guide it was asked to stage.
type hostProfileStubRunner struct {
	profile Profile
	ran     *bool
	guide   *string
}

func (r hostProfileStubRunner) RunSkill(context.Context, SkillJob, func(Event)) (SkillResult, error) {
	*r.ran = true
	return SkillResult{}, nil
}
func (r hostProfileStubRunner) SkillDir(workRoot, name string) string {
	return filepath.Join(workRoot, "container", name)
}
func (r hostProfileStubRunner) ResolveHostProfile(context.Context, SkillJob) Profile {
	return r.profile
}
func (r hostProfileStubRunner) InjectProfileGuide(profile, _ string, _ func(Event)) {
	*r.guide = profile
}

type hostStubRunner struct {
	ran    *bool
	gotJob *SkillJob
}

func (r hostStubRunner) RunSkill(_ context.Context, sj SkillJob, _ func(Event)) (SkillResult, error) {
	*r.ran = true
	*r.gotJob = sj
	return SkillResult{}, nil
}
func (r hostStubRunner) SkillDir(workRoot, name string) string {
	return filepath.Join(workRoot, "host", name)
}

func runSplitFor(t *testing.T, skill string, hostSkills []string, p Profile) (hostRan, containerRan bool, guide string, job SkillJob) {
	t.Helper()
	var hj SkillJob
	r := HostSplitRunner{
		Container:  hostProfileStubRunner{profile: p, ran: &containerRan, guide: &guide},
		Host:       hostStubRunner{ran: &hostRan, gotJob: &hj},
		HostSkills: hostSkills,
	}
	if _, err := r.RunSkill(context.Background(), SkillJob{Name: skill, WorkRoot: t.TempDir()}, func(Event) {}); err != nil {
		t.Fatalf("RunSkill: %v", err)
	}
	return hostRan, containerRan, guide, hj
}

// A host-bound skill gets the repository's host profile guide: without it the
// agent runs on the machine with none of the procedure the profile carries.
func TestHostSplitRunner_stagesHostGuideForHostSkill(t *testing.T) {
	hostRan, containerRan, guide, job := runSplitFor(t, "verify", []string{"verify"}, Profile{Name: "windows", Host: true})
	if !hostRan || containerRan {
		t.Fatalf("routing: host=%v container=%v", hostRan, containerRan)
	}
	if guide != "windows" {
		t.Errorf("staged guide = %q, want windows", guide)
	}
	if job.Profile != "windows" {
		t.Errorf("job profile = %q, want it pinned for the scan record", job.Profile)
	}
}

// The profile must not move a containerised skill. A Windows-targeted
// repository still analyses in its image; only the named skills leave it,
// which is what keeps container isolation for the rest of the pipeline.
func TestHostSplitRunner_hostProfileDoesNotMoveContainerSkills(t *testing.T) {
	hostRan, containerRan, guide, _ := runSplitFor(t, "triage", []string{"verify"}, Profile{Name: "windows", Host: true})
	if hostRan || !containerRan {
		t.Fatalf("a host profile moved a container skill: host=%v container=%v", hostRan, containerRan)
	}
	if guide != "" {
		t.Errorf("staged guide %q for a containerised run", guide)
	}
}

// No host profile for this repository: the host skill still runs, unguided.
func TestHostSplitRunner_hostSkillWithoutHostProfile(t *testing.T) {
	hostRan, _, guide, job := runSplitFor(t, "verify", []string{"verify"}, Profile{})
	if !hostRan {
		t.Fatal("host skill did not run")
	}
	if guide != "" || job.Profile != "" {
		t.Errorf("staged guide %q / profile %q with no host profile", guide, job.Profile)
	}
}

// A container side with no host-profile support must keep working.
func TestHostSplitRunner_toleratesNonResolvingContainer(t *testing.T) {
	var base string
	hostRan := false
	r := HostSplitRunner{
		Container:  contextCapturingRunner{dir: "container", apiBase: &base},
		Host:       hostStubRunner{ran: &hostRan, gotJob: new(SkillJob)},
		HostSkills: []string{"verify"},
	}
	if _, ok := r.Container.(HostProfileResolver); ok {
		t.Fatal("fixture must not implement HostProfileResolver")
	}
	if _, err := r.RunSkill(context.Background(), SkillJob{Name: "verify", WorkRoot: t.TempDir()}, func(Event) {}); err != nil {
		t.Fatalf("RunSkill: %v", err)
	}
	if !hostRan {
		t.Error("host skill did not run without a resolver")
	}
}
