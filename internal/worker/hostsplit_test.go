package worker

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
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

// profileStubRunner is a container side that resolves a fixed profile and
// records the guide it was asked to stage.
type profileStubRunner struct {
	profile Profile
	ran     *bool
	guide   *string
	gotJob  *SkillJob
}

func (r profileStubRunner) RunSkill(_ context.Context, sj SkillJob, _ func(Event)) (SkillResult, error) {
	*r.ran = true
	*r.gotJob = sj
	return SkillResult{}, nil
}
func (r profileStubRunner) SkillDir(workRoot, name string) string {
	return filepath.Join(workRoot, "container", name)
}
func (r profileStubRunner) ResolveProfile(context.Context, SkillJob) Profile { return r.profile }
func (r profileStubRunner) InjectProfileGuide(profile, _ string, _ func(Event)) {
	*r.guide = profile
}

// hostStubRunner is the host side of the split.
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

func runSplitWithProfile(t *testing.T, p Profile) (hostRan, containerRan bool, guide string, job SkillJob) {
	t.Helper()
	var hj, cj SkillJob
	r := HostSplitRunner{
		Container: profileStubRunner{profile: p, ran: &containerRan, guide: &guide, gotJob: &cj},
		Host:      hostStubRunner{ran: &hostRan, gotJob: &hj},
		// deliberately empty: routing here must come from the profile alone
		HostSkills: nil,
	}
	res, err := r.RunSkill(context.Background(), SkillJob{Name: "verify", WorkRoot: t.TempDir()}, func(Event) {})
	if err != nil {
		t.Fatalf("RunSkill: %v", err)
	}
	if hostRan {
		job = hj
		if res.Profile != p.Name {
			t.Errorf("result profile = %q, want %q so the scan record names what ran", res.Profile, p.Name)
		}
	} else {
		job = cj
	}
	return hostRan, containerRan, guide, job
}

// A host-backed profile routes at the host without being named in HostSkills —
// the repository's own ecosystem decides. It only does so where this host can
// serve it, which is what keeps a .NET repo scanned from Linux on the image.
func TestHostSplitRunner_routesHostBackedProfileByHostSupport(t *testing.T) {
	p := Profile{Name: "windows", Host: true}
	hostRan, containerRan, guide, job := runSplitWithProfile(t, p)

	if want := p.HostUsable(); hostRan != want {
		t.Fatalf("host ran = %v, want %v on %s", hostRan, want, runtime.GOOS)
	}
	if hostRan == containerRan {
		t.Fatalf("exactly one side must run; host=%v container=%v", hostRan, containerRan)
	}
	if !hostRan {
		return
	}
	if guide != "windows" {
		t.Errorf("staged guide = %q, want the host profile's: it is the only guidance the host runner gets", guide)
	}
	if job.Profile != "windows" {
		t.Errorf("job profile = %q, want it pinned so nothing probes the clone twice", job.Profile)
	}
}

// An image-backed profile stays on the container side on every host.
func TestHostSplitRunner_keepsImageProfileOnContainer(t *testing.T) {
	hostRan, containerRan, guide, _ := runSplitWithProfile(t, Profile{Name: "dotnet"})
	if hostRan || !containerRan {
		t.Errorf("image profile routed host=%v container=%v", hostRan, containerRan)
	}
	if guide != "" {
		t.Errorf("staged a guide (%q) for a run the container side stages itself", guide)
	}
}

// A container side that cannot resolve profiles at all must keep working.
func TestHostSplitRunner_toleratesNonResolvingContainer(t *testing.T) {
	var containerBase string
	r := HostSplitRunner{
		Container: contextCapturingRunner{dir: "container", apiBase: &containerBase},
		Host:      hostStubRunner{ran: new(bool), gotJob: new(SkillJob)},
	}
	if _, ok := r.Container.(ProfileResolver); ok {
		t.Fatal("fixture must not implement ProfileResolver")
	}
	if got := r.hostProfile(context.Background(), SkillJob{Name: "verify"}); !got.IsDefault() {
		t.Errorf("hostProfile = %+v, want the zero profile", got)
	}
}
