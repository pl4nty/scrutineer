package worker

import (
	"context"
	"path/filepath"
	"slices"
)

// HostSplitRunner sends the skills named in HostSkills to Host and every other
// job to Container. It is what the host_skills config key builds: Host is the
// no-isolation LocalClaude, so a skill whose toolchain only exists on the host
// (verify, say) can run there while triage and the deep-dive skills keep their
// profile containers.
//
// A host-bound run also gets the repository's host profile guide, when one
// applies. That is deliberately the only thing the profile decides here.
// Routing stays per-skill: a Windows-targeted repository still analyses inside
// the dotnet container and only the skills the operator named leave it, which
// is the whole point of splitting rather than moving the pipeline to the host.
type HostSplitRunner struct {
	Container  SkillRunner
	Host       SkillRunner
	HostSkills []string
	// HostAPIBase is the skill API address handed to a job on the host: the
	// loopback form of the worker's APIBase, which in container mode names the
	// runtime's host endpoint and only resolves through the egress proxy.
	HostAPIBase string
}

func (r HostSplitRunner) runsOnHost(skillName string) bool {
	return slices.Contains(r.HostSkills, skillName)
}

//nolint:ireturn // dispatched on the skill name; both sides are SkillRunner
func (r HostSplitRunner) runnerFor(skillName string) SkillRunner {
	if r.runsOnHost(skillName) {
		return r.Host
	}
	return r.Container
}

// HostProfileResolver is an optional extension on the container side: it can
// name the host-backed profile a repository needs without building anything.
// HostSplitRunner uses it to stage that profile's guide for a host-bound run,
// which the host runner has no profile machinery to stage itself.
type HostProfileResolver interface {
	ResolveHostProfile(ctx context.Context, sj SkillJob) Profile
	InjectProfileGuide(profile, absWork string, emit func(Event))
}

// stageHostGuide gives a host-bound job the guide for its host profile and
// pins the resolved name on it. Without this the agent runs on the machine
// with none of the guidance the profile exists to carry, which for the windows
// profile is the entire shipped-artifact procedure.
func (r HostSplitRunner) stageHostGuide(ctx context.Context, sj *SkillJob, emit func(Event)) {
	resolver, ok := r.Container.(HostProfileResolver)
	if !ok {
		return
	}
	p := resolver.ResolveHostProfile(ctx, *sj)
	if p.IsDefault() {
		return
	}
	absWork, err := filepath.Abs(sj.WorkRoot)
	if err != nil {
		return
	}
	resolver.InjectProfileGuide(p.Name, absWork, emit)
	sj.Profile = p.Name
	emit(Event{Kind: KindText, Text: "host profile: " + p.Name})
}

func (r HostSplitRunner) RunSkill(ctx context.Context, sj SkillJob, emit func(Event)) (SkillResult, error) {
	if !r.runsOnHost(sj.Name) {
		return r.Container.RunSkill(ctx, sj, emit)
	}
	r.stageHostGuide(ctx, &sj, emit)
	res, err := r.Host.RunSkill(ctx, sj, emit)
	if res.Profile == "" {
		res.Profile = sj.Profile
	}
	return res, err
}

// SkillDir stages by skill name only, which is sound because the split is
// claude-on-both-sides: host_skills is refused under a non-claude backend, so
// Container and Host agree on the staging path.
func (r HostSplitRunner) SkillDir(workRoot, name string) string {
	return r.runnerFor(name).SkillDir(workRoot, name)
}

// Backend is the container side's harness. The host side is LocalClaude, so
// it can only be claude.
func (r HostSplitRunner) Backend() string {
	if br, ok := r.Container.(BackendReporter); ok {
		return br.Backend()
	}
	return HarnessName(ClaudeHarness{})
}
