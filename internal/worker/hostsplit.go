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
// It also routes on the resolved profile. A host-backed profile (Profile.Host)
// is not an image at all — the machine is the environment — so a scan that
// resolves to one goes to Host whatever its skill name, and its PROFILE.md is
// staged the way the container path stages a profile guide. That makes the
// repository's own ecosystem, rather than operator configuration, decide where
// a scan runs; HostSkills remains the manual override for what detection
// cannot see.
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

// hostProfile resolves the job's profile and returns it when it is host-backed
// and this host can serve it. The zero Profile means "not host-backed", which
// includes every case where the container side cannot resolve profiles at all.
func (r HostSplitRunner) hostProfile(ctx context.Context, sj SkillJob) Profile {
	resolver, ok := r.Container.(ProfileResolver)
	if !ok {
		return Profile{}
	}
	p := resolver.ResolveProfile(ctx, sj)
	if !p.Host || !p.HostUsable() {
		return Profile{}
	}
	return p
}

//nolint:ireturn // dispatched on the skill name; both sides are SkillRunner
func (r HostSplitRunner) runnerFor(skillName string) SkillRunner {
	if r.runsOnHost(skillName) {
		return r.Host
	}
	return r.Container
}

func (r HostSplitRunner) RunSkill(ctx context.Context, sj SkillJob, emit func(Event)) (SkillResult, error) {
	if r.runsOnHost(sj.Name) {
		return r.Host.RunSkill(ctx, sj, emit)
	}
	if p := r.hostProfile(ctx, sj); !p.IsDefault() {
		// Pin the resolved name so nothing downstream probes the clone a second
		// time, stage the guide the host runner has no profile machinery to
		// stage itself, and report the profile the way the container path does
		// so retries and the scan record agree on what ran.
		sj.Profile = p.Name
		if injector, ok := r.Container.(interface {
			InjectProfileGuide(string, string, func(Event))
		}); ok {
			absWork, err := filepath.Abs(sj.WorkRoot)
			if err == nil {
				injector.InjectProfileGuide(p.Name, absWork, emit)
			}
		}
		emit(Event{Kind: KindText, Text: "profile: " + p.Name + " is host-backed; running on the host"})
		res, err := r.Host.RunSkill(ctx, sj, emit)
		if res.Profile == "" {
			res.Profile = p.Name
		}
		return res, err
	}
	return r.Container.RunSkill(ctx, sj, emit)
}

// SkillDir stages by skill name only, which is sound because the split is
// claude-on-both-sides: host_skills and a host profile are both refused under a
// non-claude backend, so Container and Host agree on the staging path.
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
