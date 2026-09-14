package worker

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

// verifyWindowsSchema is the schema the worker stages for the verify-windows
// skill; the tests below assert the artifact gates it adds on top of verify's.
func verifyWindowsSchema(t *testing.T) string {
	t.Helper()
	raw, err := os.ReadFile("../../skills/verify-windows/schema.json")
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

// verifyWindowsReport is a confirmed report whose execution target is a
// released binary: the shape the skill must produce for a confirmation.
func verifyWindowsReport(t *testing.T, edit func(map[string]any)) string {
	t.Helper()
	const base = `{
  "status": "confirmed",
  "preflight": {"classification": "local-safe", "justification": "Contoso.Cli.exe convert .verify\\poc\\input.dxf reads one local file"},
  "artifact": {
    "provenance": "released-binary",
    "install_mode": "extracted",
    "head_correspondence": "tested-artifact-predates-head",
    "reimplementation_free": true,
    "fallback_reason": "",
    "source": {
      "release_tag": "v4.2.1",
      "asset_name": "contoso-cli-4.2.1-win-x64.zip",
      "download_url": "https://github.com/contoso/cli/releases/download/v4.2.1/contoso-cli-4.2.1-win-x64.zip",
      "sha256": "9f2b1c0d5e4a39887766554433221100ffeeddccbbaa99887766554433221100",
      "publisher_checksum": "matched",
      "authenticode": "valid",
      "ancestry": "git merge-base --is-ancestor v4.2.1 8f1c2d0 exited 0",
      "contains_vulnerable_code": "src/Dxf/EntityReader.cs:214 present at v4.2.1"
    },
    "execution_target": {
      "path": "C:\\work\\.verify\\install\\Contoso.Cli.exe",
      "sha256": "41ce00112233445566778899aabbccddeeff00112233445566778899aabbccdd",
      "file_version": "4.2.1.0",
      "symbols": "shipped"
    },
    "authored_files": [
      {"path": ".verify/poc/input.dxf", "role": "input", "why": "crafted DXF, no target logic"}
    ],
    "toolchain": ["pwsh 7.4.6"],
    "system_changes": ["none - zip extracted to .verify\\install"]
  },
  "attack_tree": {
    "goal": "Crafted DXF crashes the shipped converter",
    "root_id": "AT1",
    "verdict": "reachable",
    "nodes": [
      {"id": "AT1", "parent_id": null, "kind": "goal", "description": "Crash the shipped converter", "status": "satisfied", "evidence": "attempts 1-3 exit 0xC0000005"},
      {"id": "AT2", "parent_id": "AT1", "kind": "entry_point", "description": "convert verb takes a file path", "status": "satisfied", "evidence": "Contoso.Cli.exe --help"},
      {"id": "AT3", "parent_id": "AT2", "kind": "sink", "description": "EntityReader reads out of bounds", "status": "satisfied", "evidence": "cdb faulting frame EntityReader.Read+0x8c"}
    ],
    "blockers": []
  },
  "attempts": [
    {"number": 1, "outcome": "reproduced", "evidence": "exit 0xC0000005", "failure_class": "access-violation", "crash_site": "EntityReader.Read+0x8c"},
    {"number": 2, "outcome": "reproduced", "evidence": "exit 0xC0000005", "failure_class": "access-violation", "crash_site": "EntityReader.Read+0x8c"},
    {"number": 3, "outcome": "reproduced", "evidence": "exit 0xC0000005", "failure_class": "access-violation", "crash_site": "EntityReader.Read+0x8c"}
  ],
  "criteria": {
    "poc_well_formed": {"verdict": "pass", "method": "ran the crafted file", "evidence": "input hash recorded", "counterevidence": "", "proof_gap": "", "confidence": "high"},
    "reproduces_three_of_three": {"verdict": "pass", "method": "three isolated processes", "evidence": "3/3", "counterevidence": "", "proof_gap": "", "confidence": "high"},
    "claimed_failure_class": {"verdict": "pass", "method": "exception code plus dump", "evidence": "0xC0000005", "counterevidence": "", "proof_gap": "", "confidence": "high"},
    "public_interface_to_first_party_sink": {"verdict": "pass", "method": "shipped binary identified by hash", "evidence": "signed 4.2.1 zip reaches Contoso.Dxf", "counterevidence": "", "proof_gap": "", "confidence": "high"},
    "deterministic": {"verdict": "pass", "method": "compared frames", "evidence": "same frame 3/3", "counterevidence": "", "proof_gap": "", "confidence": "high"},
    "control_bypass": {"matched_controls": [], "assessments": []}
  },
  "reproducer": "acquisition and trigger commands",
  "evidence": "attempt output and dump analysis",
  "notes": "tested v4.2.1"
}`
	var doc map[string]any
	if err := json.Unmarshal([]byte(base), &doc); err != nil {
		t.Fatal(err)
	}
	if edit != nil {
		edit(doc)
	}
	out, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	return string(out)
}

func artifactBlock(t *testing.T, doc map[string]any) map[string]any {
	t.Helper()
	block, ok := doc["artifact"].(map[string]any)
	if !ok {
		t.Fatal("report has no artifact block")
	}
	return block
}

// A confirmation naming the shipped binary it executed is the shape the skill
// exists to produce, and it must satisfy verify's semantic rubric too.
func TestVerifyWindowsSchema_acceptsReleasedBinaryConfirmation(t *testing.T) {
	report := verifyWindowsReport(t, nil)
	if got := ValidateSkillReport(verifyWindowsSkillName, verifyWindowsSchema(t), report); got != "" {
		t.Fatalf("valid verify-windows report rejected: %s", got)
	}
}

// The whole point of the skill: a confirmation that cannot name a real
// artifact, or that leans on a re-implementation, is not a confirmation.
func TestVerifyWindowsSchema_rejectsConfirmationWithoutRealArtifact(t *testing.T) {
	cases := []struct {
		name string
		edit func(map[string]any)
	}{
		{"no artifact obtained", func(doc map[string]any) {
			artifactBlock(t, doc)["provenance"] = "none"
		}},
		{"logic re-implemented", func(doc map[string]any) {
			artifactBlock(t, doc)["reimplementation_free"] = false
		}},
		{"execution target unhashed", func(doc map[string]any) {
			artifactBlock(t, doc)["execution_target"] = map[string]any{
				"path": "C:\\work\\.verify\\install\\Contoso.Cli.exe", "sha256": "",
			}
		}},
		{"artifact block missing", func(doc map[string]any) {
			delete(doc, "artifact")
		}},
		{"authored file with no role", func(doc map[string]any) {
			artifactBlock(t, doc)["authored_files"] = []any{
				map[string]any{"path": ".verify/poc/reimpl.py", "why": "re-states the parser"},
			}
		}},
	}
	schema := verifyWindowsSchema(t)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			report := verifyWindowsReport(t, tc.edit)
			if got := ValidateSkillReport(verifyWindowsSkillName, schema, report); got == "" {
				t.Fatal("report was accepted; the artifact gate did not hold")
			}
		})
	}
}

// A released binary that does not reproduce may simply predate the bug, so
// only an artifact that corresponds to the scanned commit can mark a finding
// fixed. That transition writes to the finding's lifecycle, so the schema, not
// only the body, has to hold the line.
func TestVerifyWindowsSchema_fixedRequiresArtifactAtHead(t *testing.T) {
	schema := verifyWindowsSchema(t)
	toFixed := func(doc map[string]any) {
		doc["status"] = "fixed"
		tree := doc["attack_tree"].(map[string]any)
		tree["verdict"] = "blocked"
		tree["blockers"] = []any{"input length rejected before the reader"}
		for _, node := range tree["nodes"].([]any) {
			node.(map[string]any)["status"] = "blocked"
		}
		for _, attempt := range doc["attempts"].([]any) {
			a := attempt.(map[string]any)
			a["outcome"] = "not_reproduced"
			a["failure_class"] = ""
			a["crash_site"] = ""
		}
		criteria := doc["criteria"].(map[string]any)
		criteria["reproduces_three_of_three"].(map[string]any)["verdict"] = "fail"
	}

	predates := verifyWindowsReport(t, toFixed)
	if got := ValidateSkillReport(verifyWindowsSkillName, schema, predates); got == "" {
		t.Fatal("a clean older release was accepted as fixed; it says nothing about HEAD")
	}

	atHead := verifyWindowsReport(t, func(doc map[string]any) {
		toFixed(doc)
		artifactBlock(t, doc)["head_correspondence"] = "tested-artifact-equals-head"
	})
	if got := ValidateSkillReport(verifyWindowsSkillName, schema, atHead); got != "" {
		t.Fatalf("fixed at HEAD rejected: %s", got)
	}
}

// verify-windows shares verify's output kind, so it must also share verify's
// semantic rubric checks rather than falling through to schema-only validation.
func TestVerifyWindowsSchema_runsVerifyRubricSemantics(t *testing.T) {
	report := verifyWindowsReport(t, func(doc map[string]any) {
		tree := doc["attack_tree"].(map[string]any)
		nodes := tree["nodes"].([]any)
		nodes[2].(map[string]any)["parent_id"] = "AT9"
	})
	got := ValidateSkillReport(verifyWindowsSkillName, verifyWindowsSchema(t), report)
	if got == "" {
		t.Fatal("dangling attack-tree parent accepted")
	}
	if !strings.Contains(got, "verify rubric") {
		t.Fatalf("want the verify rubric to have rejected it, got: %s", got)
	}
}

// A not_attempted run is how the skill reports a non-Windows host, so it must
// stay valid without any artifact having been obtained.
func TestVerifyWindowsSchema_allowsNotAttemptedWithoutArtifact(t *testing.T) {
	report := verifyWindowsReport(t, func(doc map[string]any) {
		doc["status"] = "not_attempted"
		doc["notes"] = "env-blocked: host is linux, no PowerShell present"
		block := artifactBlock(t, doc)
		block["provenance"] = "none"
		block["install_mode"] = "none"
		block["head_correspondence"] = "unknown"
		block["reimplementation_free"] = true
		block["execution_target"] = map[string]any{"path": "", "sha256": ""}
		block["authored_files"] = []any{}
		block["system_changes"] = []any{"none"}
		delete(block, "source")

		tree := doc["attack_tree"].(map[string]any)
		tree["verdict"] = "not_attempted"
		for _, node := range tree["nodes"].([]any) {
			node.(map[string]any)["status"] = "not_attempted"
		}
		for _, attempt := range doc["attempts"].([]any) {
			a := attempt.(map[string]any)
			a["outcome"] = "not_attempted"
			a["evidence"] = "host is not Windows"
			a["failure_class"] = ""
			a["crash_site"] = ""
		}
		criteria := doc["criteria"].(map[string]any)
		for _, name := range []string{"poc_well_formed", "reproduces_three_of_three", "claimed_failure_class", "public_interface_to_first_party_sink", "deterministic"} {
			criteria[name].(map[string]any)["verdict"] = "not_attempted"
		}
	})
	if got := ValidateSkillReport(verifyWindowsSkillName, verifyWindowsSchema(t), report); got != "" {
		t.Fatalf("not_attempted report rejected: %s", got)
	}
}
