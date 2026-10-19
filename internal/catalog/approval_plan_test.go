package catalog

import "testing"

func TestModelProbeDigestValidatesAggregateAndAccountOrder(t *testing.T) {
	valid := ModelProbeDecision{ModelID: "gpt-5.5", Status: "available", ScopeAccounts: []ModelProbeScopeAccount{{AccountID: 3, Reason: "probe"}, {AccountID: 9, Reason: "probe"}}, Accounts: []ModelProbeOutcome{{AccountID: 3, Outcome: "succeeded"}, {AccountID: 9, Outcome: "not_attempted_after_success"}}}
	if _, err := ModelProbeDigest([]ModelProbeDecision{valid}); err != nil {
		t.Fatalf("valid one-success aggregate rejected: %v", err)
	}
	allFailed := ModelProbeDecision{ModelID: "grok-4.5", Status: "unavailable", ScopeAccounts: []ModelProbeScopeAccount{{AccountID: 3, Reason: "probe"}, {AccountID: 9, Reason: "official_unavailable"}}, Accounts: []ModelProbeOutcome{{AccountID: 3, Outcome: "failed"}, {AccountID: 9, Outcome: "failed"}}}
	if _, err := ModelProbeDigest([]ModelProbeDecision{allFailed}); err != nil {
		t.Fatalf("complete all-failed aggregate rejected: %v", err)
	}
	ignored := ModelProbeDecision{ModelID: "codex-auto-review", Status: "ignored", ScopeAccounts: []ModelProbeScopeAccount{{AccountID: 3, Reason: "probe"}, {AccountID: 9, Reason: "probe"}}, Accounts: []ModelProbeOutcome{{AccountID: 3, Outcome: "incomplete"}, {AccountID: 9, Outcome: "failed"}}}
	if _, err := ModelProbeDigest([]ModelProbeDecision{ignored}); err != nil {
		t.Fatalf("incomplete probe was not accepted as an ignored candidate: %v", err)
	}
	availableAfterIncomplete := ModelProbeDecision{ModelID: "gpt-6-sol", Status: "available", ScopeAccounts: []ModelProbeScopeAccount{{AccountID: 3, Reason: "probe"}, {AccountID: 9, Reason: "probe"}}, Accounts: []ModelProbeOutcome{{AccountID: 3, Outcome: "incomplete"}, {AccountID: 9, Outcome: "succeeded"}}}
	if _, err := ModelProbeDigest([]ModelProbeDecision{availableAfterIncomplete}); err != nil {
		t.Fatalf("a later exact success did not override an earlier incomplete probe: %v", err)
	}
	for _, invalid := range []ModelProbeDecision{
		{ModelID: "gpt-5.5", Status: "available", Accounts: []ModelProbeOutcome{{AccountID: 3, Outcome: "failed"}}},
		{ModelID: "gpt-5.5", Status: "unavailable", Accounts: []ModelProbeOutcome{{AccountID: 3, Outcome: "succeeded"}}},
		{ModelID: "gpt-5.5", Status: "available", Accounts: []ModelProbeOutcome{{AccountID: 9, Outcome: "succeeded"}, {AccountID: 3, Outcome: "not_attempted_after_success"}}},
		{ModelID: "gpt-5.5", Status: "available", Accounts: []ModelProbeOutcome{{AccountID: 3, Outcome: "succeeded"}, {AccountID: 9, Outcome: "failed"}}},
		{ModelID: "gpt-5.5", Status: "unavailable", Accounts: []ModelProbeOutcome{{AccountID: 3, Outcome: "incomplete"}}},
		{ModelID: "gpt-5.5", Status: "ignored", Accounts: []ModelProbeOutcome{{AccountID: 3, Outcome: "failed"}}},
	} {
		if _, err := ModelProbeDigest([]ModelProbeDecision{invalid}); err == nil {
			t.Errorf("invalid probe aggregate accepted: %#v", invalid)
		}
	}
}
