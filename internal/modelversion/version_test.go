package modelversion

import "testing"

func TestLowerVersionSameFamilyOnly(t *testing.T) {
	tests := []struct {
		candidate string
		floor     string
		want      bool
	}{
		{"gpt-5.4", "gpt-5.5", true},
		{"gpt-5.5-codex", "gpt-5.5", false},
		{"gpt-image-1.5", "gpt-5.5", false},
		{"gpt-5.3-codex-spark", "gpt-5.5", false},
		{"claude-opus-4-5-20250929", "claude-opus-4-6", true},
		{"claude-sonnet-4-5", "claude-opus-4-6", false},
		{"grok-4.3", "grok-4.5", true},
		{"deepseek-v3.2", "deepseek-v4.1", true},
		{"qwen3.5-coder", "qwen3.8-flash", true},
		{"kimi-k2", "kimi-k3", true},
		{"k2", "k3", true},
		{"k2-256k", "k3", true},
		{"k3-256k", "k3", false},
		{"doubao-seed-2-0-lite", "doubao-seed-2-1-pro", true},
		{"unknown-1", "unknown-2", false},
	}
	for _, tc := range tests {
		t.Run(tc.candidate+"_below_"+tc.floor, func(t *testing.T) {
			if got := LowerVersion(tc.candidate, tc.floor); got != tc.want {
				t.Fatalf("LowerVersion(%q, %q)=%t want %t", tc.candidate, tc.floor, got, tc.want)
			}
		})
	}
}
