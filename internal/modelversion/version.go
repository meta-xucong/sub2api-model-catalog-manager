// Package modelversion recognizes conservative, same-family model versions for
// the owner's cascade rule. Unknown IDs intentionally remain incomparable.
package modelversion

import (
	"regexp"
	"strconv"
	"strings"
)

type version struct {
	family string
	parts  []int
}

var patterns = []struct {
	family string
	re     *regexp.Regexp
}{
	{"gpt", regexp.MustCompile(`^gpt-(\d+)(?:\.(\d+))?(?:-|$)`)},
	{"claude-opus", regexp.MustCompile(`^claude-opus-(\d+)[.-](\d+)(?:-|$)`)},
	{"claude-sonnet", regexp.MustCompile(`^claude-sonnet-(\d+)[.-](\d+)(?:-|$)`)},
	{"claude-haiku", regexp.MustCompile(`^claude-haiku-(\d+)[.-](\d+)(?:-|$)`)},
	{"claude-fable", regexp.MustCompile(`^claude-fable-(\d+)[.-](\d+)(?:-|$)`)},
	{"grok", regexp.MustCompile(`^grok-(\d+)\.(\d+)(?:-|$)`)},
	{"glm", regexp.MustCompile(`^glm-(\d+)\.(\d+)(?:-|$)`)},
	{"deepseek", regexp.MustCompile(`^deepseek-v(\d+)(?:\.(\d+))?(?:-|$)`)},
	{"qwen", regexp.MustCompile(`^qwen(\d+)(?:\.(\d+))?(?:-|$)`)},
	{"doubao-seed", regexp.MustCompile(`^doubao-seed-(\d+)[.-](\d+)(?:-|$)`)},
	{"minimax-m", regexp.MustCompile(`^minimax-m(\d+)(?:\.(\d+))?(?:-|$)`)},
	{"kimi-k", regexp.MustCompile(`^kimi-k(\d+)(?:\.(\d+))?(?:-|$)`)},
	{"kimi-k", regexp.MustCompile(`^k(\d+)(?:-\d+k)?(?:-[a-z0-9][a-z0-9-]*)?$`)},
}

func parse(modelID string) (version, bool) {
	id := strings.ToLower(strings.TrimSpace(modelID))
	if strings.HasPrefix(id, "gpt-image-") || strings.Contains(id, "codex-spark") {
		return version{}, false
	}
	for _, p := range patterns {
		m := p.re.FindStringSubmatch(id)
		if m == nil {
			continue
		}
		parts := make([]int, 0, 2)
		for _, raw := range m[1:] {
			if raw == "" {
				break
			}
			n, err := strconv.Atoi(raw)
			if err != nil {
				return version{}, false
			}
			parts = append(parts, n)
		}
		return version{family: p.family, parts: parts}, len(parts) > 0
	}
	return version{}, false
}

// LowerVersion reports whether candidate has a strictly lower numeric version
// than floor in the same recognized model family. Equal versions and unknown
// or cross-family identifiers never cascade.
func LowerVersion(candidate, floor string) bool {
	comparison, ok := compareVersion(candidate, floor)
	return ok && comparison < 0
}

// AtOrBelowVersion reports whether candidate has an equal or lower numeric
// version than floor in the same recognized model family. Model suffixes such
// as fast or openai-compact do not change the numeric version.
func AtOrBelowVersion(candidate, floor string) bool {
	comparison, ok := compareVersion(candidate, floor)
	return ok && comparison <= 0
}

func compareVersion(candidate, floor string) (int, bool) {
	c, okC := parse(candidate)
	f, okF := parse(floor)
	if !okC || !okF || c.family != f.family {
		return 0, false
	}
	for i := 0; i < len(c.parts) || i < len(f.parts); i++ {
		cv, fv := 0, 0
		if i < len(c.parts) {
			cv = c.parts[i]
		}
		if i < len(f.parts) {
			fv = f.parts[i]
		}
		if cv < fv {
			return -1, true
		}
		if cv > fv {
			return 1, true
		}
	}
	return 0, true
}

// HigherVersion reports whether a has a strictly higher numeric version than
// b in the same recognized family.
func HigherVersion(a, b string) bool { return LowerVersion(b, a) }

// Family returns the normalized family key used to keep floors independent.
func Family(modelID string) (string, bool) {
	v, ok := parse(modelID)
	return v.family, ok
}
