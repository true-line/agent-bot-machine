package members

import (
	"strings"
	"testing"
)

func TestStage2aReserveRequestExactFields(t *testing.T) {
	good := `{"plan_digest":"` + strings.Repeat("a", 64) + `","installation_id":"soul-one","start_id":"st_0123456789abcdef01234567","hq_epoch":"` + strings.Repeat("b", 64) + `","launch_id":"ln_0123456789abcdef01234567"}`
	parsed, err := ParseStage2aReserveRequest([]byte(good))
	if err != nil || parsed.InstallationID != "soul-one" {
		t.Fatalf("valid request: %+v %v", parsed, err)
	}
	for name, raw := range map[string]string{
		"duplicate":  strings.Replace(good, `"installation_id":"soul-one"`, `"installation_id":"soul-one","installation_id":"soul-two"`, 1),
		"extra":      strings.Replace(good, `"launch_id":`, `"uid":501,"launch_id":`, 1),
		"missing":    strings.Replace(good, `,"launch_id":"ln_0123456789abcdef01234567"`, ``, 1),
		"null":       strings.Replace(good, `"installation_id":"soul-one"`, `"installation_id":null`, 1),
		"bad epoch":  strings.Replace(good, strings.Repeat("b", 64), "legacy", 1),
		"bad launch": strings.Replace(good, "ln_0123456789abcdef01234567", "ln_other", 1),
		"trailing":   good + `{}`,
	} {
		if _, err := ParseStage2aReserveRequest([]byte(raw)); err == nil {
			t.Errorf("accepted %s", name)
		}
	}
}
