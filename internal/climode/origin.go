package climode

import (
	"encoding/json"
	"fmt"

	"github.com/LeafAI/securl/internal/notify"
)

func announceOrigin(env Env, out map[string]any) {
	value, ok := out["origin"]
	if !ok || value == nil {
		return
	}
	b, err := json.Marshal(value)
	var origin notify.Origin
	if err != nil || json.Unmarshal(b, &origin) != nil {
		fmt.Fprintln(env.Err, "securl: invalid request origin metadata")
		return
	}
	fmt.Fprintln(env.Err, "Request origin (securl host): "+origin.Description())
}
