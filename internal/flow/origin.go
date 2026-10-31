package flow

import "github.com/LeafAI/securl/internal/notify"

func (f *Flow) Origin() notify.Origin {
	if f.m == nil {
		return notify.Origin{}
	}
	return f.m.cfg.Origin
}
