package destination

import (
	"fmt"
	"sort"
	"sync"
)

// Factory builds a Destination from a name and raw config map.
type Factory func(name string, rawConfig map[string]any) (Destination, error)

var (
	regMu sync.RWMutex
	reg   = map[string]Factory{}
)

// Register associates a type name with a Factory. Intended to be called
// from package init() functions.
func Register(typeName string, f Factory) {
	regMu.Lock()
	defer regMu.Unlock()
	reg[typeName] = f
}

// Create instantiates a Destination by type name.
func Create(typeName, name string, rawConfig map[string]any) (Destination, error) {
	regMu.RLock()
	f, ok := reg[typeName]
	regMu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrUnknownType, typeName)
	}
	return f(name, rawConfig)
}

// ListTypes returns the sorted list of registered type names.
func ListTypes() []string {
	regMu.RLock()
	defer regMu.RUnlock()
	out := make([]string, 0, len(reg))
	for k := range reg {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
