package scanner

import (
	"fmt"
	"sync"
)

// DefaultRegistry is a thread-safe implementation of ScannerRegistry
type DefaultRegistry struct {
	mu       sync.RWMutex
	scanners map[string]Scanner
}

// NewRegistry creates a new scanner registry
func NewRegistry() *DefaultRegistry {
	return &DefaultRegistry{
		scanners: make(map[string]Scanner),
	}
}

// Register adds a scanner to the registry
func (r *DefaultRegistry) Register(scanner Scanner) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	
	name := scanner.Name()
	if name == "" {
		return fmt.Errorf("scanner name cannot be empty")
	}
	
	if _, exists := r.scanners[name]; exists {
		return fmt.Errorf("scanner %s already registered", name)
	}
	
	r.scanners[name] = scanner
	return nil
}

// Get retrieves a scanner by name
func (r *DefaultRegistry) Get(name string) (Scanner, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	
	scanner, exists := r.scanners[name]
	if !exists {
		return nil, fmt.Errorf("scanner %s not found", name)
	}
	
	return scanner, nil
}

// List returns all registered scanner names
func (r *DefaultRegistry) List() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	
	names := make([]string, 0, len(r.scanners))
	for name := range r.scanners {
		names = append(names, name)
	}
	
	return names
}

// ValidateAll checks if all scanners are properly configured
func (r *DefaultRegistry) ValidateAll() map[string]error {
	r.mu.RLock()
	defer r.mu.RUnlock()
	
	results := make(map[string]error)
	for name, scanner := range r.scanners {
		if err := scanner.Validate(); err != nil {
			results[name] = err
		}
	}
	
	return results
}

// MustRegister registers a scanner and panics on error
// Useful for initialization in init() functions
func (r *DefaultRegistry) MustRegister(scanner Scanner) {
	if err := r.Register(scanner); err != nil {
		panic(fmt.Sprintf("failed to register scanner: %v", err))
	}
}
