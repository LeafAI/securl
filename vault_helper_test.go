package main

import "github.com/LeafAI/securl/internal/vault"

// makeVault creates a vault with a cheap key derivation, for tests that need one to exist and be locked.
func makeVault(dir, pass string) error {
	v := vault.NewWithCost(dir, 1, 8, 1)
	if err := v.Init(pass); err != nil {
		return err
	}
	v.Lock()
	return nil
}
