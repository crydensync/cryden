package tests

import (
    "testing"
    "github.com/raymondproguy/credensync/core"
)

func TestBcryptHasher(t *testing.T) {
    hasher := core.NewBcryptHasher(4)

    t.Run("hash and compare", func(t *testing.T) {
        password := "Test123"
        
        hash, err := hasher.Hash(password)
        if err != nil {
            t.Fatalf("Hash failed: %v", err)
        }
        
        err = hasher.Compare(password, hash)
        if err != nil {
            t.Errorf("Compare failed: %v", err)
        }
    })

    t.Run("wrong password fails", func(t *testing.T) {
        hash, _ := hasher.Hash("correct")
        
        err := hasher.Compare("wrong", hash)
        if err == nil {
            t.Error("Expected error, got nil")
        }
    })
}

func TestMockHasher(t *testing.T) {
    hasher := &core.MockHasher{}

    t.Run("mock hash returns password", func(t *testing.T) {
        hash, _ := hasher.Hash("test")
        if hash != "test" {
            t.Errorf("Expected 'test', got '%s'", hash)
        }
    })

    t.Run("mock compare works", func(t *testing.T) {
        err := hasher.Compare("test", "test")
        if err != nil {
            t.Errorf("Compare failed: %v", err)
        }
    })
}
