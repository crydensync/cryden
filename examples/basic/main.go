package main

import (
	"context"
	"fmt"
	"log"

	"github.com/crydensync/cryden"
)

func main() {
	// Create engine
	engine := cryden.New()
	ctx := context.Background()

	// Sign up
	user, err := engine.SignUp(ctx, "test@example.com", "Password123")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("User created: %s\n", user.ID)

	// Login
	tokens, _, err := engine.Login(ctx, "test@example.com", "Password123")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Access token: %s\n", tokens.AccessToken)
}
