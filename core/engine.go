package core

import (
  "context"
	"fmt"
  "time"
)

// Engine is the main authentication engine
type Engine struct {
 users     UserStore
 sessions  SessionStore
 hasher    Hasher
 config    Config
}

// Config holds engine configuration
type Config struct {
    PasswordPolicy PasswordPolicy
    JWTSecret      string
    TokenExpiry    time.Duration
}

// New creates a new authentication engine
func New(users UserStore, sessions SessionStore) *Engine {
  return &Engine{
    users:    users,
    sessions: sessions,
		hasher: NewBcryptHasher(10),
    config: Config{
      PasswordPolicy: DefaultPasswordPolicy(),
      JWTSecret:      "change-this-in-production", // TODO: make configurable
      TokenExpiry:    15 * time.Minute,
    },
  }
}

func (e *Engine) WithHasher(hasher Hasher) *Engine {
    e.hasher = hasher
    return e
}

// SignUp creates a new user account
func (e *Engine) SignUp(ctx context.Context, email, password string) (*User, error) {
    // 1. Validate email
    if err := ValidateEmail(email); err != nil {
        return nil, err
    }
    
    // 2. Validate password
    if err := ValidatePassword(password, e.config.PasswordPolicy); err != nil {
        return nil, err
    }
    
    // 3. Check if user already exists
    existing, err := e.users.GetByEmail(ctx, email)
    if err != nil && err != ErrUserNotFound {
        return nil, err // Real error
    }
    if existing != nil {
        return nil, ErrUserExists
    }
    
    // 4. Hash password
   // hash, err := HashPassword(password)
	 hash, err := e.hasher.Hash(password)
    if err != nil {
        return nil, err
    }
    
    // 5. Create user
    user, err := e.users.Create(ctx, email, hash)
    if err != nil {
        return nil, err
    }
    
    return user, nil
}

// Login authenticates a user and returns tokens
func (e *Engine) Login(ctx context.Context, email, password string) (*TokenPair, error) {
    // 1. Find user
    user, err := e.users.GetByEmail(ctx, email)
    if err != nil {
        if err == ErrUserNotFound {
            return nil, ErrInvalidCredentials // Don't reveal user doesn't exist
        }
        return nil, err
    }

// 2. Check password - USE HASHER!
    if err := e.hasher.Compare(password, user.PasswordHash); err != nil {
        return nil, err
    }
    
    // 2. Check password
  //  if err := CheckPassword(password, user.PasswordHash); 
//	err != nil {
 //    return nil, ErrInvalidCredentials
//  }
    
    // 3. Create session
    session, err := e.sessions.Create(ctx, user.ID)
    if err != nil {
        return nil, err
    }
    
    // 4. Generate tokens (simplified for now)
    tokens := &TokenPair{
        AccessToken:  "jwt_" + generateID(),  // We'll make real JWT later
        RefreshToken: session.RefreshToken,
    }
    
    return tokens, nil
}

// Helper to generate IDs (move to a utils file later)
func generateID() string {
    return fmt.Sprintf("%d", time.Now().UnixNano())
}
