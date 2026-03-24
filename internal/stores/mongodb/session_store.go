package mongodb

import (
    "context"
    "fmt"
    "time"

    "github.com/crydensync/cryden/internal/core"
    "go.mongodb.org/mongo-driver/bson"
    "go.mongodb.org/mongo-driver/mongo"
    "go.mongodb.org/mongo-driver/mongo/options"
)

// SessionStore implements core.SessionStore with MongoDB
type SessionStore struct {
    collection *mongo.Collection
}

// mongoSession represents a session in MongoDB
type mongoSession struct {
    ID           string    `bson:"_id"`
    UserID       string    `bson:"user_id"`
    RefreshToken string    `bson:"refresh_token"`  // bcrypt hash
    LookupHash   string    `bson:"lookup_hash"`    // SHA256 hash (UNIQUE)
    CreatedAt    time.Time `bson:"created_at"`
    ExpiresAt    time.Time `bson:"expires_at"`
}

// NewSessionStore creates a new MongoDB session store
func NewSessionStore(uri, dbName string) (*SessionStore, error) {
    client, err := mongo.Connect(context.Background(), options.Client().ApplyURI(uri))
    if err != nil {
        return nil, fmt.Errorf("failed to connect to MongoDB: %w", err)
    }

    if err := client.Ping(context.Background(), nil); err != nil {
        return nil, fmt.Errorf("failed to ping MongoDB: %w", err)
    }

    collection := client.Database(dbName).Collection("sessions")

    // Create unique index on lookup_hash for fast lookups
    lookupIndex := mongo.IndexModel{
        Keys:    bson.D{{Key: "lookup_hash", Value: 1}},
        Options: options.Index().SetUnique(true),
    }

    // Create index on user_id for listing sessions
    userIndex := mongo.IndexModel{
        Keys: bson.D{{Key: "user_id", Value: 1}},
    }

    // Create TTL index to auto-delete expired sessions
    ttlIndex := mongo.IndexModel{
        Keys:    bson.D{{Key: "expires_at", Value: 1}},
        Options: options.Index().SetExpireAfterSeconds(0),
    }

    _, err = collection.Indexes().CreateMany(context.Background(), []mongo.IndexModel{
        lookupIndex,
        userIndex,
        ttlIndex,
    })
    if err != nil {
        return nil, fmt.Errorf("failed to create indexes: %w", err)
    }

    return &SessionStore{collection: collection}, nil
}

// Create stores a new session with hashed tokens
func (s *SessionStore) Create(ctx context.Context, userID, refreshTokenHash, lookupHash string) (*core.Session, error) {
    session := mongoSession{
        ID:           fmt.Sprintf("sess_%d", time.Now().UnixNano()),
        UserID:       userID,
        RefreshToken: refreshTokenHash,
        LookupHash:   lookupHash,
        CreatedAt:    time.Now(),
        ExpiresAt:    time.Now().Add(7 * 24 * time.Hour),
    }

    _, err := s.collection.InsertOne(ctx, session)
    if err != nil {
        if mongo.IsDuplicateKeyError(err) {
            return nil, fmt.Errorf("lookup hash already exists: %w", err)
        }
        return nil, fmt.Errorf("failed to create session: %w", err)
    }

    return &core.Session{
        ID:           session.ID,
        UserID:       session.UserID,
        RefreshToken: session.RefreshToken,
        LookupHash:   session.LookupHash,
        CreatedAt:    session.CreatedAt,
        ExpiresAt:    session.ExpiresAt,
    }, nil
}

// GetByRefreshToken finds session using lookup hash
func (s *SessionStore) GetByRefreshToken(ctx context.Context, lookupHash string) (*core.Session, error) {
    var session mongoSession
    err := s.collection.FindOne(ctx, bson.M{
        "lookup_hash": lookupHash,
        "expires_at":  bson.M{"$gt": time.Now()},
    }).Decode(&session)

    if err == mongo.ErrNoDocuments {
        return nil, core.ErrSessionNotFound
    }
    if err != nil {
        return nil, fmt.Errorf("failed to get session: %w", err)
    }

    return &core.Session{
        ID:           session.ID,
        UserID:       session.UserID,
        RefreshToken: session.RefreshToken,
        LookupHash:   session.LookupHash,
        CreatedAt:    session.CreatedAt,
        ExpiresAt:    session.ExpiresAt,
    }, nil
}

// Revoke removes a specific session
func (s *SessionStore) Revoke(ctx context.Context, sessionID string) error {
    result, err := s.collection.DeleteOne(ctx, bson.M{"_id": sessionID})
    if err != nil {
        return fmt.Errorf("failed to revoke session: %w", err)
    }

    if result.DeletedCount == 0 {
        return core.ErrSessionNotFound
    }

    return nil
}

// RevokeAllForUser removes all sessions for a user
func (s *SessionStore) RevokeAllForUser(ctx context.Context, userID string) error {
    _, err := s.collection.DeleteMany(ctx, bson.M{"user_id": userID})
    if err != nil {
        return fmt.Errorf("failed to revoke all sessions: %w", err)
    }

    return nil
}

// ListForUser returns all active sessions for a user
func (s *SessionStore) ListForUser(ctx context.Context, userID string) ([]core.Session, error) {
    cursor, err := s.collection.Find(ctx, bson.M{
        "user_id":    userID,
        "expires_at": bson.M{"$gt": time.Now()},
    })
    if err != nil {
        return nil, fmt.Errorf("failed to list sessions: %w", err)
    }
    defer cursor.Close(ctx)

    var sessions []core.Session
    for cursor.Next(ctx) {
        var ms mongoSession
        if err := cursor.Decode(&ms); err != nil {
            return nil, fmt.Errorf("failed to decode session: %w", err)
        }

        // Don't expose lookup hash in list response
        sessions = append(sessions, core.Session{
            ID:           ms.ID,
            UserID:       ms.UserID,
            RefreshToken: ms.RefreshToken,
            LookupHash:   "", // Hide lookup hash
            CreatedAt:    ms.CreatedAt,
            ExpiresAt:    ms.ExpiresAt,
        })
    }

    return sessions, nil
}

// Close closes the MongoDB connection
func (s *SessionStore) Close() error {
    // Client is managed elsewhere
    return nil
}
