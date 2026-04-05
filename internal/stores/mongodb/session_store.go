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

type SessionStore struct {
    collection *mongo.Collection
}

type mongoSession struct {
    ID           string    `bson:"_id"`
    UserID       string    `bson:"user_id"`
    RefreshToken string    `bson:"refresh_token"`
    LookupHash   string    `bson:"lookup_hash"`
    CreatedAt    time.Time `bson:"created_at"`
    ExpiresAt    time.Time `bson:"expires_at"`
    LastSeenAt   time.Time `bson:"last_seen_at"`
    IPAddress    string    `bson:"ip_address,omitempty"`
    DeviceName   string    `bson:"device_name,omitempty"`
    DeviceType   string    `bson:"device_type,omitempty"`
    Browser      string    `bson:"browser,omitempty"`
    OS           string    `bson:"os,omitempty"`
}

func NewSessionStore(uri, dbName string) (*SessionStore, error) {
    client, err := mongo.Connect(context.Background(), options.Client().ApplyURI(uri))
    if err != nil {
        return nil, fmt.Errorf("failed to connect to MongoDB: %w", err)
    }

    if err := client.Ping(context.Background(), nil); err != nil {
        return nil, fmt.Errorf("failed to ping MongoDB: %w", err)
    }

    collection := client.Database(dbName).Collection("sessions")

    // Create indexes
    lookupIndex := mongo.IndexModel{
        Keys:    bson.D{{Key: "lookup_hash", Value: 1}},
        Options: options.Index().SetUnique(true),
    }

    userIndex := mongo.IndexModel{
        Keys: bson.D{{Key: "user_id", Value: 1}},
    }

    ttlIndex := mongo.IndexModel{
        Keys:    bson.D{{Key: "expires_at", Value: 1}},
        Options: options.Index().SetExpireAfterSeconds(0),
    }

    lastSeenIndex := mongo.IndexModel{
        Keys: bson.D{{Key: "last_seen_at", Value: -1}},
    }

    _, err = collection.Indexes().CreateMany(context.Background(), []mongo.IndexModel{
        lookupIndex,
        userIndex,
        ttlIndex,
        lastSeenIndex,
    })
    if err != nil {
        return nil, fmt.Errorf("failed to create indexes: %w", err)
    }

    return &SessionStore{collection: collection}, nil
}

// Create stores a new session with device info
func (s *SessionStore) Create(ctx context.Context, userID, refreshTokenHash, lookupHash string, device *core.DeviceInfo, ipAddress string) (*core.Session, error) {
    now := time.Now()
    
    session := mongoSession{
        ID:           fmt.Sprintf("sess_%d", now.UnixNano()),
        UserID:       userID,
        RefreshToken: refreshTokenHash,
        LookupHash:   lookupHash,
        CreatedAt:    now,
        ExpiresAt:    now.Add(7 * 24 * time.Hour),
        LastSeenAt:   now,
        IPAddress:    ipAddress,
    }

    if device != nil {
        session.DeviceName = device.DeviceName
        session.DeviceType = device.DeviceType
        session.Browser = device.Browser
        session.OS = device.OS
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
        LastSeenAt:   session.LastSeenAt,
        IPAddress:    session.IPAddress,
        DeviceName:   session.DeviceName,
        DeviceType:   session.DeviceType,
        Browser:      session.Browser,
        OS:           session.OS,
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
        LastSeenAt:   session.LastSeenAt,
        IPAddress:    session.IPAddress,
        DeviceName:   session.DeviceName,
        DeviceType:   session.DeviceType,
        Browser:      session.Browser,
        OS:           session.OS,
    }, nil
}

// UpdateLastSeen updates the last seen time for a session
func (s *SessionStore) UpdateLastSeen(ctx context.Context, sessionID string) error {
    result, err := s.collection.UpdateOne(
        ctx,
        bson.M{"_id": sessionID},
        bson.M{"$set": bson.M{"last_seen_at": time.Now()}},
    )
    if err != nil {
        return fmt.Errorf("failed to update last seen: %w", err)
    }

    if result.MatchedCount == 0 {
        return core.ErrSessionNotFound
    }

    return nil
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
    }, options.Find().SetSort(bson.M{"last_seen_at": -1}))
    
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

        sessions = append(sessions, core.Session{
            ID:           ms.ID,
            UserID:       ms.UserID,
            RefreshToken: ms.RefreshToken,
            LookupHash:   "",
            CreatedAt:    ms.CreatedAt,
            ExpiresAt:    ms.ExpiresAt,
            LastSeenAt:   ms.LastSeenAt,
            IPAddress:    ms.IPAddress,
            DeviceName:   ms.DeviceName,
            DeviceType:   ms.DeviceType,
            Browser:      ms.Browser,
            OS:           ms.OS,
        })
    }

    return sessions, nil
}

func (s *SessionStore) Close() error {
    return nil
}
