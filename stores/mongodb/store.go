// stores/mongodb/store.go
package mongodb

import (
	"context"
	"fmt"
	"time"

	"github.com/raymondproguy/credensync/core"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

type UserStore struct {
	collection *mongo.Collection
}

type mongoUser struct {
	ID           string    `bson:"_id"`
	Email        string    `bson:"email"`
	PasswordHash string    `bson:"password_hash"`
	CreatedAt    time.Time `bson:"created_at"`
	UpdatedAt    time.Time `bson:"updated_at"`
}

func NewUserStore(uri, dbName string) (*UserStore, error) {
	client, err := mongo.Connect(context.Background(), options.Client().ApplyURI(uri))
	if err != nil {
		return nil, fmt.Errorf("failed to connect to MongoDB: %w", err)
	}

	if err := client.Ping(context.Background(), nil); err != nil {
		return nil, fmt.Errorf("failed to ping MongoDB: %w", err)
	}

	collection := client.Database(dbName).Collection("users")

	// Create unique index on email
	indexModel := mongo.IndexModel{
		Keys:    bson.D{{Key: "email", Value: 1}},
		Options: options.Index().SetUnique(true),
	}

	_, err = collection.Indexes().CreateOne(context.Background(), indexModel)
	if err != nil {
		return nil, fmt.Errorf("failed to create index: %w", err)
	}

	return &UserStore{collection: collection}, nil
}

func (s *UserStore) Create(ctx context.Context, email, passwordHash string) (*core.User, error) {
	now := time.Now()
	user := mongoUser{
		ID:           fmt.Sprintf("usr_%d", time.Now().UnixNano()),
		Email:        email,
		PasswordHash: passwordHash,
		CreatedAt:    now,
		UpdatedAt:    now,
	}

	_, err := s.collection.InsertOne(ctx, user)
	if err != nil {
		if mongo.IsDuplicateKeyError(err) {
			return nil, core.ErrUserExists
		}
		return nil, fmt.Errorf("failed to create user: %w", err)
	}

	return &core.User{
		ID:           user.ID,
		Email:        user.Email,
		PasswordHash: user.PasswordHash,
		CreatedAt:    user.CreatedAt,
		UpdatedAt:    user.UpdatedAt,
	}, nil
}

func (s *UserStore) GetByEmail(ctx context.Context, email string) (*core.User, error) {
	var user mongoUser
	err := s.collection.FindOne(ctx, bson.M{"email": email}).Decode(&user)

	if err == mongo.ErrNoDocuments {
		return nil, core.ErrUserNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get user: %w", err)
	}

	return &core.User{
		ID:           user.ID,
		Email:        user.Email,
		PasswordHash: user.PasswordHash,
		CreatedAt:    user.CreatedAt,
		UpdatedAt:    user.UpdatedAt,
	}, nil
}

func (s *UserStore) GetByID(ctx context.Context, id string) (*core.User, error) {
	var user mongoUser
	err := s.collection.FindOne(ctx, bson.M{"_id": id}).Decode(&user)

	if err == mongo.ErrNoDocuments {
		return nil, core.ErrUserNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get user: %w", err)
	}

	return &core.User{
		ID:           user.ID,
		Email:        user.Email,
		PasswordHash: user.PasswordHash,
		CreatedAt:    user.CreatedAt,
		UpdatedAt:    user.UpdatedAt,
	}, nil
}

func (s *UserStore) UpdateEmail(ctx context.Context, id, newEmail string) error {
	result, err := s.collection.UpdateOne(
		ctx,
		bson.M{"_id": id},
		bson.M{"$set": bson.M{"email": newEmail, "updated_at": time.Now()}},
	)

	if err != nil {
		if mongo.IsDuplicateKeyError(err) {
			return core.ErrUserExists
		}
		return fmt.Errorf("failed to update email: %w", err)
	}

	if result.MatchedCount == 0 {
		return core.ErrUserNotFound
	}

	return nil
}

func (s *UserStore) UpdatePassword(ctx context.Context, id, newPasswordHash string) error {
	result, err := s.collection.UpdateOne(
		ctx,
		bson.M{"_id": id},
		bson.M{"$set": bson.M{"password_hash": newPasswordHash, "updated_at": time.Now()}},
	)

	if err != nil {
		return fmt.Errorf("failed to update password: %w", err)
	}

	if result.MatchedCount == 0 {
		return core.ErrUserNotFound
	}

	return nil
}

func (s *UserStore) Delete(ctx context.Context, id string) error {
	result, err := s.collection.DeleteOne(ctx, bson.M{"_id": id})

	if err != nil {
		return fmt.Errorf("failed to delete user: %w", err)
	}

	if result.DeletedCount == 0 {
		return core.ErrUserNotFound
	}

	return nil
}

func (s *UserStore) Close() error {
	// MongoDB client is managed elsewhere
	return nil
}
