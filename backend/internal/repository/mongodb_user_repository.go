package repository

import (
	"context"
	"errors"
	"time"

	"napscan-be/internal/models"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

type MongoDBUserRepository struct {
	collection *mongo.Collection
}

func NewMongoDBUserRepository(db *mongo.Database) UserRepository {
	collection := db.Collection("users")
	
	// Create indexes for better performance
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	
	// Create unique index on email
	emailIndex := mongo.IndexModel{
		Keys:    bson.D{{Key: "email", Value: 1}},
		Options: options.Index().SetUnique(true),
	}
	
	// Create index on user ID
	idIndex := mongo.IndexModel{
		Keys: bson.D{{Key: "id", Value: 1}},
	}
	
	collection.Indexes().CreateMany(ctx, []mongo.IndexModel{emailIndex, idIndex})
	
	return &MongoDBUserRepository{
		collection: collection,
	}
}

func (r *MongoDBUserRepository) Upsert(ctx context.Context, user *models.User) error {
	if user == nil {
		return errors.New("user cannot be nil")
	}
	
	user.UpdatedAt = time.Now()
	if user.CreatedAt.IsZero() {
		user.CreatedAt = time.Now()
	}
	
	filter := bson.M{"id": user.ID}
	update := bson.M{
		"$set": bson.M{
			"email":      user.Email,
			"name":       user.Name,
			"picture":    user.Picture,
			"updated_at": user.UpdatedAt,
		},
		"$setOnInsert": bson.M{
			"id":         user.ID,
			"created_at": user.CreatedAt,
		},
	}
	
	opts := options.Update().SetUpsert(true)
	_, err := r.collection.UpdateOne(ctx, filter, update, opts)
	return err
}

func (r *MongoDBUserRepository) FindByID(ctx context.Context, id string) (*models.User, error) {
	var user models.User
	filter := bson.M{"id": id}
	
	err := r.collection.FindOne(ctx, filter).Decode(&user)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, errors.New("user not found")
		}
		return nil, err
	}
	
	return &user, nil
}

func (r *MongoDBUserRepository) FindByEmail(ctx context.Context, email string) (*models.User, error) {
	var user models.User
	filter := bson.M{"email": email}
	
	err := r.collection.FindOne(ctx, filter).Decode(&user)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, errors.New("user not found")
		}
		return nil, err
	}
	
	return &user, nil
}

func (r *MongoDBUserRepository) Delete(ctx context.Context, id string) error {
	filter := bson.M{"id": id}
	result, err := r.collection.DeleteOne(ctx, filter)
	if err != nil {
		return err
	}
	
	if result.DeletedCount == 0 {
		return errors.New("user not found")
	}
	
	return nil
}
