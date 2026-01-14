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

type MongoDBBatchRepository struct {
	collection *mongo.Collection
}

func NewMongoDBBatchRepository(db *mongo.Database) BatchRepository {
	collection := db.Collection("scan_batches")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	indexes := []mongo.IndexModel{
		{Keys: bson.D{{Key: "batch_id", Value: 1}}, Options: options.Index().SetUnique(true)},
		{Keys: bson.D{{Key: "user_id", Value: 1}}},
		{Keys: bson.D{{Key: "created_at", Value: -1}}},
	}
	_, _ = collection.Indexes().CreateMany(ctx, indexes)

	return &MongoDBBatchRepository{collection: collection}
}

func (r *MongoDBBatchRepository) Create(ctx context.Context, batch *models.Batch) error {
	if batch == nil {
		return errors.New("batch cannot be nil")
	}
	batch.CreatedAt = time.Now()
	_, err := r.collection.InsertOne(ctx, batch)
	return err
}

func (r *MongoDBBatchRepository) FindByID(ctx context.Context, batchID string) (*models.Batch, error) {
	var batch models.Batch
	err := r.collection.FindOne(ctx, bson.M{"batch_id": batchID}).Decode(&batch)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, nil // Not found is not an error here
		}
		return nil, err
	}
	return &batch, nil
}

func (r *MongoDBBatchRepository) FindBatchesByUserID(ctx context.Context, userID string) ([]*models.Batch, error) {
	cursor, err := r.collection.Find(ctx, bson.M{"user_id": userID}, options.Find().SetSort(bson.D{{"created_at", -1}}))
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)

	var batches []*models.Batch
	if err = cursor.All(ctx, &batches); err != nil {
		return nil, err
	}
	return batches, nil
}
