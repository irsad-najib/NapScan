package repository

import (
	"context"
	"errors"
	"time"

	"napscan-be/internal/models"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

type MongoDBScanResultRepository struct {
	collection *mongo.Collection
}

func NewMongoDBScanResultRepository(db *mongo.Database) ScanResultRepository {
	collection := db.Collection("scan_results")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	indexes := []mongo.IndexModel{
		{Keys: bson.D{{Key: "batch_id", Value: 1}}},
		{Keys: bson.D{{Key: "tool", Value: 1}}},
		{Keys: bson.D{{Key: "created_at", Value: -1}}},
		{Keys: bson.D{{Key: "batch_id", Value: 1}, {Key: "tool", Value: 1}}},
	}

	_, _ = collection.Indexes().CreateMany(ctx, indexes, options.CreateIndexes())

	return &MongoDBScanResultRepository{collection: collection}
}

func (r *MongoDBScanResultRepository) Insert(ctx context.Context, scan *models.ScanResult) (primitive.ObjectID, error) {
	if scan == nil {
		return primitive.NilObjectID, errors.New("scan result cannot be nil")
	}
	if scan.BatchID == "" {
		return primitive.NilObjectID, errors.New("batch_id is required")
	}
	if scan.Tool == "" {
		return primitive.NilObjectID, errors.New("tool is required")
	}
	if scan.Target == "" {
		return primitive.NilObjectID, errors.New("target is required")
	}
	if scan.CreatedAt.IsZero() {
		scan.CreatedAt = time.Now().UTC()
	}

	res, err := r.collection.InsertOne(ctx, scan)
	if err != nil {
		return primitive.NilObjectID, err
	}

	id, ok := res.InsertedID.(primitive.ObjectID)
	if !ok {
		return primitive.NilObjectID, errors.New("unexpected inserted id type")
	}
	return id, nil
}
