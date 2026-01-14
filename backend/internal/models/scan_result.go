package models

import (
	"time"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

// ScanResult stores the raw output of a tool scan.
// MongoDB equivalent of a SQL table is a "collection".
// This struct maps to the "scan_results" collection.
type ScanResult struct {
	ID        primitive.ObjectID `json:"id" bson:"_id,omitempty"`
	BatchID   string             `json:"batch_id" bson:"batch_id"`
	Tool      string             `json:"tool" bson:"tool"`
	Target    string             `json:"target" bson:"target"`
	Result    interface{}        `json:"result" bson:"result"`
	CreatedAt time.Time          `json:"created_at" bson:"created_at"`
}
