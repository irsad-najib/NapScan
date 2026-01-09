package models

import "time"

// BatchStatus indicates the progress of the batch
type BatchStatus string

const (
	BatchStatusProcessing BatchStatus = "processing"
	BatchStatusComplete   BatchStatus = "complete"
)

// Batch represents the aggregated state of multiple API requests
type Batch struct {
	UserID         string                 `json:"user_id"`
	BatchID        string                 `json:"batch_id"`
	ExpectedCount  int                    `json:"expected_count"`
	ReceivedCount  int                    `json:"received_count"`
	Results        map[string]interface{} `json:"results"`
	Status         BatchStatus            `json:"status"`
	AnalysisResult interface{}            `json:"analysis_result,omitempty"`
	CreatedAt      time.Time              `json:"created_at"`
}

// BatchRequest represents the input for fan-in endpoints
type BatchRequest struct {
	Data string `json:"data"`
}

// BatchResponse returns the status of an analysis
type BatchResponse struct {
	Status         BatchStatus `json:"status"`
	AnalysisResult interface{} `json:"result,omitempty"`
	BatchID        string      `json:"batch_id"`
}
