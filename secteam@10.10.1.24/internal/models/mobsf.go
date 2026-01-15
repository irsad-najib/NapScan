package models

// MobSFScanRequest is the request payload for starting a MobSF analysis
// using a file that was already uploaded to MobSF (referenced by hash).
//
// swagger:model
type MobSFScanRequest struct {
	Hash     string `json:"hash" example:"0123456789abcdef0123456789abcdef"`
	ScanType string `json:"scan_type,omitempty" example:"apk"`
	FileName string `json:"file_name,omitempty" example:"app.apk"`
	BatchID  string `json:"batch_id" example:"550e8400-e29b-41d4-a716-446655440000"`
}
