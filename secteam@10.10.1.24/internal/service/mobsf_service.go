package service

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type MobSFService struct{}

type MobSFFileInfo struct {
	Hash     string `json:"hash"`
	ScanType string `json:"scan_type"`
	FileName string `json:"file_name"`
}

func NewMobSFService() *MobSFService {
	return &MobSFService{}
}

func (s *MobSFService) mobsfBaseURL() string {
	base := strings.TrimSpace(os.Getenv("MOBSF_BASE_URL"))
	if base == "" {
		base = "http://localhost:8000"
	}
	return strings.TrimRight(base, "/")
}

func (s *MobSFService) mobsfAPIKey() string {
	return strings.TrimSpace(os.Getenv("MOBSF_API_KEY"))
}

func (s *MobSFService) debugEnabled() bool {
	v := strings.ToLower(strings.TrimSpace(os.Getenv("MOBSF_DEBUG")))
	return v == "1" || v == "true" || v == "yes" || v == "on"
}

func (s *MobSFService) logf(format string, args ...any) {
	if !s.debugEnabled() {
		return
	}
	log.Printf("[mobsf] "+format, args...)
}

func (s *MobSFService) setAuthHeaders(req *http.Request) {
	apiKey := s.mobsfAPIKey()
	if apiKey == "" {
		return
	}

	// MobSF supports API key auth. Some deployments behave unexpectedly if both
	// headers are present, so we default to the explicit MobSF header.
	mode := strings.ToLower(strings.TrimSpace(os.Getenv("MOBSF_AUTH_HEADER")))
	if mode == "authorization" {
		req.Header.Set("Authorization", apiKey)
		return
	}
	req.Header.Set("X-Mobsf-Api-Key", apiKey)
}

func (s *MobSFService) doJSONRequest(_ context.Context, req *http.Request) (map[string]interface{}, error) {
	start := time.Now()
	s.setAuthHeaders(req)

	if s.debugEnabled() {
		// Do not log API key values.
		mode := strings.ToLower(strings.TrimSpace(os.Getenv("MOBSF_AUTH_HEADER")))
		if mode == "" {
			mode = "x-mobsf-api-key"
		}
		s.logf("request %s %s ct=%q cl=%d auth=%s hasKey=%t", req.Method, req.URL.String(), req.Header.Get("Content-Type"), req.ContentLength, mode, s.mobsfAPIKey() != "")
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		s.logf("request error: %v", err)
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		s.logf("read body error: %v", err)
		return nil, err
	}

	if s.debugEnabled() {
		trim := strings.TrimSpace(string(body))
		if len(trim) > 800 {
			trim = trim[:800] + "…"
		}
		s.logf("response %s in %s body=%q", resp.Status, time.Since(start).Truncate(time.Millisecond), trim)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("mobsf api request failed: %s: %s", resp.Status, strings.TrimSpace(string(body)))
	}

	var out map[string]interface{}
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, fmt.Errorf("invalid mobsf json response: %w: %s", err, strings.TrimSpace(string(body)))
	}
	return out, nil
}

func (s *MobSFService) Upload(ctx context.Context, fileName string, file io.Reader) (MobSFFileInfo, map[string]interface{}, error) {
	baseURL := s.mobsfBaseURL()
	if s.debugEnabled() {
		s.logf("upload start base=%s fileName=%q", baseURL, fileName)
	}

	// Some MobSF deployments (or their reverse proxies) do not handle chunked
	// multipart uploads reliably. To maximize compatibility, we build the
	// multipart payload into a temp file so we can send a fixed Content-Length.
	tmpPath := filepath.Join(os.TempDir(), "napscan-mobsf-upload-"+randHex(8)+".multipart")
	tmp, err := os.OpenFile(tmpPath, os.O_CREATE|os.O_TRUNC|os.O_RDWR, 0600)
	if err != nil {
		return MobSFFileInfo{}, nil, err
	}
	defer func() {
		_ = tmp.Close()
		_ = os.Remove(tmpPath)
	}()

	mw := multipart.NewWriter(tmp)
	part, err := mw.CreateFormFile("file", fileName)
	if err != nil {
		_ = mw.Close()
		return MobSFFileInfo{}, nil, err
	}
	written, err := io.Copy(part, file)
	if err != nil {
		_ = mw.Close()
		return MobSFFileInfo{}, nil, err
	}
	if err := mw.Close(); err != nil {
		return MobSFFileInfo{}, nil, err
	}
	if s.debugEnabled() {
		s.logf("upload multipart built tmp=%s fileBytes=%d", tmpPath, written)
	}

	st, err := tmp.Stat()
	if err != nil {
		return MobSFFileInfo{}, nil, err
	}
	if s.debugEnabled() {
		s.logf("upload multipart size=%d", st.Size())
	}
	if _, err := tmp.Seek(0, 0); err != nil {
		return MobSFFileInfo{}, nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, baseURL+"/api/v1/upload", tmp)
	if err != nil {
		return MobSFFileInfo{}, nil, err
	}
	req.Header.Set("Content-Type", mw.FormDataContentType())
	req.ContentLength = st.Size()

	raw, err := s.doJSONRequest(ctx, req)
	if err != nil {
		return MobSFFileInfo{}, nil, err
	}

	info := MobSFFileInfo{
		Hash:     fmt.Sprint(raw["hash"]),
		ScanType: fmt.Sprint(raw["scan_type"]),
		FileName: fmt.Sprint(raw["file_name"]),
	}

	// Some MobSF versions might use different keys; try a couple fallbacks.
	if info.FileName == "" || info.FileName == "<nil>" {
		info.FileName = fmt.Sprint(raw["file"])
	}

	return info, raw, nil
}

func randHex(nBytes int) string {
	b := make([]byte, nBytes)
	if _, err := rand.Read(b); err != nil {
		// fallback: not security-sensitive; just avoid empty names
		return fmt.Sprintf("%d", time.Now().UnixNano())
	}
	const hexdigits = "0123456789abcdef"
	out := make([]byte, nBytes*2)
	for i, v := range b {
		out[i*2] = hexdigits[v>>4]
		out[i*2+1] = hexdigits[v&0x0f]
	}
	return string(out)
}

func (s *MobSFService) Scan(ctx context.Context, info MobSFFileInfo) (map[string]interface{}, error) {
	baseURL := s.mobsfBaseURL()

	form := url.Values{}
	if strings.TrimSpace(info.Hash) != "" {
		form.Set("hash", info.Hash)
	}
	if strings.TrimSpace(info.ScanType) != "" {
		form.Set("scan_type", info.ScanType)
	}
	if strings.TrimSpace(info.FileName) != "" {
		form.Set("file_name", info.FileName)
	}

	body := strings.NewReader(form.Encode())
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, baseURL+"/api/v1/scan", body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return s.doJSONRequest(ctx, req)
}

func (s *MobSFService) ReportJSON(ctx context.Context, info MobSFFileInfo) (map[string]interface{}, error) {
	baseURL := s.mobsfBaseURL()

	form := url.Values{}
	if strings.TrimSpace(info.Hash) != "" {
		form.Set("hash", info.Hash)
	}
	if strings.TrimSpace(info.ScanType) != "" {
		form.Set("scan_type", info.ScanType)
	}
	if strings.TrimSpace(info.FileName) != "" {
		form.Set("file_name", info.FileName)
	}

	body := strings.NewReader(form.Encode())
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, baseURL+"/api/v1/report_json", body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return s.doJSONRequest(ctx, req)
}

// Analyze is a convenience helper for: upload -> scan -> report_json.
func (s *MobSFService) Analyze(ctx context.Context, fileName string, file io.Reader) (MobSFFileInfo, map[string]interface{}, map[string]interface{}, map[string]interface{}, error) {
	info, uploadRaw, err := s.Upload(ctx, fileName, file)
	if err != nil {
		return MobSFFileInfo{}, nil, nil, nil, err
	}

	scanRaw, err := s.Scan(ctx, info)
	if err != nil {
		return info, uploadRaw, nil, nil, err
	}

	// Some MobSF setups might need a brief moment to build report.
	// We do a small retry window to avoid immediate "not found" type failures.
	var reportRaw map[string]interface{}
	var lastErr error
	for i := 0; i < 5; i++ {
		reportRaw, lastErr = s.ReportJSON(ctx, info)
		if lastErr == nil {
			break
		}
		t := time.Duration(i+1) * 500 * time.Millisecond
		select {
		case <-ctx.Done():
			return info, uploadRaw, scanRaw, nil, ctx.Err()
		case <-time.After(t):
		}
	}
	if lastErr != nil {
		return info, uploadRaw, scanRaw, nil, lastErr
	}

	return info, uploadRaw, scanRaw, reportRaw, nil
}
