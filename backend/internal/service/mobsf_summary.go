package service

import (
	"fmt"
	"sort"
	"strings"
)

// BuildMobSFSummary creates a comprehensive summary of the MobSF scan report.
// It accepts scan and report maps and returns a map suitable for JSON output.
func BuildMobSFSummary(info MobSFFileInfo, scanRaw, reportRaw map[string]interface{}) map[string]interface{} {
	asString := func(v interface{}) string {
		if v == nil {
			return ""
		}
		switch t := v.(type) {
		case string:
			return strings.TrimSpace(t)
		case float64:
			// JSON numbers decode as float64. Render without trailing .0 when possible.
			if t == float64(int64(t)) {
				return fmt.Sprintf("%d", int64(t))
			}
			return fmt.Sprintf("%v", t)
		case bool:
			if t {
				return "true"
			}
			return "false"
		default:
			return strings.TrimSpace(fmt.Sprint(v))
		}
	}
	getStr := func(m map[string]interface{}, key string) string {
		if m == nil {
			return ""
		}
		v, ok := m[key]
		if !ok {
			return ""
		}
		return asString(v)
	}
	asMap := func(v interface{}) map[string]interface{} {
		if v == nil {
			return nil
		}
		m, _ := v.(map[string]interface{})
		return m
	}
	asSlice := func(v interface{}) []interface{} {
		if v == nil {
			return nil
		}
		s, _ := v.([]interface{})
		return s
	}
	truncate := func(s string, max int) string {
		s = strings.TrimSpace(s)
		if max <= 0 {
			return ""
		}
		if len(s) <= max {
			return s
		}
		// keep a tiny suffix room for ellipsis
		if max <= 3 {
			return s[:max]
		}
		return s[:max-3] + "..."
	}
	uniqueStrings := func(in []string) []string {
		seen := make(map[string]struct{}, len(in))
		out := make([]string, 0, len(in))
		for _, s := range in {
			s = strings.TrimSpace(s)
			if s == "" {
				continue
			}
			if _, ok := seen[s]; ok {
				continue
			}
			seen[s] = struct{}{}
			out = append(out, s)
		}
		sort.Strings(out)
		return out
	}

	// Prefer report_json fields as they tend to be richer.
	md5 := getStr(reportRaw, "md5")
	sha1 := getStr(reportRaw, "sha1")
	sha256 := getStr(reportRaw, "sha256")
	if md5 == "" {
		md5 = getStr(scanRaw, "md5")
	}
	if sha1 == "" {
		sha1 = getStr(scanRaw, "sha1")
	}
	if sha256 == "" {
		sha256 = getStr(scanRaw, "sha256")
	}

	// --- Permissions ---
	permStatusCounts := make(map[string]interface{})
	dangerousPerms := make([]map[string]interface{}, 0)
	permissions := asMap(reportRaw["permissions"])
	if permissions != nil {
		for permName, raw := range permissions {
			p := asMap(raw)
			status := strings.ToLower(getStr(p, "status"))
			if status == "" {
				status = "unknown"
			}
			prev, ok := permStatusCounts[status]
			if !ok {
				permStatusCounts[status] = 1
			} else {
				// counts are integers; keep as int for JSON encoder.
				permStatusCounts[status] = prev.(int) + 1
			}
			if status == "dangerous" {
				dangerousPerms = append(dangerousPerms, map[string]interface{}{
					"permission":   permName,
					"info":         truncate(getStr(p, "info"), 200),
					"description":  truncate(getStr(p, "description"), 300),
					"protection":   status,
				})
			}
		}
		sort.Slice(dangerousPerms, func(i, j int) bool {
			return asString(dangerousPerms[i]["permission"]) < asString(dangerousPerms[j]["permission"])
		})
		if len(dangerousPerms) > 25 {
			dangerousPerms = dangerousPerms[:25]
		}
	}

	// --- AppSec (findings by severity) ---
	appsec := asMap(reportRaw["appsec"])
	getFindingList := func(section string, maxItems int) ([]map[string]interface{}, int) {
		items := make([]map[string]interface{}, 0)
		s := asSlice(appsec[section])
		for _, raw := range s {
			m := asMap(raw)
			if m == nil {
				continue
			}
			items = append(items, map[string]interface{}{
				"title":       truncate(getStr(m, "title"), 180),
				"section":     truncate(getStr(m, "section"), 60),
				"description": truncate(getStr(m, "description"), 400),
			})
			if maxItems > 0 && len(items) >= maxItems {
				break
			}
		}
		return items, len(s)
	}
	highItems, highTotal := getFindingList("high", 10)
	warningItems, warningTotal := getFindingList("warning", 10)
	hotspotItems, hotspotTotal := getFindingList("hotspot", 10)
	infoItems, infoTotal := getFindingList("info", 10)
	secureItems, secureTotal := getFindingList("secure", 10)

	// --- Manifest findings ---
	manifest := asMap(reportRaw["manifest_analysis"])
	manifestSummary := asMap(manifest["manifest_summary"])
	manifestFindingsOut := make([]map[string]interface{}, 0)
	manifestFindings := asSlice(manifest["manifest_findings"])
	for _, raw := range manifestFindings {
		m := asMap(raw)
		if m == nil {
			continue
		}
		manifestFindingsOut = append(manifestFindingsOut, map[string]interface{}{
			"severity":    strings.ToLower(getStr(m, "severity")),
			"rule":        truncate(getStr(m, "rule"), 80),
			"title":       truncate(getStr(m, "title"), 180),
			"description": truncate(getStr(m, "description"), 400),
		})
		if len(manifestFindingsOut) >= 10 {
			break
		}
	}

	// --- Certificate findings ---
	cert := asMap(reportRaw["certificate_analysis"])
	certSummary := asMap(cert["certificate_summary"])
	certFindings := asSlice(cert["certificate_findings"])
	certFindingsOut := make([]map[string]interface{}, 0)
	for _, raw := range certFindings {
		row := asSlice(raw)
		if len(row) < 3 {
			continue
		}
		certFindingsOut = append(certFindingsOut, map[string]interface{}{
			"severity":     strings.ToLower(asString(row[0])),
			"title":        truncate(asString(row[1]), 180),
			"description":  truncate(asString(row[2]), 400),
		})
		if len(certFindingsOut) >= 10 {
			break
		}
	}

	// --- Trackers ---
	trackers := asMap(reportRaw["trackers"])
	trackerNames := make([]string, 0)
	trackerList := asSlice(trackers["trackers"])
	for _, raw := range trackerList {
		m := asMap(raw)
		if m != nil {
			name := getStr(m, "name")
			if name != "" {
				trackerNames = append(trackerNames, name)
				continue
			}
		}
		if s, ok := raw.(string); ok {
			trackerNames = append(trackerNames, s)
		}
	}
	trackerNames = uniqueStrings(trackerNames)
	if len(trackerNames) > 30 {
		trackerNames = trackerNames[:30]
	}

	// --- URLs & Domains ---
	urlEntries := asSlice(reportRaw["urls"])
	flatURLs := make([]string, 0)
	for _, raw := range urlEntries {
		m := asMap(raw)
		if m == nil {
			continue
		}
		urls := asSlice(m["urls"])
		for _, u := range urls {
			flatURLs = append(flatURLs, asString(u))
		}
	}
	flatURLs = uniqueStrings(flatURLs)
	urlSample := flatURLs
	if len(urlSample) > 30 {
		urlSample = urlSample[:30]
	}

	domains := asMap(reportRaw["domains"])
	domainNames := make([]string, 0, len(domains))
	suspiciousDomains := make([]map[string]interface{}, 0)
	for domain, raw := range domains {
		domainNames = append(domainNames, domain)
		m := asMap(raw)
		if m == nil {
			continue
		}
		bad := strings.ToLower(getStr(m, "bad"))
		of := m["ofac"]
		ofStr := strings.ToLower(asString(of))
		if bad == "yes" || ofStr == "true" {
			suspiciousDomains = append(suspiciousDomains, map[string]interface{}{
				"domain": domain,
				"bad":    bad,
				"ofac":   ofStr == "true",
			})
		}
	}
	sort.Strings(domainNames)
	if len(domainNames) > 50 {
		domainNames = domainNames[:50]
	}
	if len(suspiciousDomains) > 30 {
		suspiciousDomains = suspiciousDomains[:30]
	}

	// --- Secrets ---
	secretsRaw := asSlice(reportRaw["secrets"])
	secrets := make([]string, 0)
	for _, s := range secretsRaw {
		secrets = append(secrets, truncate(asString(s), 120))
	}
	secrets = uniqueStrings(secrets)
	secretSample := secrets
	if len(secretSample) > 30 {
		secretSample = secretSample[:30]
	}

	// --- Small metadata ---
	exportedCount := asMap(reportRaw["exported_count"])
	activities := asSlice(reportRaw["activities"])
	services := asSlice(reportRaw["services"])
	receivers := asSlice(reportRaw["receivers"])
	providers := asSlice(reportRaw["providers"])

	return map[string]interface{}{
		"hash": info.Hash,
		"identity": map[string]interface{}{
			"app_name":      getStr(reportRaw, "app_name"),
			"package_name":  getStr(reportRaw, "package_name"),
			"file_name":     getStr(reportRaw, "file_name"),
			"version_name":  getStr(reportRaw, "version_name"),
			"main_activity": getStr(reportRaw, "main_activity"),
			"icon_path":     getStr(reportRaw, "icon_path"),
			"timestamp":     getStr(reportRaw, "timestamp"),
		},
		"hashes": map[string]interface{}{
			"md5":    md5,
			"sha1":   sha1,
			"sha256": sha256,
		},
		"sdk": map[string]interface{}{
			"min_sdk":    getStr(reportRaw, "min_sdk"),
			"target_sdk": getStr(reportRaw, "target_sdk"),
			"max_sdk":    getStr(reportRaw, "max_sdk"),
		},
		"components": map[string]interface{}{
			"activities":     len(activities),
			"services":       len(services),
			"receivers":      len(receivers),
			"providers":      len(providers),
			"exported_count": exportedCount,
		},
		"permissions": map[string]interface{}{
			"status_counts":    permStatusCounts,
			"dangerous_sample": dangerousPerms,
		},
		"findings": map[string]interface{}{
			"security_score": getStr(appsec, "security_score"),
			"totals": map[string]interface{}{
				"high":    highTotal,
				"warning": warningTotal,
				"hotspot": hotspotTotal,
				"info":    infoTotal,
				"secure":  secureTotal,
			},
			"high":    highItems,
			"warning": warningItems,
			"hotspot": hotspotItems,
			"info":    infoItems,
			"secure":  secureItems,
		},
		"manifest": map[string]interface{}{
			"summary":  manifestSummary,
			"findings": manifestFindingsOut,
		},
		"certificate": map[string]interface{}{
			"summary":  certSummary,
			"findings": certFindingsOut,
		},
		"network": map[string]interface{}{
			"urls_total":         len(flatURLs),
			"urls_sample":        urlSample,
			"domains_total":      len(domains),
			"domains_sample":     domainNames,
			"suspicious_domains": suspiciousDomains,
		},
		"trackers": map[string]interface{}{
			"detected_trackers": trackers["detected_trackers"],
			"total_trackers":    trackers["total_trackers"],
			"trackers_sample":   trackerNames,
		},
		"secrets": map[string]interface{}{
			"total":  len(secrets),
			"sample": secretSample,
		},
		"meta": map[string]interface{}{
			"mobsf_version": getStr(reportRaw, "version"),
			"has_scan":      scanRaw != nil,
			"has_report":    reportRaw != nil,
		},
	}
}
