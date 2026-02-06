
// Self-contained verification script with the fixed logic

// Mock function representing the fixed parseMobsfResults
function parseMobsfResults(rawResult) {
    const vulnerabilities = [];
    const data = rawResult?.data || rawResult;

    const mapSeverity = (mobsfSeverity) => {
        const sev = (mobsfSeverity || "info").toLowerCase();
        if (sev === "critical" || sev === "danger") return "Critical";
        if (sev === "high") return "High";
        if (sev === "warning" || sev === "medium") return "Medium";
        if (sev === "low") return "Low";
        return "Info";
    };

    // --- Format 1: findings.mobsf structure (new combined scan response) ---
    // THE FIX: Added rawResult?.result?.mobsf
    const mobsfData = rawResult?.findings?.mobsf || data?.findings?.mobsf || rawResult?.result?.mobsf;

    if (mobsfData) {
        console.log("[MobSF Parser] Found findings.mobsf structure, parsing...");

        // Parse certificate findings
        const certificate = mobsfData?.certificate;
        if (certificate?.findings && Array.isArray(certificate.findings)) {
            certificate.findings.forEach((finding) => {
                vulnerabilities.push({
                    name: finding.title || "Certificate Issue",
                    severity: mapSeverity(finding.severity),
                    tool: "mobsf",
                });
            });
        }

        // Parse manifest findings
        const manifest = mobsfData?.manifest;
        if (manifest?.findings && Array.isArray(manifest.findings)) {
            manifest.findings.forEach((finding) => {
                vulnerabilities.push({
                    name: finding.title || "Manifest Issue",
                    severity: mapSeverity(finding.severity),
                    tool: "mobsf",
                });
            });
        }
    }

    return vulnerabilities;
}

const mockPayload = {
    "id": 6,
    "tool": "mobsf",
    "target": "ayolari-dummy-app-staging.apk",
    "result": {
        "mobsf": {
            "certificate": {
                "findings": [
                    {
                        "description": "Signed Application",
                        "severity": "info",
                        "title": "Application is signed with a code signing certificate"
                    }
                ]
            },
            "manifest": {
                "findings": [
                    {
                        "description": "Debug Enabled",
                        "severity": "high",
                        "title": "Debug Enabled For App"
                    }
                ]
            }
        }
    }
};

console.log("Verifying fix with corrected logic...");
try {
    const vulns = parseMobsfResults(mockPayload);
    console.log(`Found ${vulns.length} vulnerabilities.`);
    if (vulns.length > 0) {
        console.log("SUCCESS: Fix works! Findings extracted:");
        vulns.forEach(v => console.log(`- [${v.severity}] ${v.name}`));
    } else {
        console.error("FAIL: Still no vulnerabilities found.");
    }
} catch (e) {
    console.error("ERROR:", e);
}
