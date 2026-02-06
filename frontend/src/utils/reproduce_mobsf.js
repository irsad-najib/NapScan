
const { parseMobsfResults } = require('./toolParsers');

// Mock console.log/error to keep output clean, or let it print to see parser logs
// console.log = () => {};
// console.error = () => {};

const mockPayload = {
    "id": 6,
    "tool": "mobsf",
    "target": "ayolari-dummy-app-staging-2.1.3-build-260113.apk",
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

console.log("Testing parseMobsfResults with provided payload...");
try {
    const vulnerabilities = parseMobsfResults(mockPayload);
    console.log(`Found ${vulnerabilities.length} vulnerabilities.`);

    if (vulnerabilities.length === 0) {
        console.error("FAIL: No vulnerabilities found. Parser failed to extract data.");
    } else {
        console.log("SUCCESS: Vulnerabilities extracted.");
        vulnerabilities.forEach(v => console.log(`- [${v.severity}] ${v.name}`));
    }
} catch (error) {
    console.error("CRASH: Parser threw an exception:", error);
}
