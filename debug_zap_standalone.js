
// Mock of the extractAlerts function from zapParser.ts (JS version)
function extractAlerts(rawResult) {
    console.log("[ZapParser] extractAlerts input type:", typeof rawResult, Array.isArray(rawResult) ? "isArray" : "");

    if (Array.isArray(rawResult) && rawResult.length > 0) {
        if (rawResult[0]?.alertsRaw?.alerts) {
            console.log("[ZapParser] Detected new array format with alertsRaw.alerts");
            const allAlerts = [];
            rawResult.forEach(item => {
                if (item.alertsRaw?.alerts && Array.isArray(item.alertsRaw.alerts)) {
                    allAlerts.push(...item.alertsRaw.alerts);
                }
            });
            return allAlerts;
        }
        if (rawResult[0]?.alert || rawResult[0]?.alertRef) {
            console.log("[ZapParser] Detected direct alerts array");
            return rawResult;
        }
    }

    if (rawResult?.data?.alertsRaw?.alerts) {
        console.log("[ZapParser] Detected data.alertsRaw.alerts format");
        return rawResult.data.alertsRaw.alerts;
    }

    if (rawResult?.alertsRaw?.alerts) {
        console.log("[ZapParser] Detected alertsRaw.alerts format");
        return rawResult.alertsRaw.alerts;
    }

    if (Array.isArray(rawResult?.alertsRaw)) {
        console.log("[ZapParser] Detected alertsRaw array format");
        return rawResult.alertsRaw;
    }

    if (Array.isArray(rawResult?.alerts)) {
        console.log("[ZapParser] Detected alerts array format");
        return rawResult.alerts;
    }

    if (Array.isArray(rawResult)) {
        console.log("[ZapParser] Detected raw array format");
        return rawResult;
    }

    console.warn("[ZapParser] Could not extract alerts from result:", rawResult);
    return [];
}

const mockResult1 = {
    alertsRaw: {
        alerts: [
            { alert: "Test Alert 1", risk: "Start" }
        ]
    }
};

const mockResult2 = {
    data: {
        alertsRaw: {
            alerts: [
                { alert: "Test Alert 2", risk: "Start" }
            ]
        }
    }
};

const mockResultEmpty = {};

console.log("Testing Format 1 (alertsRaw.alerts):", extractAlerts(mockResult1).length);
console.log("Testing Format 2 (data.alertsRaw.alerts):", extractAlerts(mockResult2).length);
console.log("Testing Empty:", extractAlerts(mockResultEmpty).length);
