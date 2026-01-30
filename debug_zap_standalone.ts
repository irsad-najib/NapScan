
// Mock of the extractAlerts function from zapParser.ts
function extractAlerts(rawResult: any): any[] {
    console.log("[ZapParser] extractAlerts input type:", typeof rawResult, Array.isArray(rawResult) ? "isArray" : "");

    // Format 0: New async format - Array at top level containing objects with alertsRaw
    // [{ active: {...}, alertsRaw: { alerts: [...] } }]
    if (Array.isArray(rawResult) && rawResult.length > 0) {
        // Check if first item has alertsRaw.alerts (Format 0)
        if (rawResult[0]?.alertsRaw?.alerts) {
            console.log("[ZapParser] Detected new array format with alertsRaw.alerts");
            // Flatten all alerts from all items in the array
            const allAlerts: any[] = [];
            rawResult.forEach(item => {
                if (item.alertsRaw?.alerts && Array.isArray(item.alertsRaw.alerts)) {
                    allAlerts.push(...item.alertsRaw.alerts);
                }
            });
            return allAlerts;
        }
        // Check if array items are direct ZapAlert objects
        if (rawResult[0]?.alert || rawResult[0]?.alertRef) {
            console.log("[ZapParser] Detected direct alerts array");
            return rawResult;
        }
    }

    // Format 1: Full API response with data wrapper
    // { success: true, data: { alertsRaw: { alerts: [...] } } }
    if (rawResult?.data?.alertsRaw?.alerts) {
        console.log("[ZapParser] Detected data.alertsRaw.alerts format");
        return rawResult.data.alertsRaw.alerts;
    }

    // Format 2: Direct data object (after unwrapping)
    // { alertsRaw: { alerts: [...] } }
    if (rawResult?.alertsRaw?.alerts) {
        console.log("[ZapParser] Detected alertsRaw.alerts format");
        return rawResult.alertsRaw.alerts;
    }

    // Format 3: Direct alerts array in alertsRaw
    // { alertsRaw: [...] }
    if (Array.isArray(rawResult?.alertsRaw)) {
        console.log("[ZapParser] Detected alertsRaw array format");
        return rawResult.alertsRaw;
    }

    // Format 4: Direct alerts array
    // { alerts: [...] }
    if (Array.isArray(rawResult?.alerts)) {
        console.log("[ZapParser] Detected alerts array format");
        return rawResult.alerts;
    }

    // Format 5: Raw array of alerts
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

// Cases that might fail
const mockResultEmpty = {};
const mockResultNull = null;

console.log("Testing Format 1 (alertsRaw.alerts):", extractAlerts(mockResult1).length);
console.log("Testing Format 2 (data.alertsRaw.alerts):", extractAlerts(mockResult2).length);
console.log("Testing Empty:", extractAlerts(mockResultEmpty).length);
