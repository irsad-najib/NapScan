
import { extractAlerts } from './frontend/src/utils/zapParser';

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

// Simulate what seems to be the problematic structure based on description
const mockResult3 = {
    alertsRaw: {
        alerts: [
            { alert: "Test Alert 3", risk: "Start" }
        ]
    }
};

console.log("Testing Format 1:", extractAlerts(mockResult1));
console.log("Testing Format 2:", extractAlerts(mockResult2));
console.log("Testing Format 3:", extractAlerts(mockResult3)); 
