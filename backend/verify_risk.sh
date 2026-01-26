#!/bin/bash

# Configuration
API_URL="http://localhost:5000/api"
TOKEN="YOUR_JWT_TOKEN_HERE" 

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'

echo "🔥 Batch Risk Engine Verification"

# 1. Create a Batch
echo -e "\n${GREEN}[1] Creating Batch...${NC}"
BATCH_RES=$(curl -s -X POST "$API_URL/batch/create" \
  -H "Authorization: Bearer $TOKEN")
BATCH_ID=$(echo $BATCH_RES | jq -r '.batch_id')

if [ "$BATCH_ID" == "null" ]; then
    echo -e "${RED}Failed to create batch${NC}"
    echo $BATCH_RES
    exit 1
fi
echo "Batch ID: $BATCH_ID"

# 2. Add Nmap Scan Result (Mock)
echo -e "\n${GREEN}[2] Adding Nmap Scan...${NC}"
# Note: You can't inject results directly via API typically, 
# so we'll run a real scan command or assuming you have a way to populate it.
# For this script we assume running a scan triggers the background process
curl -s -X POST "$API_URL/scan/nmap" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d "{\"batch_id\": \"$BATCH_ID\", \"target\": \"scanme.nmap.org\"}" | jq .

# 3. Add FFUF Scan Result (Mock)
echo -e "\n${GREEN}[3] Adding FFUF Scan...${NC}"
curl -s -X POST "$API_URL/scan/ffuf" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d "{\"batch_id\": \"$BATCH_ID\", \"target\": \"https://scanme.nmap.org\"}" | jq .

# 4. Wait for processing (In a real scenario)
echo -e "\n${GREEN}[4] Waiting for scans to process...${NC}"
sleep 5

# 5. Get Batch Detail (Check Risk Score)
echo -e "\n${GREEN}[5] Fetching Batch Risk Detail...${NC}"
RISK_RES=$(curl -s "$API_URL/batch/$BATCH_ID" \
  -H "Authorization: Bearer $TOKEN")

echo $RISK_RES | jq .

RISK_SCORE=$(echo $RISK_RES | jq -r '.risk_score')
RISK_LEVEL=$(echo $RISK_RES | jq -r '.risk_level')

echo -e "\nRisk Score: $RISK_SCORE"
echo -e "Risk Level: $RISK_LEVEL"
