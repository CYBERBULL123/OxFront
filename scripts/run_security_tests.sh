#!/bin/bash
# Comprehensive test script for OxInteLL security features
# This script runs all tests associated with OxInteLL security features

# Print colored output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[0;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}   OxInteLL Security Testing Suite     ${NC}"
echo -e "${GREEN}========================================${NC}"
echo ""

# Function to run tests and report status
run_test() {
  TEST_TYPE=$1
  TEST_CMD=$2
  
  echo -e "${YELLOW}Running $TEST_TYPE tests...${NC}"
  
  $TEST_CMD
  
  if [ $? -eq 0 ]; then
    echo -e "${GREEN}✓ $TEST_TYPE tests passed${NC}"
    return 0
  else
    echo -e "${RED}✗ $TEST_TYPE tests failed${NC}"
    return 1
  fi
  
  echo ""
}

# Track overall success
SUCCESS=true

# Step 1: Run linting to ensure code quality
echo -e "${YELLOW}Step 1: Code Quality Checks${NC}"
npm run lint

if [ $? -eq 0 ]; then
  echo -e "${GREEN}✓ Code quality checks passed${NC}"
else
  echo -e "${RED}✗ Code quality checks failed${NC}"
  SUCCESS=false
fi
echo ""

# Step 2: Run TypeScript type checking
echo -e "${YELLOW}Step 2: TypeScript Type Checking${NC}"
npm run type-check

if [ $? -eq 0 ]; then
  echo -e "${GREEN}✓ Type checking passed${NC}"
else
  echo -e "${RED}✗ Type checking failed${NC}"
  SUCCESS=false
fi
echo ""

# Step 3: Run unit tests
echo -e "${YELLOW}Step 3: Unit Tests${NC}"

# Frontend unit tests
run_test "Frontend Component" "npm test -- --testPathPattern='__tests__/components'"
COMP_TESTS_RESULT=$?

run_test "Library" "npm test -- --testPathPattern='__tests__/lib'"
LIB_TESTS_RESULT=$?

if [ $COMP_TESTS_RESULT -ne 0 ] || [ $LIB_TESTS_RESULT -ne 0 ]; then
  SUCCESS=false
fi
echo ""

# Step 4: Run API route tests
echo -e "${YELLOW}Step 4: API Route Tests${NC}"
run_test "API Route" "npm test -- --testPathPattern='__tests__/app'"
if [ $? -ne 0 ]; then
  SUCCESS=false
fi
echo ""

# Step 5: Run integration tests
echo -e "${YELLOW}Step 5: Integration Tests${NC}"
run_test "Integration" "npm test -- --testPathPattern='__tests__/integration'"
if [ $? -ne 0 ]; then
  SUCCESS=false
fi
echo ""

# Step 6: Run backend tests
echo -e "${YELLOW}Step 6: Backend Tests${NC}"
cd backend
run_test "Backend Python" "python -m pytest -xvs"
BACKEND_RESULT=$?
cd ..

if [ $BACKEND_RESULT -ne 0 ]; then
  SUCCESS=false
fi
echo ""

# Step 7: Run end-to-end tests
echo -e "${YELLOW}Step 7: End-to-End Tests${NC}"
run_test "E2E" "npx playwright test"
if [ $? -ne 0 ]; then
  SUCCESS=false
fi
echo ""

# Step 8: Run performance tests (optional)
echo -e "${YELLOW}Step 8: Performance Tests${NC}"
read -p "Run performance tests? These may take several minutes (y/n): " RUN_PERF

if [ "$RUN_PERF" = "y" ]; then
  run_test "Performance" "npm test -- --testPathPattern='__tests__/performance'"
  if [ $? -ne 0 ]; then
    echo -e "${YELLOW}⚠ Performance tests failed, but these are not blocking${NC}"
  fi
else
  echo -e "${YELLOW}Skipping performance tests${NC}"
fi
echo ""

# Step 9: Run security scan on the project itself
echo -e "${YELLOW}Step 9: Security Scanning${NC}"
read -p "Run security scan on the project? (y/n): " RUN_SEC

if [ "$RUN_SEC" = "y" ]; then
  echo -e "${YELLOW}Running OxInteLL security scan on the project itself...${NC}"
  node scripts/oxintell-security-scan.js
  if [ $? -ne 0 ]; then
    echo -e "${RED}⚠ Security scan found issues${NC}"
    SUCCESS=false
  else
    echo -e "${GREEN}✓ Security scan passed${NC}"
  fi
else
  echo -e "${YELLOW}Skipping security scan${NC}"
fi
echo ""

# Generate test coverage report
echo -e "${YELLOW}Generating test coverage report...${NC}"
npm test -- --coverage

echo ""
echo -e "${GREEN}========================================${NC}"
if [ "$SUCCESS" = true ]; then
  echo -e "${GREEN}✓ All required tests passed${NC}"
  echo -e "${GREEN}========================================${NC}"
  exit 0
else
  echo -e "${RED}✗ Some tests failed${NC}"
  echo -e "${GREEN}========================================${NC}"
  exit 1
fi
