#!/bin/sh
#
# Keyvault Deployment Script
#
# Deploys the keyvault kernel module and test suite to a remote FreeBSD VM.
#
# Usage: ./deploy.sh <vm-ip> [user]
#
# Examples:
#   ./deploy.sh 192.168.1.100
#   ./deploy.sh 192.168.1.100 root
#

set -e

usage() {
    echo "Usage: $0 <vm-ip> [user]"
    echo ""
    echo "Arguments:"
    echo "  vm-ip    IP address of the target FreeBSD VM"
    echo "  user     SSH user (default: root)"
    echo ""
    echo "Examples:"
    echo "  $0 192.168.1.100"
    echo "  $0 192.168.1.100 admin"
    exit 1
}

if [ -z "$1" ]; then
    usage
fi

VM_IP="$1"
VM_USER="${2:-root}"
REMOTE="${VM_USER}@${VM_IP}"
DEPLOY_DIR="/root/keyvault"

# Get script directory
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

echo "========================================"
echo "Keyvault Deployment"
echo "========================================"
echo "Target: ${REMOTE}"
echo "Deploy directory: ${DEPLOY_DIR}"
echo ""

# Build locally first
echo "[1/5] Building module locally..."
cd "${SCRIPT_DIR}"
make clean >/dev/null 2>&1 || true
make
echo "      Module built: keyvault.ko"

# Build test programs
echo "[2/5] Building test programs..."
(cd tests && make clean >/dev/null 2>&1 || true && make)
echo "      Tests built: tests/kv_test"

# Create deployment package
echo "[3/5] Creating deployment package..."
DEPLOY_FILES="
keyvault.ko
keyvault.h
tests/kv_test
tests/kv_fdpass_server
tests/kv_fdpass_client
tests/Makefile
"

# Build fd passing test programs if they exist
if [ -f tests/kv_fdpass_server.c ]; then
    (cd tests && make kv_fdpass_server kv_fdpass_client 2>/dev/null || true)
fi

# Create tarball
tar -czf /tmp/keyvault-deploy.tar.gz \
    keyvault.ko \
    keyvault.h \
    tests/kv_test \
    tests/kv_fdpass_server \
    tests/kv_fdpass_client \
    2>/dev/null || \
tar -czf /tmp/keyvault-deploy.tar.gz \
    keyvault.ko \
    keyvault.h \
    tests/kv_test

echo "      Package created: /tmp/keyvault-deploy.tar.gz"

# Deploy to VM
echo "[4/5] Deploying to ${REMOTE}..."
ssh "${REMOTE}" "mkdir -p ${DEPLOY_DIR}/tests"
scp /tmp/keyvault-deploy.tar.gz "${REMOTE}:${DEPLOY_DIR}/"
ssh "${REMOTE}" "cd ${DEPLOY_DIR} && tar -xzf keyvault-deploy.tar.gz && rm keyvault-deploy.tar.gz"
echo "      Files deployed to ${DEPLOY_DIR}"

# Create run script on VM
echo "[5/5] Creating run scripts on VM..."
ssh "${REMOTE}" "cat > ${DEPLOY_DIR}/run_tests.sh" << 'RUNSCRIPT'
#!/bin/sh
#
# Run keyvault tests
#
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "${SCRIPT_DIR}"

echo "========================================"
echo "Keyvault Test Suite"
echo "========================================"

# Unload if already loaded
echo "[*] Unloading existing module (if any)..."
kldunload keyvault 2>/dev/null || true

# Load module
echo "[*] Loading keyvault module..."
kldload ./keyvault.ko
echo "    Module loaded successfully"

# Check device exists
if [ ! -c /dev/keyvault ]; then
    echo "ERROR: /dev/keyvault not created"
    exit 1
fi
echo "    Device /dev/keyvault created"

# Run main test suite
echo ""
echo "[*] Running main test suite..."
./tests/kv_test
RESULT=$?

# Run fd passing tests if available
if [ -x ./tests/kv_fdpass_server ]; then
    echo ""
    echo "[*] Running fd passing integration test..."
    ./tests/kv_fdpass_server &
    SERVER_PID=$!
    sleep 1
    ./tests/kv_fdpass_client
    wait $SERVER_PID || true
fi

# Unload module
echo ""
echo "[*] Unloading module..."
kldunload keyvault

echo ""
echo "========================================"
if [ $RESULT -eq 0 ]; then
    echo "All tests passed!"
else
    echo "Some tests failed (exit code: $RESULT)"
fi
echo "========================================"

exit $RESULT
RUNSCRIPT

ssh "${REMOTE}" "chmod +x ${DEPLOY_DIR}/run_tests.sh"

# Create quick load/unload scripts
ssh "${REMOTE}" "cat > ${DEPLOY_DIR}/load.sh" << 'LOADSCRIPT'
#!/bin/sh
cd "$(dirname "$0")"
kldunload keyvault 2>/dev/null || true
kldload ./keyvault.ko
echo "keyvault loaded"
kldstat | grep keyvault
LOADSCRIPT

ssh "${REMOTE}" "cat > ${DEPLOY_DIR}/unload.sh" << 'UNLOADSCRIPT'
#!/bin/sh
kldunload keyvault 2>/dev/null && echo "keyvault unloaded" || echo "keyvault not loaded"
UNLOADSCRIPT

ssh "${REMOTE}" "chmod +x ${DEPLOY_DIR}/load.sh ${DEPLOY_DIR}/unload.sh"

echo ""
echo "========================================"
echo "Deployment complete!"
echo "========================================"
echo ""
echo "To run tests on the VM:"
echo "  ssh ${REMOTE}"
echo "  cd ${DEPLOY_DIR}"
echo "  ./run_tests.sh"
echo ""
echo "Quick commands:"
echo "  ./load.sh    - Load the module"
echo "  ./unload.sh  - Unload the module"
echo ""
