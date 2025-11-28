#!/bin/bash
#
# Install container security tools

set -e

echo "Installing container security tools..."

# Install Trivy
curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin

# Install Cosign
curl -sL 'https://github.com/sigstore/cosign/releases/latest/download/cosign-linux-amd64' -o /usr/local/bin/cosign
chmod +x /usr/local/bin/cosign

# Install Syft
curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin

# Install Docker Bench for Security
git clone https://github.com/docker/docker-bench-security.git /opt/docker-bench-security

# Install Falco
curl -s https://falco.org/repo/falcosecurity-3672BA8F.asc | apt-key add -
echo "deb https://download.falco.org/packages/deb stable main" | tee -a /etc/apt/sources.list.d/falcosecurity.list
apt-get update -y
apt-get install -y falco

echo "Installation completed. Available tools:"
echo "  Trivy: $(trivy --version | head -1)"
echo "  Cosign: $(cosign version | head -1)"
echo "  Syft: $(syft version | head -1)"
